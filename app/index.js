import net from 'net';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';
import { createLogger } from '@jobscale/logger';
import { resolver } from './resolver.js';
import { search, records, denys, denyHost } from './record.js';

const logger = createLogger('info', { noPathName: true, timestamp: true });

class Nameserver {
  constructor() {
    this.cache = {};
    const rand = Math.floor(Math.random() * 3600);
    setInterval(() => this.clean(), (3600 + rand) * 1000);
  }

  clean() {
    const now = Math.floor(Date.now() / 1000);
    Object.entries(this.cache).forEach(([key, value]) => {
      if (value.expires < now) {
        delete this.cache[key];
      }
    });
  }

  async createServer(config) {
    const { transport, forwarder, glueNS } = config;
    // glue proxy
    await Promise.all(
      glueNS.map(name => resolver(name, 'A', forwarder)),
    )
    .then(res => res.map(([item]) => item.data))
    .then(glue => {
      this.transport = transport;
      this.forwarder = forwarder;
      this.glue = glue;
    });
    return this;
  }

  async enter(name, type, opts = { answers: [] }) {
    if (!opts.visited) opts.visited = new Set();
    if (opts.visited.has(name)) {
      logger.warn(`CNAME loop detected for ${name}`);
      return opts.answers;
    }
    opts.visited.add(name);

    const deny = denys.find(exp => name.match(exp));
    if (deny) return this.enter(...denyHost(name));

    const now = Math.floor(Date.now() / 1000);

    const resolverViaCache = async dns => {
      const key = `${name}-${type}`;
      if (!this.cache[key] || this.cache[key].expires < now) {
        this.cache[key] = await resolver(name, type, dns, this.transport);
        this.cache[key].forEach(item => {
          // cache minimum 20 minutes and for client
          const ttl = Number.parseInt(item.ttl, 10) || 0;
          if (ttl < 1200) item.ttl = 1200;
        });
        const expiresIn = Math.max(...this.cache[key].map(item => item.ttl || 0), 1200);
        this.cache[key].expires = now + expiresIn;
        logger.info(`Query for ${name} (${type}) ${JSON.stringify(this.cache[key])}`);
      }
      opts.answers.push(...this.cache[key]);
    };

    // in records to static
    const candidates = Object.entries(records).map(([sub, list]) => {
      const match = list.filter(v => {
        if (v.type === type) return true;
        return type === 'A' && v.type === 'CNAME';
      });
      if (!match.length) return undefined;
      if (sub === '@' && name === search) return { list: match, priority: 1 };
      if (name === `${sub}.${search}`) return { list: match, priority: 10 };
      if (sub.startsWith('*') && name.endsWith(`${sub.slice(1)}.${search}`)) return { list: match, priority: 100 };
      return undefined;
    }).filter(Boolean).sort((a, b) => a.priority - b.priority);
    // choice via priority if exist
    const [exist] = candidates;
    if (exist) {
      exist.list.forEach(item => {
        opts.answers.push({ name, ...item });
      });
      logger.info(`Query for ${name} (${type}) ${JSON.stringify(opts.answers)}`);
    } else if (name.endsWith(`.${search}`)) {
      // in search to glue
      await resolverViaCache(this.glue);
    } else {
      // other to forwarder
      await resolverViaCache(this.forwarder);
    }

    if (type !== 'A') return opts.answers;
    if (!opts.resolved) opts.resolved = [];
    opts.aliases = opts.answers.filter(item => {
      if (opts.resolved.find(v => v.data === item.data)) return false;
      return item.type === 'CNAME';
    });
    if (!opts.aliases.length) {
      return opts.answers;
    }
    await Promise.all(opts.aliases.map(alias => {
      opts.resolved.push(alias);
      const normName = alias.data.endsWith('.') ? alias.data.slice(0, -1) : alias.data;
      return this.enter(normName, 'A', opts);
    }));
    return opts.answers;
  }

  async parseDNS(msg) {
    const query = dnsPacket.decode(msg);
    const { id, questions } = query;
    const [question] = questions;
    const name = question.name.toLowerCase();
    const { type } = question;
    const answers = await this.enter(name, type).catch(e => logger.error(e) || []);
    const flags = answers.length ? dnsPacket.RECURSION_AVAILABLE : 0;
    const rcode = answers.length ? 0 : 3;
    const response = dnsPacket.encode({
      type: 'response', id, flags, rcode, questions, answers,
    });
    return response;
  }
}

const dnsBind = async (port, bind = '127.0.0.1') => {
  const forwarder = ['8.8.8.8', '8.8.4.4'];
  const glueNS = ['NS1.GSLB13.SAKURA.NE.JP', 'NS2.GSLB13.SAKURA.NE.JP'];
  const nameserver = {
    udp: await new Nameserver().createServer({ transport: 'udp', forwarder, glueNS }),
    tcp: await new Nameserver().createServer({ transport: 'tcp', forwarder, glueNS }),
  };

  const tcpReceiver = async (buffer, socket) => {
    const length = buffer.readUInt16BE(0);
    const msg = buffer.slice(2, 2 + length);
    const response = await nameserver.tcp.parseDNS(msg)
    .catch(e => logger.warn(e.message));
    if (response) {
      const lengthBuf = Buffer.alloc(2);
      lengthBuf.writeUInt16BE(response.length);
      socket.write(Buffer.concat([lengthBuf, response]));
    }
    socket.end();
  };
  const tcpConnecter = socket => {
    socket.on('data', buffer => {
      tcpReceiver(buffer, socket)
      .catch(e => logger.warn(e.message));
    });
    socket.on('error', e => logger.error(`TCP socket error: ${e.message}`));
  };
  const tcpServer = net.createServer(tcpConnecter);
  tcpServer.listen(port, bind, () => {
    logger.info(`DNS server listening on ${bind} port TCP ${port}`);
  });

  const udpServer = dgram.createSocket('udp4');
  const udpReceiver = async (msg, rinfo) => {
    const response = await nameserver.udp.parseDNS(msg)
    .catch(e => logger.warn(e.message));
    if (response) {
      udpServer.send(response, 0, response.length, rinfo.port, rinfo.address);
    }
  };
  udpServer.on('message', (msg, rinfo) => {
    udpReceiver(msg, rinfo)
    .catch(e => logger.warn(e.message));
  });
  udpServer.bind(port, bind, () => {
    logger.info(`DNS server listening on ${bind} port UDP ${port}`);
  });
};

dnsBind(53, '0.0.0.0');
