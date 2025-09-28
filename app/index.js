import net from 'net';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';
import { createLogger } from '@jobscale/logger';
import { search, records, denys } from './record.js';

const logger = createLogger('info', { noPathName: true, timestamp: true });

const resolveUDP = (name, type, ns) => new Promise((resolve, reject) => {
  const query = dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }],
  });

  const socket = dgram.createSocket('udp4');
  const timeout = setTimeout(() => {
    socket.close();
    reject(new Error('UDP socket timed out'));
  }, 5000);
  socket.on('message', msg => {
    clearTimeout(timeout);
    socket.close();
    try {
      const response = dnsPacket.decode(msg);
      resolve(response);
    } catch (e) {
      reject(e);
    }
  });
  socket.on('error', e => {
    clearTimeout(timeout);
    reject(e);
  });
  socket.send(query, 53, ns);
});

const resolveTCP = (name, type, ns) => new Promise((resolve, reject) => {
  const query = dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }],
  });

  const socket = net.connect(53, ns, () => {
    const lengthBuf = Buffer.alloc(2);
    lengthBuf.writeUInt16BE(query.length);
    socket.write(Buffer.concat([lengthBuf, query]));
  });
  const chunks = [];
  socket.on('data', chunk => chunks.push(chunk));
  socket.on('end', () => {
    const buffer = Buffer.concat(chunks);
    const length = buffer.readUInt16BE(0);
    const msg = buffer.slice(2, 2 + length);
    try {
      const response = dnsPacket.decode(msg);
      resolve(response.answers);
    } catch (e) {
      reject(e);
    }
  });
  socket.on('error', reject);
});

const resolver = async (name, type, nss, transport = 'udp') => {
  const resolveFn = transport === 'tcp' ? resolveTCP : resolveUDP;
  for (const ns of nss) {
    const answers = (
      await resolveFn(name, type, ns)
      .catch(e => logger.warn(`${e.message} ${name} ${type}`))
    ) || [];
    if (answers.length) return answers;
  }
  return [];
};

class Nameserver {
  async createServer(config) {
    this.cache = {};
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
    opts.visited = opts.visited || new Set();
    if (opts.visited.has(name)) {
      logger.warn(`CNAME loop detected for ${name}`);
      return opts.answers;
    }
    opts.visited.add(name);

    const deny = denys.find(exp => name.match(exp));
    if (deny) {
      return [{
        type: 'CNAME',
        name,
        ttl: 2592000,
        data: 'GITHUB.IO',
      }];
    }

    const now = Math.floor(Date.now() / 1000);
    // in records to static
    const exist = Object.keys(records).find(sub => {
      if (name === `${sub}.${search}`) return true;
      if (sub === '@' && name === search) return true;
      if (sub[0] === '*' && name.endsWith(`${sub.slice(1)}.${search}`)) return true;
      return false;
    });
    const filter = list => {
      const std = list.filter(record => record.type === type);
      const alt = list.filter(record => type === 'A' && record.type === 'CNAME');
      return [...std, ...alt];
    };
    const match = (exist && filter(records[exist])) || [];
    if (match.length) {
      opts.answers.push(...match.map(({ type: t, data, ttl }) => ({ type: t, name, ttl, data })));
      logger.info(`Query for ${name} (${type}) ${JSON.stringify(opts.answers)}`);
    } else if (name.endsWith(`.${search}`)) {
      // in search to glue
      const key = `${name}-${type}`;
      if (!this.cache[key] || this.cache[key].expires < now) {
        this.cache[key] = await resolver(name, type, this.glue, this.transport);
        const ttl = this.cache[key].find(item => item.type === 'A')?.ttl || 172800;
        this.cache[key].expires = now + ttl;
        logger.info(`Query for ${name} (${type}) ${JSON.stringify(this.cache[key])}`);
      }
      opts.answers.push(...this.cache[key]);
    } else {
      // other to forwarder
      const key = `${name}-${type}`;
      if (!this.cache[key] || this.cache[key].expires < now) {
        this.cache[key] = await resolver(name, type, this.forwarder, this.transport);
        const ttl = this.cache[key].find(item => item.type === 'A')?.ttl || 172800;
        this.cache[key].expires = now + ttl;
        logger.info(`Query for ${name} (${type}) ${JSON.stringify(this.cache[key])}`);
      }
      opts.answers.push(...this.cache[key]);
    }

    if (type !== 'A') return opts.answers;
    if (opts.aliases?.length) return opts.answers;
    opts.aliases = opts.answers.filter(item => item.type === 'CNAME');
    if (!opts.aliases.length || opts.aliases.length !== opts.answers.length) {
      return opts.answers;
    }
    await Promise.all(opts.aliases.map(
      alias => this.enter(alias.data, 'A', opts),
    ));
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
