import path from 'path';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';
import { createLogger } from '@jobscale/logger';

const logger = createLogger('info', { noPathName: true, timestamp: true });

const dirname = path.dirname(fileURLToPath(import.meta.url));
const json = JSON.parse(readFileSync(path.join(dirname, 'package.json')));

const search = 'jsx.jp';
const records = {
  version: {
    TXT: [{ data: json.version, ttl: 300 }],
  },
  '@': {
    A: [{ data: '172.16.6.66', ttl: 300 }],
  },
  '*.x': {
    A: [{ data: '172.16.6.66', ttl: 300 }],
  },
  n100: {
    A: [{ data: '172.16.6.66', ttl: 300 }],
  },
  proxy: {
    A: [{ data: '172.16.6.22', ttl: 300 }],
  },
};

const denys = [
  ...readFileSync(path.join(process.cwd(), 'acl/deny-domain')).toString()
  .split('\n'),
  ...readFileSync(path.join(process.cwd(), 'acl/deny-regex')).toString()
  .split('\n').map(exp => new RegExp(exp)),
];

const resolveAny = (name, type, ns) => new Promise((resolve, reject) => {
  const query = dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }],
  });
  const socket = dgram.createSocket('udp4');
  const timeout = setTimeout(() => {
    socket.close();
    reject(new Error('socket timed out'));
  }, 10000);
  socket.on('message', msg => {
    clearTimeout(timeout);
    socket.close();
    const response = dnsPacket.decode(msg);
    resolve(response.answers);
  });
  socket.on('error', e => {
    clearTimeout(timeout);
    reject(e);
  });
  socket.send(query, 53, ns);
});

const resolver = async (name, type, nss) => {
  for (const ns of nss) {
    const answers = (
      await resolveAny(name, type, ns)
      .catch(e => logger.warn(`${e.message} ${name} ${type}`))
    ) || [];
    if (answers.length) return answers;
  }
  return [];
};

const dnsBind = async (port, bind = '127.0.0.1') => {
  // パブリックフォワード
  const forwarder = ['8.8.8.8', '8.8.4.4'];
  // 権威サーバプロキシ
  const [ns1] = await resolver('NS1.GSLB13.SAKURA.NE.JP', 'A', forwarder);
  const [ns2] = await resolver('NS2.GSLB13.SAKURA.NE.JP', 'A', forwarder);
  const glue = [ns1.data, ns2.data];

  // キャッシュ
  const cache = {};

  const nameserver = async (name, type) => {
    const deny = denys.find(exp => name.match(exp));
    if (deny) {
      return [{
        type: 'CNAME',
        name,
        ttl: 2592000,
        data: 'GITHUB.IO',
      }];
    }

    const answers = [];
    const now = Math.floor(Date.now() / 1000);
    // 1. 固定レコードを返すドメイン
    const exist = Object.keys(records).find(sub => {
      if (name === `${sub}.${search}`) return true;
      if (sub === '@' && name === search) return true;
      if (sub[0] === '*' && name.endsWith(`${sub.slice(1)}.${search}`)) return true;
      return false;
    });
    if (exist && records[exist][type]) {
      const ips = records[exist][type];
      answers.push(...ips.map(({ data, ttl }) => ({ type, name, ttl, data })));
      logger.info(`Query for ${name} (${type}) ${JSON.stringify(answers)}`);
    } else if (name.endsWith(`.${search}`)) {
      // 2. jsx.jp ドメイン → プロキシ
      const key = `${name}-${type}`;
      if (!cache[key] || cache[key].expires < now) {
        cache[key] = await resolver(name, type, glue);
        const ttl = cache[key].find(item => item.type === 'A')?.ttl || 172800;
        cache[key].expires = now + ttl;
        logger.info(`Query for ${name} (${type}) ${JSON.stringify(cache[key])}`);
      }
      answers.push(...cache[key]);
    } else {
      // 3. その他のドメイン → フォワード
      const key = `${name}-${type}`;
      if (!cache[key] || cache[key].expires < now) {
        cache[key] = await resolver(name, type, forwarder);
        const ttl = cache[key].find(item => item.type === 'A')?.ttl || 172800;
        cache[key].expires = now + ttl;
        logger.info(`Query for ${name} (${type}) ${JSON.stringify(cache[key])}`);
      }
      answers.push(...cache[key]);
    }
    return answers;
  };

  const server = dgram.createSocket('udp4');
  server.on('message', async (msg, rinfo) => {
    const query = dnsPacket.decode(msg);
    const { id, questions } = query;
    const [question] = questions;
    const name = question.name.toLowerCase();
    const { type } = question;
    const answers = await nameserver(name, type).catch(e => logger.error(e) || []);
    const flags = answers.length ? dnsPacket.RECURSION_AVAILABLE : 0;
    const rcode = answers.length ? 0 : 3;
    const response = dnsPacket.encode({
      type: 'response', id, flags, rcode, questions, answers,
    });
    server.send(response, 0, response.length, rinfo.port, rinfo.address);
  });

  server.bind(port, bind, () => {
    logger.info(`DNS server listening on UDP ${bind} port ${port}`);
  });
};

dnsBind(53, '0.0.0.0');
