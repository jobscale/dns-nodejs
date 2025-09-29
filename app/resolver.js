import net from 'net';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';
import { createLogger } from '@jobscale/logger';

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

export const resolver = async (name, type, nss, transport = 'udp') => {
  const resolveFn = transport === 'tcp' ? resolveTCP : resolveUDP;
  for (const ns of nss) {
    const { answers } = await resolveFn(name, type, ns)
    .catch(e => logger.warn(`${e.message} ${name} ${type}`) || {});
    if (answers?.length) return answers;
  }
  return [];
};

export default {
  resolver,
};
