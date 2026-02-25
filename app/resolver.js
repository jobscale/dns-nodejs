import net from 'net';
import dgram from 'dgram';
import dnsPacket from 'dns-packet';

const logger = new Proxy(console, {
  get(target, property) {
    return (...args) => target[property](`[dns ${property.toUpperCase()}]`.padEnd(8, ' '), ...args);
  },
});

const resolveUDP = (query, question, ns) => new Promise((resolve, reject) => {
  const socket = dgram.createSocket('udp4');
  const timeout = setTimeout(() => {
    socket.close();
    reject(new Error('UDP socket timed out'));
  }, 5000);
  const fail = e => {
    clearTimeout(timeout);
    logger.warn(JSON.stringify({ resolveUDP: e.message, ns, ...question }));
    reject(e);
  };
  const checkFail = e => e && fail(e);
  const onMessage = msg => {
    clearTimeout(timeout);
    socket.close();
    try {
      resolve(dnsPacket.decode(msg));
    } catch (e) {
      fail(e);
    }
  };
  socket.on('message', onMessage);
  socket.on('error', fail);
  socket.send(query, 53, ns, checkFail);
});

const resolveTCP = (query, question, ns) => new Promise((resolve, reject) => {
  const socket = net.connect(53, ns, () => {
    const lengthBuf = Buffer.alloc(2);
    lengthBuf.writeUInt16BE(query.length);
    socket.write(Buffer.concat([lengthBuf, query]));
  });
  const timeout = setTimeout(() => {
    socket.destroy();
    reject(new Error('TCP socket timed out'));
  }, 5000);
  const chunks = [];
  const fail = e => {
    clearTimeout(timeout);
    logger.warn(JSON.stringify({ resolveTCP: e.message, ns, ...question }));
    reject(e);
  };
  const onMessage = chunk => {
    chunks.push(chunk);
    const buffer = Buffer.concat(chunks);
    if (buffer.length < 2) return;
    const length = buffer.readUInt16BE(0);
    if (buffer.length < 2 + length) return;
    clearTimeout(timeout);
    socket.end();
    const msg = buffer.slice(2, 2 + length);
    try {
      resolve(dnsPacket.decode(msg));
    } catch (e) {
      fail(e);
    }
  };
  socket.on('data', onMessage);
  socket.on('error', fail);
});

export const resolver = async (name, type, nss, transport = 'udp') => {
  const question = { type, name };
  const query = dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [question],
  });
  const resolveFn = transport === 'tcp' ? resolveTCP : resolveUDP;
  for (const ns of nss) {
    const result = await resolveFn(query, question, ns)
    .catch(e => logger.warn(JSON.stringify({ [transport]: e.message, ns, ...question })) ?? {});
    if (result.answers) return result;
  }
  return { answers: [] };
};
