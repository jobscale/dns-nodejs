import net from 'net';
import dgram from 'dgram';
import { Nameserver } from './app/index.js';

const JEST_TEST = Object.keys(process.env).filter(v => v.toLowerCase().match('jest')).length;
const DNS_BIND = process.env.DNS_BIND || '0.0.0.0';
const DNS_PORT = Number.parseInt(process.env.DNS_PORT, 10) || 53;

const logger = new Proxy(console, {
  get(target, property) {
    return (...args) => target[property](`[dns ${property.toUpperCase()}]`.padEnd(8, ' '), ...args);
  },
});

const tcpServer = async (port, bind = '127.0.0.1') => {
  const transport = 'tcp';
  const parser = await new Nameserver().createServer({ transport });
  const tcpReceiver = async (chunk, opts) => {
    opts.buffer = Buffer.concat([opts.buffer, chunk]);
    if (opts.buffer.length < 2) return;
    const length = opts.buffer.readUInt16BE(0);
    if (opts.buffer.length < length + 2) return;
    const msg = opts.buffer.slice(2, 2 + length);
    opts.buffer = opts.buffer.slice(2 + length);
    const response = await parser.parseDNS(msg)
    .catch(e => logger.warn(JSON.stringify({ parseDNS: e.message, msg })));
    if (response) {
      const lengthBuf = Buffer.alloc(2);
      lengthBuf.writeUInt16BE(response.length);
      opts.socket.write(Buffer.concat([lengthBuf, response]));
    }
    opts.socket.end();
  };
  const tcpConnecter = socket => {
    const opts = { socket, buffer: Buffer.alloc(0) };
    socket.on('data', chunk => {
      logger.debug(JSON.stringify({ socket, 'chunk.length': chunk.length }));
      tcpReceiver(chunk, opts)
      .catch(e => logger.warn(JSON.stringify({ tcpReceiver: e.message })));
    });
    socket.on('error', e => logger.error(JSON.stringify({ 'TCP socket error': e.message })));
  };
  const server = net.createServer(tcpConnecter);
  server.listen(port, bind, () => {
    logger.info(`DNS server listening on ${bind}:${port} ${transport}`);
  });
};

const udpServer = async (port, bind = '127.0.0.1') => {
  const transport = 'udp';
  const parser = await new Nameserver().createServer({ transport });
  const server = dgram.createSocket('udp4');
  const udpReceiver = async (msg, rinfo) => {
    const response = await parser.parseDNS(msg)
    .catch(e => logger.warn(JSON.stringify({ parseDNS: e.message, rinfo })));
    if (response) {
      server.send(response, 0, response.length, rinfo.port, rinfo.address);
    }
  };
  server.on('message', (msg, rinfo) => {
    if (msg.length < 17) return;
    udpReceiver(msg, rinfo)
    .catch(e => logger.warn(JSON.stringify({ udpReceiver: e.message, rinfo })));
  });
  server.on('error', e => logger.error(JSON.stringify({ 'UDP server error': e.message })));
  server.bind(port, bind, () => {
    logger.info(`DNS server listening on ${bind}:${port} ${transport}`);
  });
};

const main = async () => {
  if (JEST_TEST) return;
  tcpServer(DNS_PORT, DNS_BIND);
  udpServer(DNS_PORT, DNS_BIND);
};

export default main();
