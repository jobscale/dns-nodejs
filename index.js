import net from 'net';
import dgram from 'dgram';
import { createLogger } from '@jobscale/logger';
import { Nameserver } from './app/index.js';

const JEST_TEST = Object.keys(process.env).filter(v => v.toLowerCase().match('jest')).length;
const { PORT } = process.env;

const logger = createLogger('info', { noPathName: true, timestamp: true });

const dnsBind = async (port, bind = '127.0.0.1') => {
  const nameserver = {
    udp: await new Nameserver().createServer({ transport: 'udp' }),
    tcp: await new Nameserver().createServer({ transport: 'tcp' }),
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

const main = () => {
  if (!JEST_TEST) dnsBind(Number.parseInt(PORT, 10) || 53, '0.0.0.0');
};

export default main();
