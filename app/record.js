import path from 'path';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { createLogger } from '@jobscale/logger';

const logger = createLogger('info', { noPathName: true, timestamp: true });
const dirname = path.dirname(fileURLToPath(import.meta.url));
const json = JSON.parse(await fs.readFile(path.join(dirname, '../package.json')));

export const forwarder = ['8.8.8.8', '8.8.4.4'];
export const glueNS = ['NS1.GSLB13.SAKURA.NE.JP', 'NS2.GSLB13.SAKURA.NE.JP'];
export const authority = {
  name: 'jp',
  type: 'SOA',
  ttl: 1200,
  data: {
    mname: 'z.dns.jp',
    rname: 'root.dns.jp',
    serial: Math.floor(Date.now() / 10000),
    refresh: 3600,
    retry: 900,
    expire: 1814400,
    minimum: 900,
  },
};

const dirPath = path.join(process.cwd(), 'db');
const files = await fs.readdir(dirPath);
const jsonFiles = files.filter(file => path.extname(file) === '.json');
const dbList = await Promise.all(jsonFiles.map(async file => {
  const search = path.basename(file, '.json');
  const record = JSON.parse((await fs.readFile(path.join(dirPath, file))).toString());
  return { search, record };
}));

export const searches = dbList.map(db => db.search);
export const records = {};

const setupSearch = (search, record) => {
  dbList.find(db => db.search === search).record.forEach(item => {
    const { Name: name, Type: type, RData: data, TTL: ttl } = item;
    if (!record[name]) record[name] = [];
    if (record[name].find(v => v.type.toUpperCase() === 'CNAME')) {
      logger.warn({ 'Already CNAME': JSON.stringify(item) });
      return;
    }
    if (record[name].length && type.toUpperCase() === 'CNAME') {
      logger.warn({ 'Already Multiple CNAME': JSON.stringify(item) });
      return;
    }
    record[name].push({ type, data, ttl });
  });
};
searches.forEach(search => {
  records[search] = { version: [{ type: 'TXT', data: json.version, ttl: 300 }] };
  setupSearch(search, records[search]);
});

export const denys = [
  ...(await fs.readFile(path.join(process.cwd(), 'acl/deny-domain'))).toString()
  .split('\n').filter(line => line.trim()),
  ...(await fs.readFile(path.join(process.cwd(), 'acl/deny-regex'))).toString()
  .split('\n').filter(line => line.trim()).map(exp => new RegExp(exp)),
];

export const denyHost = name => [
  'GITHUB.IO', 'A', {
    answers: [{
      name, type: 'CNAME', ttl: 2592000, data: 'GITHUB.IO',
    }],
  },
];
