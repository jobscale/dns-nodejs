import path from 'path';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { createLogger } from '@jobscale/logger';
import { recordList } from './records.js';

const logger = createLogger('info', { noPathName: true, timestamp: true });
const dirname = path.dirname(fileURLToPath(import.meta.url));
const json = JSON.parse(readFileSync(path.join(dirname, '../package.json')));

export const search = 'jsx.jp';
export const records = {
  version: [{ type: 'TXT', data: json.version, ttl: 300 }],
  'alias-1': [{ type: 'CNAME', data: 'alias-2.jsx.jp.', ttl: 300 }],
  'alias-2': [{ type: 'CNAME', data: 'alias-3.jsx.jp.', ttl: 300 }],
  'alias-3': [{ type: 'CNAME', data: 'alias-4.jsx.jp.', ttl: 300 }],
  'alias-4': [{ type: 'CNAME', data: 'alias-5.jsx.jp.', ttl: 300 }],
};

recordList.forEach(item => {
  const { Name: name, Type: type, RData: data, TTL: ttl } = item;
  if (!records[name]) records[name] = [];
  if (records[name].find(v => v.type.toUpperCase() === 'CNAME')) {
    logger.warn({ 'Already CNAME': JSON.stringify(item) });
    return;
  }
  if (records[name].length && type.toUpperCase() === 'CNAME') {
    logger.warn({ 'Already Multiple CNAME': JSON.stringify(item) });
    return;
  }
  records[name].push({ type, data, ttl });
});

export const denys = [
  ...readFileSync(path.join(process.cwd(), 'acl/deny-domain')).toString()
  .split('\n'),
  ...readFileSync(path.join(process.cwd(), 'acl/deny-regex')).toString()
  .split('\n').map(exp => new RegExp(exp)),
];

export const denyHost = name => [
  'GITHUB.IO', 'A', {
    answers: [{
      name, type: 'CNAME', ttl: 2592000, data: 'GITHUB.IO',
    }],
  },
];
