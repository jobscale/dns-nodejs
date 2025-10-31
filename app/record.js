import path from 'path';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { recordList } from './records.js';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const json = JSON.parse(readFileSync(path.join(dirname, '../package.json')));

export const search = 'jsx.jp';
export const records = {
  version: [{ type: 'TXT', data: json.version, ttl: 300 }],
  '@': [{ type: 'A', data: '172.16.6.66', ttl: 300 }],
  '*.x': [{ type: 'A', data: '172.16.6.66', ttl: 300 }],
  n100: [{ type: 'A', data: '172.16.6.66', ttl: 300 }],
  proxy: [{ type: 'CNAME', data: 'dark.jsx.jp', ttl: 300 }],
};

recordList.forEach(item => {
  const { Name: name, Type: type, RData: data, TTL: ttl } = item;
  if (!records[name]) records[name] = [];
  records[name].push({ type, data, ttl });
});

export const denys = [
  ...readFileSync(path.join(process.cwd(), 'acl/deny-domain')).toString()
  .split('\n'),
  ...readFileSync(path.join(process.cwd(), 'acl/deny-regex')).toString()
  .split('\n').map(exp => new RegExp(exp)),
];
