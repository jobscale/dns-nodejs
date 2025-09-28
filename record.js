import path from 'path';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';

const dirname = path.dirname(fileURLToPath(import.meta.url));
const json = JSON.parse(readFileSync(path.join(dirname, 'package.json')));

export const search = 'jsx.jp';
export const records = {
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
