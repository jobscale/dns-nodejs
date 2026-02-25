import dnsPacket from 'dns-packet';
import { resolver } from './resolver.js';
import {
  searches, records, denys, denyAnswer, forwarder, glueNS, authority,
} from './record.js';

const JEST_TEST = Object.keys(process.env).filter(v => v.toLowerCase().match('jest')).length;

const logger = new Proxy(console, {
  get(target, property) {
    return (...args) => target[property](`[dns ${property.toUpperCase()}]`.padEnd(8, ' '), ...args);
  },
});

const cache = {
  access: new Map(),
  TTL: 60 * 60 * 1000,

  clean() {
    const expired = Date.now() - cache.TTL;
    for (const [host, last] of cache.access.entries()) {
      if (last < expired) cache.access.delete(host);
    }
  },
};

export class Nameserver {
  constructor() {
    this.cache = {};
  }

  clean() {
    const now = Math.floor(Date.now() / 1000);
    Object.entries(this.cache).forEach(([key, value]) => {
      if (value.expires < now) {
        delete this.cache[key];
      }
    });
  }

  async createServer(config) {
    const { transport } = config;
    // glue proxy
    await Promise.all(
      glueNS.map(name => resolver(name, 'A', forwarder)),
    )
    .then(res => res.map(({ answers: [item] }) => item?.data))
    .then(glue => {
      this.transport = transport;
      this.forwarder = forwarder;
      this.glue = glue;
    });
    const rand = Math.floor(Math.random() * 3600);
    this.intervalId = setInterval(() => this.clean(), (3600 + rand) * 1000);
    return this;
  }

  terminate() {
    clearInterval(this.intervalId);
    delete this.intervalId;
  }

  searchRecords(name, type, search, recordSet) {
    const candidates = Object.entries(recordSet).map(([sub, list]) => {
      const match = list.filter(v => {
        if (v.type === type) return true;
        return type === 'A' && v.type === 'CNAME';
      });
      if (!match.length) return undefined;
      if (sub === '@' && name === search) return { list: match, priority: 1 };
      if (name === `${sub}.${search}`) return { list: match, priority: 10 };
      if (sub.startsWith('*')) {
        const wildcardSuffix = `${sub.slice(1)}.${search}`;
        const expectedLabels = wildcardSuffix.split('.').length;
        const nameLabels = name.split('.').length;
        if (name.endsWith(wildcardSuffix) && nameLabels === expectedLabels) {
          return { list: match, priority: 100 };
        }
      }
      return undefined;
    }).filter(Boolean).sort((a, b) => a.priority - b.priority);
    // choice via priority if exist
    const [exist] = candidates;
    return exist;
  }

  async enter(name, type, opts = { answers: [] }) {
    // IPpv6 NXDOMAIN
    if (type === 'AAAA') return opts;
    // IPv6 PTR (ip6.arpa) REFUSED
    if (type === 'PTR' && name.endsWith('.ip6.arpa')) return opts;

    if (!opts.visited) opts.visited = new Set();
    if (opts.visited.has(name)) {
      logger.warn(JSON.stringify({ 'CNAME loop detected': name }));
      return opts.answers;
    }
    opts.visited.add(name);

    const deny = denys.some(exp => name.match(exp));
    if (deny) return this.enter(...denyAnswer(name));

    const now = Math.floor(Date.now() / 1000);

    const findFirst = answers => {
      const aData = answers?.find(answer => ['A', 'AAAA'].includes(answer.type))?.data;
      if (aData) return aData;
      const cname = answers?.find(answer => ['CNAME'].includes(answer.type))?.data;
      if (cname) return cname;
      return answers?.[0]?.data ?? 'no resolved';
    };

    const resolverViaCache = async dns => {
      const key = `${name}-${type}`;
      if (!this.cache[key] || this.cache[key].expires < now) {
        this.cache[key] = await resolver(name, type, dns, this.transport);
        const recordA = this.cache[key].answers.filter(item => item.type === 'A');
        recordA.forEach(item => {
          // cache minimum 20 minutes and for client
          const ttl = Number.parseInt(item.ttl, 10) || 0;
          if (ttl < 1200) item.ttl = 1200;
        });
        const expiresIn = recordA.length
          ? Math.max(...this.cache[key].answers.map(item => item.ttl ?? 0), 1200)
          : 120;
        this.cache[key].expires = now + expiresIn;
        const host = `${name} (${type}) ${findFirst(this.cache[key].answers)}`;
        if (!cache.access.get(host)) logger.info(JSON.stringify({ ts: new Date(), Query: host }));
        cache.access.set(host, Date.now());
        if (!JEST_TEST) {
          clearTimeout(cache.id);
          cache.id = setTimeout(cache.clean, 60_000);
        }
      }
      const { answers, authorities } = this.cache[key];
      opts.answers.push(...answers);
      opts.authorities = authorities;
    };

    // in record to static
    const exist = Object.entries(records).reduce((accumulate, [search, recordSet]) => {
      if (accumulate) return accumulate;
      const myself = name === search || name.endsWith(`.${search}`);
      if (!myself) return undefined;
      return this.searchRecords(name, type, search, recordSet);
    }, undefined);
    if (exist) {
      exist.list.forEach(item => {
        opts.answers.push({ name, ...item });
      });
      const host = `${name} (${type}) ${findFirst(opts.answers)}`;
      if (!cache.access.get(host)) logger.info(JSON.stringify({ ts: new Date(), Static: host }));
      cache.access.set(host, Date.now());
      if (!opts.authorities) opts.authorities = [authority];
    } else if (searches.find(search => name.endsWith(`.${search}`))) {
      // in search to glue
      await resolverViaCache(this.glue);
      // finish resolve do not recursive
      return opts;
    } else {
      // other to forwarder
      await resolverViaCache(this.forwarder);
      // finish resolve do not recursive
      return opts;
    }

    if (type === 'MX') {
      opts.answers = opts.answers.map(answer => {
        if (typeof answer.data !== 'string') return answer;
        const [preference, exchange] = answer.data.split(' ');
        return { ...answer, data: { preference, exchange } };
      });
      return opts;
    }
    if (type !== 'A') return opts;
    if (!opts.resolved) opts.resolved = [];
    opts.aliases = opts.answers.filter(item => {
      if (opts.resolved.find(v => v.data === item.data)) return false;
      return item.type === 'CNAME';
    });
    if (!opts.aliases.length) {
      return opts;
    }
    await Promise.all(opts.aliases.map(alias => {
      opts.resolved.push(alias);
      const normName = alias.data.endsWith('.') ? alias.data.slice(0, -1) : alias.data;
      return this.enter(normName, 'A', opts);
    }));
    return opts;
  }

  async parseDNS(msg) {
    const query = dnsPacket.decode(msg);
    const { id, questions } = query;
    const [question] = questions;
    const name = question.name.toLowerCase();
    const { type } = question;
    const { answers, authorities } = await this.enter(name, type)
    .catch(e => logger.error(JSON.stringify({ enter: e.message, name, type })) ?? { answers: [] });
    const flags = answers.length ? dnsPacket.RECURSION_AVAILABLE : 0;
    const rcode = answers.length ? 0 : 3;
    const response = dnsPacket.encode({
      type: 'response', id, flags, rcode, questions, answers, authorities,
    });
    return response;
  }
}
