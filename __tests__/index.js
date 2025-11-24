import { Nameserver } from '../app/index.js';

describe('Nameserver enter() actual name resolution tests', () => {
  let ns;

  beforeAll(async () => {
    ns = await new Nameserver().createServer({ transport: 'udp' });
  });

  afterAll(async () => {
    ns.terminate();
  });

  test('should follow TXT record for version.internal', async () => {
    const result = await ns.enter('version.internal', 'TXT');
    const follow = result.answers.find(a => a.type === 'TXT');
    expect(follow).toBeDefined();
    expect(/^\d+\.\d+\.\d+$/.test(follow.data)).toBe(true);
  });

  test('should resolve internal domain dark.internal with A record', async () => {
    const result = await ns.enter('dark.internal', 'A');
    const answer = result.answers.find(a => a.name === 'dark.internal');
    expect(answer).toBeDefined();
    expect(answer.data).toBe('172.16.6.77');
  });

  test('should follow TXT record for version.jsx.jp', async () => {
    const result = await ns.enter('version.jsx.jp', 'TXT');
    const follow = result.answers.find(a => a.type === 'TXT');
    expect(follow).toBeDefined();
    expect(/^\d+\.\d+\.\d+$/.test(follow.data)).toBe(true);
  });

  test('should resolve root domain jsx.jp with A record', async () => {
    const result = await ns.enter('jsx.jp', 'A');
    const answer = result.answers.find(a => a.name === 'jsx.jp');
    expect(answer).toBeDefined();
    expect(answer.data).toBe('216.24.57.4');
  });

  test('should follow CNAME record for jsx.jp', async () => {
    const result = await ns.enter('cdn.jsx.jp', 'A');
    const cname = result.answers.find(a => a.type === 'CNAME');
    expect(cname).toBeDefined();
    expect(cname.data).toBe('jobscale.github.io.');
  });

  test('should resolve MX record for jsx.jp', async () => {
    const result = await ns.enter('jsx.jp', 'MX');
    const mx = result.answers.find(a => a.type === 'MX');
    expect(mx).toBeDefined();
    expect(mx.data.exchange).toMatch(/amazonaws\.com/);
    expect(Number.parseInt(mx.data.preference, 10)).toBeGreaterThan(0);
  });

  const LIST = [
    'proxy.jsx.jp',
    'version.jsx.jp',
    'black.jsx.jp',
    'pink.jsx.jp',
    'dark.jsx.jp',
    'n100.jsx.jp',
    'mac.jsx.jp',
    'shop.jsx.jp',
    'jp.jsx.jp',
    'us.jsx.jp',
    'eu.jsx.jp',
    'ae.jsx.jp',
    'x.jsx.jp',
    'a.jsx.jp',
    'in.jsx.jp',
    'video-assets.mathtag.com',
    'www.cloudflare.com',
    'cloudflare.com',
    'dns.google.com',
    'www.google.com',
    'www.amazon.com',
    'amazonaws.com',
  ];

  LIST.forEach(domain => {
    test(`should resolve ${domain} with A record`, async () => {
      const result = await ns.enter(domain, 'A');
      const answersA = result.answers.filter(a => a.type === 'A');
      expect(answersA.length).toBeGreaterThan(0);
      answersA.forEach(a => {
        expect(typeof a.data).toBe('string');
        expect(/^\d+\.\d+\.\d+\.\d+$/.test(a.data)).toBe(true);
      });
    });
  });
});
