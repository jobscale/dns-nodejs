import { Nameserver } from '../app/index.js';

describe('Nameserver enter() actual name resolution tests', () => {
  let ns;

  beforeAll(async () => {
    ns = await new Nameserver().createServer({ transport: 'udp' });
  });

  afterAll(async () => {
    ns.terminate();
  });

  ['first check', 'cache check'].forEach(type => {
    describe(`${type} phase`, () => {
      describe('static ip address', () => {
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
      });

      describe('listup domain check', () => {
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
          'uk.jsx.jp',
          'fr.jsx.jp',
          'de.jsx.jp',
          'au.jsx.jp',
          'br.jsx.jp',
          'cn.jsx.jp',
          'kr.jsx.jp',
          'sg.jsx.jp',
          'ca.jsx.jp',
          'es.jsx.jp',
          'ocn.ne.jp',
          'www.ntt-east.co.jp',
          'www.ntt-west.co.jp',
          'docomo.ne.jp',
          'softbank.jp',
          'au.com',
          'www.jcom.co.jp',
          'nifty.com',
          'plala.or.jp',
          'microsoft.com',
          'office.com',
          'teams.microsoft.com',
          'azure.com',
          'aws.amazon.com',
          'alexa.com',
          'youtube.com',
          'drive.google.com',
          'gmail.com',
          'x.com',
          'twitter.com',
          'discord.com',
          'line.me',
          'chatwork.com',
          'slack.com',
          'instagram.com',
          'zoom.us',
          'mobile.rakuten.co.jp',
          'pay.rakuten.co.jp',
          'rakuten.co.jp',
          'paypay.ne.jp',
          'visa.co.jp',
          'www.mufg.jp',
          'www.nomura.co.jp',
          'playstation.com',
          'roblox.com',
          'steampowered.com',
          'rockstargames.com',
          'minecraft.net',
          'fortnite.com',
          'finalfantasy.com',
          'yahoo.co.jp',
          'atlassian.com',
          'zscaler.com',
          'udemy.com',
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

      describe('deny-regex domain check', () => {
        // deny-regex file contains regex patterns for matching domain names
        // Examples: -ad-, -ads., .ads-, googleads., .yimg.jp, ads.g.doubleclick.net
        // When a domain matches a deny-regex pattern, it should be processed as denyHost
        // denyHost function returns a CNAME record redirecting to GITHUB.IO
        test('should identify domain matching deny-regex pattern -ad- as denyHost candidate', async () => {
          // test-ad-domain.com contains "-ad-" which matches the pattern in deny-regex file
          // The nameserver should invoke denyHost function for this domain
          const result = await ns.enter('test-ad-domain.com', 'A');

          // When denyHost is invoked, it returns a CNAME record from the original domain to GITHUB.IO
          expect(result).toBeDefined();
          expect(result.answers).toBeDefined();

          // Look for CNAME record created by denyHost function
          const cnameFromDenyHost = result.answers.find(answer =>
            answer.type === 'CNAME' &&
            answer.name === 'test-ad-domain.com' &&
            answer.data === 'GITHUB.IO' &&
            answer.ttl === 2592000,
          );

          expect(cnameFromDenyHost).toBeDefined();
        });

        test('should apply denyHost function to domains matching deny-regex patterns', async () => {
          // banner-ads.com contains "-ads." pattern from deny-regex
          const result = await ns.enter('banner-ads.com', 'A');

          expect(result).toBeDefined();
          expect(result.answers).toBeDefined();

          // Should have CNAME from denyHost function
          const denyHostRecord = result.answers.find(a =>
            a.type === 'CNAME' &&
            a.data === 'GITHUB.IO',
          );

          expect(denyHostRecord).toBeDefined();
          expect(denyHostRecord.ttl).toBe(2592000);
        });
      });
    });
  });
});
