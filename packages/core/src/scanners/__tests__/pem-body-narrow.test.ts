import { SecretScanner } from '../secret-scanner';
import { isPemHeaderWithoutBody } from '../../utils/placeholder';

const HEADER = '-----BEGIN RSA PRIVATE KEY-----';
const FOOTER = '-----END RSA PRIVATE KEY-----';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** A deterministic 1200-character base64 body (a 2048-bit RSA key is about this long). */
function body(): string {
  let x = 12345;
  let out = '';
  for (let i = 0; i < 1200; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out += B64[x % 64];
  }
  return out;
}

const fold = (s: string, n: number): string[] => s.match(new RegExp(`.{1,${n}}`, 'g')) ?? [];
const pem = (lines: string[], eol = '\n'): string => [HEADER, ...lines, FOOTER].join(eol) + eol;
const declines = (text: string): boolean => isPemHeaderWithoutBody(text, text.indexOf(HEADER) + HEADER.length);

describe('a PEM body is recognised at any fold width', () => {
  it.each([16, 32, 64, 76])('width %i', n => {
    expect(declines(pem(fold(body(), n)))).toBe(false);
  });

  it.each([16, 32, 64])('width %i with a "+" ending every line (cleanPemToken peels a trailing plus)', n => {
    const lines = fold(body(), n).map(l => l.slice(0, -1) + '+');
    expect(declines(pem(lines))).toBe(false);
  });

  it('one line', () => expect(declines(pem([body()]))).toBe(false));
  it('CRLF at width 32', () => expect(declines(pem(fold(body(), 32), '\r\n'))).toBe(false));
  it('an indented YAML block scalar at width 32', () => {
    const text = ['key: |', `  ${HEADER}`, ...fold(body(), 32).map(l => `  ${l}`), `  ${FOOTER}`].join('\n') + '\n';
    expect(declines(text)).toBe(false);
  });
  it('a JSON string with escaped newlines at width 32', () => {
    const text = `{"k":"${HEADER}\\n${fold(body(), 32).join('\\n')}\\n${FOOTER}\\n"}`;
    expect(declines(text)).toBe(false);
  });
  it('comment-led lines at width 32', () => {
    expect(declines(pem(fold(body(), 32).map(l => `# ${l}`)))).toBe(false);
  });
  it('the scanner reports a key refolded at 32 columns', () => {
    expect(new SecretScanner({}).scanContent(pem(fold(body(), 32)), { filePath: '/r/config/deploy.pem' })).toHaveLength(1);
  });
});

describe('a header without a body still declines', () => {
  it('nothing between the header and the footer', () => expect(declines(`${HEADER}\n${FOOTER}\n`)).toBe(true));
  it('a label in code', () => expect(declines(`const begins = '${HEADER}'\n`)).toBe(true));
  it('prose', () => expect(declines(`${HEADER}\nThis is the header you paste above your key.\n`)).toBe(true));
  it('an ellipsis', () => expect(declines(`${HEADER}\n...\n${FOOTER}\n`)).toBe(true));
  it('single words one per line', () => {
    expect(declines(`${HEADER}\nHello\nWorld\nAnother\nExample\nSentence\nBreaks\nHere\n`)).toBe(true);
  });
  it('lines of different widths', () => {
    expect(declines(`${HEADER}\nAbCdEfGh12345678\nAbCdEf\nAbCdEfGh123456789012\nAbC\n`)).toBe(true);
  });
  it('too short to be a key', () => expect(declines(`${HEADER}\nAbCdEfGh12345678\nAbCd\n`)).toBe(true));
});

describe('connection strings: the host and the password decline for different reasons', () => {
  const scanner = new SecretScanner({});
  const url = 'postgres://app_prod:Qz8vN2kLp4Rt7wXy@db/main';

  it('elsewhere a bare host declines, counted as a placeholder skip', () => {
    const ph = { count: 0, lines: [] as number[] };
    expect(scanner.scanContent(`${url}\n`, { placeholderSkips: ph })).toHaveLength(0);
    expect(ph.count).toBe(1);
  });

  it('with inlineDirectives mark the host decline is kept and named', () => {
    const m = scanner.scanContent(`${url}\n`, { inlineDirectives: 'mark' });
    expect(m.map(x => x.contextFilterNotHonoured)).toEqual(['local-host']);
  });

  it('a placeholder password still declines under mark, counted', () => {
    const ph = { count: 0, lines: [] as number[] };
    expect(scanner.scanContent('postgres://u:changeme@db.example.com/main\n', { inlineDirectives: 'mark', placeholderSkips: ph })).toHaveLength(0);
    expect(ph.count).toBe(1);
  });
});

describe('the value filters judge the secret part of a whole-match rule in mark mode', () => {
  const scanner = new SecretScanner({});
  const pw = 'Vq7hR2mX9kLp4TzB';
  const dsns = [
    `postgres://app:${pw}@prod-db.acme.io:5432/main?application_name=example-worker`,
    `mongodb://dummy_svc:${pw}@cluster0.ab1cd.mongodb.net/db`,
    `redis://example:${pw}@cache.acme.io:6379`,
  ];

  it.each(dsns)('elsewhere a marker anywhere in the URL declines it: %s', dsn => {
    expect(scanner.scanContent(`${dsn}\n`, {})).toHaveLength(0);
  });

  it.each(dsns)('in mark mode the marker outside the password keeps it, named url-context: %s', dsn => {
    expect(scanner.scanContent(`${dsn}\n`, { inlineDirectives: 'mark' }).map(m => m.contextFilterNotHonoured)).toEqual(['url-context']);
  });

  it('a placeholder password stays declined in mark mode, with its rule recorded', () => {
    const ph = { count: 0, lines: [] as number[], rules: [] as string[] };
    expect(scanner.scanContent('postgres://app:changeme@prod-db.acme.io:5432/main\n', { inlineDirectives: 'mark', placeholderSkips: ph })).toHaveLength(0);
    expect(ph).toMatchObject({ count: 1, lines: [1], rules: ['postgresql-url'] });
  });
});

describe('mark mode: every plausible split of a URL is judged, and what cannot be read is kept', () => {
  const scanner = new SecretScanner({});
  const kinds = (text: string): Array<string | undefined> =>
    scanner.scanContent(`${text}\n`, { inlineDirectives: 'mark' }).map(m => m.contextFilterNotHonoured);

  it.each([
    ['a password with a slash, marker in the query', 'postgres://app:Vq7h/R2mX9kLp4TzB@prod-db.acme.io:5432/main?application_name=example-worker'],
    ['a password with a slash, marker in the host', 'redis://u:Vq7h/R2mX9kLp4TzB@example-cache.acme.io:6379'],
    ['a password with a literal @, marker in the database', 'postgres://app:Vq7h@R2mX9kLp4TzB@prod-db.acme.io:5432/dummy_data'],
    ['a password with a quote', "postgres://app:Vq7h'R2mX9kLp4TzB@prod-db.acme.io:5432/dummy_data"],
    ['a percent-encoded @', 'postgres://app:Vq7h%40R2mX9kLp4TzB@prod-db.acme.io:5432/dummy_data'],
    ['a plain password, marker in the user', 'mongodb://dummy_svc:Vq7hR2mX9kLp4TzB@cluster0.ab1cd.mongodb.net/db'],
  ])('%s: kept, named url-context', (_name, url) => {
    expect(kinds(url)).toContain('url-context');
  });

  it('a first segment that alone looks like a placeholder does not drop the URL: the other split is a real password', () => {
    const url = 'postgres://app:ABCDEFGH@Xk29PqLmN4vRt7zW@prod-db.acme.io:5432/main';
    expect(scanner.scanContent(`${url}\n`, { inlineDirectives: 'mark' })).toHaveLength(1);
  });

  it('a placeholder password with a slash is still declined', () => {
    expect(kinds('postgres://app:change/me@prod-db.acme.io:5432/main')).toEqual([]);
  });

  it('azure: AccountKey spelled twice cannot be isolated, so the match is kept', () => {
    const key = 'Vq7hR2mX9kLp4TzB'.repeat(5);
    expect(kinds(`DefaultEndpointsProtocol=https;AccountName=AccountKey=example;AccountKey=${key}==`)).toEqual(['url-context']);
  });

  it('fail closed: a match whose secret part cannot be read is kept whole, even with a marker in it', () => {
    const patterns = (scanner as unknown as { patterns: Map<string, { regex: RegExp }> }).patterns;
    const entry = patterns.get('redis-url') as { regex: RegExp };
    const original = entry.regex;
    entry.regex = /redis:\/\/[^\s]+/g; // a contrived rule: matches a URL with no userinfo, nothing to extract
    try {
      const text = 'redis://example-cache.acme.io:6379\n';
      expect(scanner.scanContent(text, { inlineDirectives: 'mark' }).map(m => m.contextFilterNotHonoured)).toEqual(['url-context']);
      expect(scanner.scanContent(text, {})).toHaveLength(0); // elsewhere the marker still declines it
    } finally {
      entry.regex = original;
    }
  });
});
