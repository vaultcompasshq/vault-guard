import { generateKeyPairSync } from 'crypto';
import { SecretScanner } from '../secret-scanner';
import { randomBody } from './pem-test-bodies';

const scanner = new SecretScanner({});
const PEM_RULE = 'ssh-private-key';
const URL_RULES = new Set(['postgresql-url', 'mysql-url', 'mongodb-url', 'redis-url']);

const reported = (text: string, rules: ReadonlySet<string> | string): boolean =>
  scanner.scanContent(text, { filePath: '/r/x.txt' }).some(m => (typeof rules === 'string' ? m.type === rules : rules.has(m.type)));

const HDR = '-----BEGIN PRIVATE KEY-----';
const FTR = '-----END PRIVATE KEY-----';
const wrap = (lines: string[]): string => [HDR, ...lines, FTR].join('\n') + '\n';
const fold = (s: string, n: number): string[] => s.match(new RegExp(`.{1,${n}}`, 'g')) ?? [];
const first = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC';

/** Documentation and sample shapes that are not keys: every one must stay silent. */
const DOC_PEM: Array<[string, string]> = [
  ['x lines (32 wide) under a realistic first line', wrap([first, ...Array(3).fill('x'.repeat(32))])],
  ['x lines (64 wide) under a realistic first line', wrap([first, ...Array(3).fill('x'.repeat(64))])],
  ['A lines', wrap([first, ...Array(3).fill('A'.repeat(32))])],
  ['REDACTED lines', wrap([first, ...Array(3).fill('REDACTED'.repeat(4))])],
  ['a repeated Base64EncodedKeyMaterial', wrap(['Base64EncodedKeyMaterial', 'Base64EncodedKeyMaterial', 'Base64EncodedKeyMaterial'])],
  ['YourBase64EncodedPrivateKey over two lines', wrap(['YourBase64EncodedPrivateKey', 'GoesHereOnSeveralLines123'])],
  ['39 characters, an ellipsis, 29 characters', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM9Oi', '...', 'Kq8vZ3pXw9Lm2Tn+abcdEFGH1234=='])],
  ['two 28-character lines around an ellipsis', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAM', '...', 'Kq8vZ3pXw9Lm2Tn+abcdEFGH1234'])],
  ['two 28-character lines then an ellipsis', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAM', 'fQyuvBjM9Oi8Kq8vZ3pXw9Lm2Tn', '...'])],
  ['two 36-character lines then an ellipsis', wrap([randomBody(36, 1), randomBody(36, 2), '...'])],
  ['a header as a label before an enum', "export const PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----';\nexport enum Algo {\n  RsaPrivateKey2048,\n  RsaPrivateKey4096,\n  EcPrivateKeyP256,\n  EcPrivateKeyP384,\n  Ed25519PrivateKey,\n}\n"],
  ['a header as a label before a Python list', "PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----'\nKEY_TYPES = [\n    'Ed25519PrivateKey',\n    'RsaPrivateKey2048',\n    'EcPrivateKeyP256',\n    'EcPrivateKeyP384',\n]\n"],
  ['a header in a JSON object before an ids array', '{"header": "-----BEGIN RSA PRIVATE KEY-----",\n "ids": [\n  "a1b2c3d4e5f60718293a4b5c6d7e8f90",\n  "b1c2d3e4f5a60718293a4b5c6d7e8f91",\n  "c1d2e3f4a5b60718293a4b5c6d7e8f92"\n ]}\n'],
  ['a header ending a sentence, then vectors', 'Test vectors for the parser, see -----BEGIN RSA PRIVATE KEY----- in the spec:\n\nVGhpcyBpcyBhIHRlc3QgdmVjdG9yIG51bWJlciBvbmU=\nVGhpcyBpcyBhIHRlc3QgdmVjdG9yIG51bWJlciB0d28=\n'],
  ['a header in a markdown sentence, then commit ids', 'The key starts with the line `-----BEGIN RSA PRIVATE KEY-----`. Recent commits:\n\n- 3f2a9c81d7e04b6a\n- 9b1e44c2a8f03d57\n- c07d5e19b3a2f684\n'],
];

const R = 'Kq8vZ3pXw9Lm2Tn';
const DOC_URLS: Array<[string, string]> = [
  ['an x password', 'REDIS_URL=redis://:xxx@cache.acme.io:6379'],
  ['a dot password', 'REDIS_URL=redis://:...@cache.acme.io:6379'],
  ['a percent-encoded star mask', 'REDIS_URL=redis://:%2A%2A%2A@cache.acme.io:6379'],
  ['a Python format field', 'DB=postgres://app:%(db_pw)s@db.acme.io/main'],
  ['the default Redis port typed as a password', 'REDIS_URL=redis://:6379@cache.acme.io'],
  ['the default Postgres port typed as a password', 'DB=postgres://:5432@db.acme.io/main'],
];
const REAL_URLS: Array<[string, string]> = [
  ['an empty user with a real password', `REDIS_URL=redis://:${R}@cache.acme.io:6379`],
  ['a numeric password that is not the default port', 'REDIS_URL=redis://:48151623@cache.acme.io:6379'],
  ['a Postgres URL', `DB=postgres://app:${R}@db.acme.io/main`],
  ['a default port as the password for another scheme', 'DB=postgres://:6379@db.acme.io/main'],
];

function realKeys(): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  const enc = { type: 'pkcs8', format: 'pem' } as const;
  const pairs: Array<[string, string]> = [
    ['rsa', generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: enc, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey],
    ['ec', generateKeyPairSync('ec', { namedCurve: 'prime256v1', privateKeyEncoding: enc, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey],
    ['ed25519', generateKeyPairSync('ed25519', { privateKeyEncoding: enc, publicKeyEncoding: { type: 'spki', format: 'pem' } }).privateKey],
  ];
  for (const [kind, pem] of pairs) {
    const b64 = pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');
    for (const w of [8, 12, 16, 32, 64, 76]) out.push([`${kind} folded at ${w}`, wrap(fold(b64, w))]);
    out.push([`${kind} on one line`, wrap([b64])]);
    out.push([`${kind} without a footer, folded at 64`, [HDR, ...fold(b64, 64)].join('\n') + '\n']);
    out.push([`${kind} without a footer, folded at 16`, [HDR, ...fold(b64, 16)].join('\n') + '\n']);
    // Uneven widths between 20 and 39.
    const lines: string[] = [];
    let seed = 7;
    for (let i = 0; i < b64.length; ) {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      const n = 20 + ((seed >> 8) % 20);
      lines.push(b64.slice(i, i + n));
      i += n;
    }
    out.push([`${kind} folded unevenly`, wrap(lines)]);
  }
  return out;
}

describe('false-positive corpus: documentation shapes stay silent, real keys and URLs are reported', () => {
  it.each(DOC_PEM)('documentation, not a key: %s', (_name, text) => {
    expect(reported(text, PEM_RULE)).toBe(false);
  });

  it.each(realKeys())('a real key is reported: %s', (_name, text) => {
    expect(reported(text, PEM_RULE)).toBe(true);
  });

  it.each(DOC_URLS)('a URL that is not a credential: %s', (_name, text) => {
    expect(reported(`${text}\n`, URL_RULES)).toBe(false);
  });

  it.each(REAL_URLS)('a URL with a credential is reported: %s', (_name, text) => {
    expect(reported(`${text}\n`, URL_RULES)).toBe(true);
  });

  it('a real key with a stray ellipsis line in the middle is still reported', () => {
    const b64 = randomBody(1190, 9);
    const lines = fold(b64, 32);
    lines.splice(Math.floor(lines.length / 2), 0, '...');
    expect(reported(wrap(lines), PEM_RULE)).toBe(true);
  });
});

describe('base64 characters at a fold boundary are not lost to the peeling of list syntax', () => {
  it('an Ed25519-length body (64 characters) split after a "+" and before a "//" is reported', () => {
    const b64 = `MC4CAQAwBQYDK2VwBCIEIB15pKOSi${'k68a+WCmQ/QoP+rAZ+XyhLuXZ4oK1KfDk'}++`;
    expect(reported(wrap(['MC4CAQAwBQYDK2VwBCIEIB15pKOSi', 'k68a+WCmQ/QoP+rAZ+XyhLuXZ4oK1KfDk++']), PEM_RULE)).toBe(true);
    expect(reported(wrap(['MC4CAQAwBQYDK2VwBCIEIErjvrFCo+', '//T91g3IzgqUZJqW+gfOkqSUtkpL2ixGZqV']), PEM_RULE)).toBe(true);
    expect(b64.length).toBeGreaterThan(0);
  });
});

describe('without a footer the run starts on the line after the header', () => {
  const body = fold(randomBody(1190, 3), 64);
  const keyFrom = (lines: string[]): string => [HDR, ...lines].join('\n') + '\n';

  it('a blank line or RFC 1421 header lines between the header and the body are fine', () => {
    expect(reported(keyFrom(['', ...body]), PEM_RULE)).toBe(true);
    expect(reported(keyFrom(['Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF', '', ...body]), PEM_RULE)).toBe(true);
  });

  it('a body folded at 16 columns starts the run on the next line', () => {
    expect(reported(keyFrom(fold(randomBody(600, 4), 16)), PEM_RULE)).toBe(true);
  });

  it('a list that starts later is not the body, however key-like its lines are', () => {
    expect(reported(keyFrom(['// the vectors below', ...fold(randomBody(600, 4), 16)]), PEM_RULE)).toBe(false);
    expect(reported(keyFrom(['const vectors = [', ...fold(randomBody(600, 4), 16)]), PEM_RULE)).toBe(false);
  });

  it('text after the header on its own line means the header is a label', () => {
    expect(reported(`${HDR} then paste your key\n${body.join('\n')}\n`, PEM_RULE)).toBe(false);
  });

  it('a run that is interrupted is judged only up to the interruption', () => {
    const lines = fold(randomBody(600, 5), 16);
    lines.splice(1, 0, 'this line is not base64');
    expect(reported(keyFrom(lines), PEM_RULE)).toBe(false);
  });
});

describe('with a footer, a run of 40 joined characters is not enough', () => {
  it('a footer and two 20-character lines are not a key body', () => {
    expect(reported(wrap([randomBody(20, 1), randomBody(20, 2)]), PEM_RULE)).toBe(false);
  });
  it('64 characters in two lines under a footer are', () => {
    expect(reported(wrap([randomBody(32, 1), randomBody(32, 2)]), PEM_RULE)).toBe(true);
  });
});
