import { generateKeyPairSync } from 'crypto';
import { SecretScanner } from '../secret-scanner';
import { cleanPemToken, declinedBy1134, isPemHeaderWithoutBody } from '../../utils/placeholder';
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
  ['a header in a markdown sentence, then commit ids', 'The key starts with the line `-----BEGIN RSA PRIVATE KEY-----`. Recent commits:\n\n- 3f2a9c81d7e04b6a\n- 9b1e44c2a8f03d57\n- c07d5e19b3a2f684\n'],
  ['the base64 alphabet over two lines', wrap(['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef', 'ghijklmnopqrstuvwxyz0123456789+/'])],
  ['the base64 alphabet over three lines', wrap(['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef', 'ghijklmnopqrstuvwxyz0123456789+/', 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef'])],
  ['a "Word: text" line then digests (not an RFC 1421 header)', `Key format: ${HDR}\nNote: digests of the test keys\n- ${randomBody(32, 41)}\n- ${randomBody(32, 42)}\n- ${randomBody(32, 43)}\n`],
  ['a YAML algorithm line then list items', `key:\n  header: ${HDR}\n  algorithm: rsa\n  ids:\n    - ${randomBody(32, 44)}\n    - ${randomBody(32, 45)}\n    - ${randomBody(32, 46)}\n`],
  ['every line ending in three dots', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQ...', 'yuvBjM9Oi8Kq8vZ3pXw9Lm2Tn+abcdE...', 'FGH1234qRsT5uVwXyZ0aBcDeFgHiJkL...'])],
  ['every line ending in the ellipsis character', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQ…', 'yuvBjM9Oi8Kq8vZ3pXw9Lm2Tn+abcdE…', 'FGH1234qRsT5uVwXyZ0aBcDeFgHiJkL…'])],
  ['a spaced ". . ." ellipsis', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM', '. . .', 'Kq8vZ3pXw9Lm2Tn+abcdEFGH1234abcdEFGH'])],
  ['".. (truncated)"', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM', '.. (truncated)', 'Kq8vZ3pXw9Lm2Tn+abcdEFGH1234abcdEFGH'])],
  ['"etc." between two pieces', wrap(['MIIEpAIBAAKCAQEA3Tz2mr7SZiAMfQyuvBjM', 'etc.', 'Kq8vZ3pXw9Lm2Tn+abcdEFGH1234abcdEFGH'])],
  ['no footer: two 32-character blocks apart (an empty line between) are not one 64-character run', [HDR, ...fold(randomBody(32, 51), 16), '', ...fold(randomBody(32, 52), 16)].join('\n') + '\n'],
  ['no footer: pieces around an ellipsis are not one run', [HDR, ...fold(randomBody(48, 53), 16), '...', ...fold(randomBody(48, 54), 16)].join('\n') + '\n'],
  ['no footer: 96 characters then an ellipsis then 16', [HDR, ...fold(randomBody(96, 55), 16), '...', randomBody(16, 56)].join('\n') + '\n'],
  ['an "omitted" line between two pieces', wrap([randomBody(36, 57), 'omitted', randomBody(36, 58)])],
  ['a "TRUNCATED" line between two pieces', wrap([randomBody(36, 57), 'TRUNCATED', randomBody(36, 58)])],
  ['a "cut" line between two pieces', wrap([randomBody(36, 57), 'cut', randomBody(36, 58)])],
  ['a "snipped" line between two pieces', wrap([randomBody(36, 57), 'snipped', randomBody(36, 58)])],
  ['an "[elided]" line between two pieces', wrap([randomBody(36, 57), '[elided]', randomBody(36, 58)])],
  ['an "(omitted)" line between two pieces', wrap([randomBody(36, 57), '(omitted)', randomBody(36, 58)])],
  ['no footer: an "omitted" line between two pieces', [HDR, randomBody(36, 57), 'omitted', randomBody(36, 58)].join('\n') + '\n'],
  ['two lines of 32 whose second is camelCase words (under 48 characters)', wrap(['MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'ReplaceThisPrivateMaterialHere12'])],
  ['an OpenSSH preamble over a repeated phrase', ['-----BEGIN OPENSSH PRIVATE KEY-----', ...fold('b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAA' + 'Zm9vYmFy'.repeat(24), 16), '-----END OPENSSH PRIVATE KEY-----'].join('\n') + '\n'],
  ['an OpenSSH preamble and nothing else', ['-----BEGIN OPENSSH PRIVATE KEY-----', ...fold('b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD', 16), '-----END OPENSSH PRIVATE KEY-----'].join('\n') + '\n'],
  ['a "// comment:" line is not an RFC 1421 header', [HDR, '// comment: see the docs', ...fold(randomBody(160, 59), 16)].join('\n') + '\n'],
  ['every-second-letter alphabets', wrap(['MIIEvQIBADANBgkqhkiG9w0BAQEFAASC', 'acegikmoqsuwyACEGIKMOQSUWY13579', 'bdfhjlnprtvxzBDFHJLNPRTVXZ24680'])],
];

const R = 'Kq8vZ3pXw9Lm2Tn';
const DOC_URLS: Array<[string, string]> = [
  ['an x password', 'REDIS_URL=redis://:xxx@cache.acme.io:6379'],
  ['a dot password', 'REDIS_URL=redis://:...@cache.acme.io:6379'],
  ['a percent-encoded star mask', 'REDIS_URL=redis://:%2A%2A%2A@cache.acme.io:6379'],
  ['a Python format field', 'REDIS_URL=redis://:%(db_pw)s@cache.acme.io:6379'],
  ['the default Redis port typed as a password', 'REDIS_URL=redis://:6379@cache.acme.io'],
  ['the default Postgres port typed as a password', 'DB=postgres://:5432@db.acme.io/main'],
  ['a printf %s', 'REDIS_URL=redis://:%s@cache.acme.io:6379'],
  ['a Go %v', 'REDIS_URL=redis://:%v@cache.acme.io:6379'],
  ['null', 'REDIS_URL=redis://:null@cache.acme.io:6379'],
  ['undefined', 'REDIS_URL=redis://:undefined@cache.acme.io:6379'],
  ['none', 'REDIS_URL=redis://:none@cache.acme.io:6379'],
  ['a dash', 'REDIS_URL=redis://:-@cache.acme.io:6379'],
  ['a question mark', 'REDIS_URL=redis://:?@cache.acme.io:6379'],
  ['bullets', 'REDIS_URL=redis://:\u2022\u2022\u2022\u2022@cache.acme.io:6379'],
  ['black circles', 'REDIS_URL=redis://:\u25CF\u25CF\u25CF\u25CF@cache.acme.io:6379'],
  ['Ruby interpolation', "REDIS_URL=redis://:#{ENV['X']}@cache.acme.io:6379"],
  ['a concatenation with a quoted key', "url = 'redis://:'+os.environ['PW']+'@cache.acme-prod.net'"],
  ['a concatenation with spaces', "url = 'redis://:' + os.environ['PW'] + '@cache.acme-prod.net'"],
];
const REAL_URLS: Array<[string, string]> = [
  ['an empty user with a real password', `REDIS_URL=redis://:${R}@cache.acme.io:6379`],
  ['a numeric password that is not the default port', 'REDIS_URL=redis://:48151623@cache.acme.io:6379'],
  ['a Postgres URL', `DB=postgres://app:${R}@db.acme.io/main`],
  ['a user with the password none (1.13.4 reported it)', 'DB=postgres://app:none@db.acme-prod.net/app'],
  ['a user with the password null', 'DB=postgres://app:null@db.acme-prod.net/app'],
  ['a user with the password -', 'DB=postgres://app:-@db.acme-prod.net/app'],
  ['a user with the password %s', 'DB=postgres://app:%s@db.acme-prod.net/app'],
  ['a default port as the password for another scheme', 'DB=postgres://:6379@db.acme.io/main'],
  ['a password that merely starts with null', 'REDIS_URL=redis://:nullable9Kq8vZ3p@cache.acme.io:6379'],
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

  it('text after the header does not hide a 64-column body that 1.13.4 reported', () => {
    expect(reported(`${HDR} then paste your key\n${body.join('\n')}\n`, PEM_RULE)).toBe(true);
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

describe('a body on the header line, with no footer, is a body by the 40-character rule', () => {
  const rsa = randomBody(1600, 77);
  const ed = randomBody(64, 78);
  it.each([
    ['an env assignment', `KEY=${HDR}${rsa}\n`],
    ['an env assignment, truncated with dots', `KEY=${HDR}${rsa.slice(0, 60)}...\n`],
    ['an Ed25519-length body', `KEY=${HDR}${ed}\n`],
    ['the body folded into space-joined chunks', `${HDR} ${fold(rsa, 64).join(' ')}\n`],
    ['an END footer more than 8192 characters away', `${HDR}${rsa}\n${'x'.repeat(9000)}\n${FTR}\n`],
    ['another BEGIN directly after the body', `${HDR}${rsa}${HDR}\n`],
  ])('is reported: %s', (_name, text) => {
    expect(reported(text, PEM_RULE)).toBe(true);
  });
  it('prose after the header on its own line is still a label', () => {
    expect(reported(`${HDR} then paste a key of at least forty characters here\n`, PEM_RULE)).toBe(false);
  });
});

describe('legacy encrypted keys written as string concatenations', () => {
  const body = fold(randomBody(1190, 21), 16);
  const dek = 'DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF';
  it('a JavaScript concatenation, with the headers quoted, is reported at width 16', () => {
    const js = ['const k = "-----BEGIN RSA PRIVATE KEY-----\\n" +', '  "Proc-Type: 4,ENCRYPTED\\n" +', `  "${dek}\\n" +`, '  "\\n" +', ...body.map(l => `  "${l}\\n" +`), '  "";'].join('\n');
    expect(reported(`${js}\n`, PEM_RULE)).toBe(true);
  });
  it('a Python concatenation is reported at width 16', () => {
    const py = ['k = ("-----BEGIN RSA PRIVATE KEY-----\\n"', '     "Proc-Type: 4,ENCRYPTED\\n"', `     "${dek}\\n"`, '     "\\n"', ...body.map(l => `     "${l}\\n"`), '     )'].join('\n');
    expect(reported(`${py}\n`, PEM_RULE)).toBe(true);
  });
  it('plain RFC 1421 headers and a Comment header, with a footer', () => {
    const pem = ['-----BEGIN RSA PRIVATE KEY-----', 'Proc-Type: 4,ENCRYPTED', dek, 'Comment: made by hand', '', ...body, '-----END RSA PRIVATE KEY-----'].join('\n');
    expect(reported(`${pem}\n`, PEM_RULE)).toBe(true);
  });
});

describe('characters at the end of a fold are base64, not syntax', () => {
  it('a body of 64 characters whose last character is "+" and sits alone on a 21-column fold', () => {
    const b = `${randomBody(63, 31)}+`;
    expect(fold(b, 21)).toHaveLength(4);
    expect(reported(wrap(fold(b, 21)), PEM_RULE)).toBe(true);
    expect(reported([HDR, ...fold(b, 21)].join('\n') + '\n', PEM_RULE)).toBe(true);
  });
  it('a last line of "++" or "//"', () => {
    expect(reported(wrap([`${randomBody(31, 32)}`, `${randomBody(31, 33)}`, '++']), PEM_RULE)).toBe(true);
    expect(reported(wrap([`${randomBody(31, 32)}`, `${randomBody(31, 33)}`, '//']), PEM_RULE)).toBe(true);
  });
});

describe('an unencrypted OpenSSH Ed25519 key is reported at every fold width', () => {
  function opensshBody(seed: number): string {
    const str = (b: Buffer): Buffer => Buffer.concat([Buffer.from([0, 0, 0, b.length]), b]);
    const pub = Buffer.from(randomBody(43, seed), 'base64').subarray(0, 32);
    const sec = Buffer.from(randomBody(86, seed + 1), 'base64').subarray(0, 32);
    const check = Buffer.from([1, 2, 3, 4]);
    const inner = Buffer.concat([check, check, str(Buffer.from('ssh-ed25519')), str(pub), str(Buffer.concat([sec, pub])), str(Buffer.from('user@host'))]);
    const pad = Buffer.from(Array.from({ length: (8 - (inner.length % 8)) % 8 }, (_, i) => i + 1));
    const blob = Buffer.concat([Buffer.from('openssh-key-v1\0'), str(Buffer.from('none')), str(Buffer.from('none')), str(Buffer.alloc(0)), Buffer.from([0, 0, 0, 1]), str(Buffer.concat([str(Buffer.from('ssh-ed25519')), str(pub)])), str(Buffer.concat([inner, pad]))]);
    return blob.toString('base64');
  }
  it.each([8, 12, 16, 32, 64, 70])('width %i', w => {
    const body = opensshBody(5);
    expect(body.startsWith('b3BlbnNzaC1rZXktdjE')).toBe(true);
    const text = ['-----BEGIN OPENSSH PRIVATE KEY-----', ...fold(body, w), '-----END OPENSSH PRIVATE KEY-----'].join('\n') + '\n';
    expect(reported(text, PEM_RULE)).toBe(true);
  });
});

describe('long runs of syntax characters are judged in linear time', () => {
  it.each([
    ['plus signs', '+'],
    ['plus and quote', '+"'],
    ['comma and semicolon', ',;'],
    ['dots and spaces', '. '],
    ['quotes', '"'],
    ['closing brackets', ')]'],
  ])('a header followed by 8000 characters of %s, 40 times', (_name, unit) => {
    const text = `${HDR}\n${unit.repeat(Math.ceil(8000 / unit.length))}x\n`;
    const t0 = Date.now();
    for (let i = 0; i < 40; i++) isPemHeaderWithoutBody(text, HDR.length);
    // With the quadratic expressions one call took 30 to 800 ms; linear, 40 calls take a few.
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it('1 MB of headers each followed by 8000 plus-and-quote characters is scanned in seconds, not 30', () => {
    const text = `${HDR}\n${'+"'.repeat(4000)}x\n`.repeat(120);
    const t0 = Date.now();
    reported(text, PEM_RULE);
    expect(Date.now() - t0).toBeLessThan(8000);
  });
});

describe('reviewer shapes that 1.13.4 reported are still reported', () => {
  const body64 = fold(randomBody(9300, 61), 64);
  it.each([
    ['PGP Version and Hash headers, a 9.3k body, no footer in range', ['-----BEGIN RSA PRIVATE KEY-----', 'Version: GnuPG v1', 'Hash: SHA256', '', ...body64].join('\n') + '\n'],
    ['an OpenPGP.js Version header', ['-----BEGIN RSA PRIVATE KEY-----', 'Version: OpenPGP.js v4.10.10', 'Comment: https://openpgpjs.org', '', ...body64.slice(0, 20)].join('\n') + '\n'],
    ['an SSH2 Subject header', ['-----BEGIN RSA PRIVATE KEY-----', 'Subject: ops', '', ...body64.slice(0, 20)].join('\n') + '\n'],
    ['an X-Note header', ['-----BEGIN RSA PRIVATE KEY-----', 'X-Note: staging', ...body64.slice(0, 20)].join('\n') + '\n'],
    ['a trailing comment on the header line, no footer', ['-----BEGIN RSA PRIVATE KEY-----  # staging only', ...body64.slice(0, 20)].join('\n') + '\n'],
    ['a space-joined body whose last token ends in +', `${HDR} MC4CAQAwBQYDK2VwBCIEIGk+ArNScJ/a3hrNdt83QmFfDXSoHsoeR z63DrThWq++ ${FTR}\n`],
  ])('%s', (_name, text) => {
    expect(reported(text, PEM_RULE)).toBe(true);
  });
});

describe('the superset rule: a key 1.13.4 reported is reported', () => {
  function presentations(body: string, i: number): string[] {
    const widths = [8, 12, 16, 24, 32, 40, 64, 76];
    const out: string[] = [];
    for (const w of widths) {
      const ls = fold(body, w);
      out.push(wrap(ls), [HDR, ...ls].join('\n'), wrap(ls).replace(/\n/g, '\r\n'));
      out.push(JSON.stringify(wrap(ls)).slice(1, -1), ls.map(l => `# ${l}`).join('\n').replace(/^/, `${HDR}\n`) + `\n${FTR}\n`);
      out.push(`${HDR}  # staging only\n${ls.join('\n')}`, `${HDR}\nVersion: GnuPG v1\nHash: SHA256\n\n${ls.join('\n')}\n`, `KEY=${HDR}${body}`, `${HDR} ${ls.join(' ')} ${FTR}`);
      out.push(`${HDR}\n${ls.map(l => `    "${l}\\n" +`).join('\n')}\n`, wrap(ls.map(l => `${l}+`)), wrap([...ls.slice(0, 2), '...', ...ls.slice(2)]));
    }
    return out.map(t => (i % 2 === 0 ? t : `prefix text\n${t}`));
  }
  it('holds for generated keys in many presentations', () => {
    let checked = 0;
    let reportedBy1134 = 0;
    for (let i = 0; i < 40; i++) {
      for (const text of presentations(randomBody(64 + ((i * 37) % 1700), 1000 + i), i)) {
        const off = text.indexOf('PRIVATE KEY-----') + 'PRIVATE KEY-----'.length;
        const old = declinedBy1134(text, off);
        if (!old) reportedBy1134++;
        if (!old) expect(isPemHeaderWithoutBody(text, off)).toBe(false);
        checked++;
      }
    }
    expect(checked).toBeGreaterThan(1500);
    expect(reportedBy1134).toBeGreaterThan(300);
  });
  it('holds for random region text', () => {
    const atoms = ['AbCd1+/Ef', 'GhIj2kLmNoPqRsTuVwXyZ0123456789abcdefgh', '\n', '\n', ' ', '"', "'", '+', '...', '#', '-----END ', '-----BEGIN ', 'Version: x', '\\n', '=', '\t', 'xxxxxxxx', '//', ',', ';'];
    let x = 12345;
    const next = (n: number): number => {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      return (x >> 8) % n;
    };
    let kept = 0;
    for (let i = 0; i < 4000; i++) {
      let t = `${HDR}`;
      const n = 3 + next(40);
      for (let k = 0; k < n; k++) t += atoms[next(atoms.length)];
      if (!declinedBy1134(t, HDR.length)) {
        kept++;
        expect(isPemHeaderWithoutBody(t, HDR.length)).toBe(false);
      }
    }
    expect(kept).toBeGreaterThan(100);
  });
});

describe('cleanPemToken keeps its 1.13.4 output with a linear trailing strip', () => {
  // The expression on origin/main, quadratic on a long run.
  function original(raw: string): string {
    let t = raw;
    for (let i = 0; i < 4; i++) {
      const before = t;
      t = t
        .replace(/^(?:[#>;%|*]+|\/{2,}|-{2,})/, '')
        .replace(/^[bBrRuUfF]{1,2}(?=["'`])/, '')
        .replace(/^["'`[({\\]+/, '');
      if (t === before) break;
    }
    t = t.replace(/[\s"'`\])},;+\\.&|]+$/, '');
    return /^[-.&|+_]+$/.test(t) ? '' : t;
  }
  it('matches for 100,000 random strings, long punctuation runs and unicode spaces included', () => {
    const atoms = ['a', 'Z', '9', '+', '/', '=', '"', "'", '`', ']', ')', '}', ',', ';', '\\', '.', '&', '|', '#', '>', '*', '-', '_', '%', '(', '[', '{', 'b', 'r', ' ', ' ', ' ', '﻿', '\t', 'xyz'];
    let x = 987654;
    const next = (n: number): number => {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      return (x >> 8) % n;
    };
    for (let i = 0; i < 100000; i++) {
      let t = '';
      const n = next(12);
      for (let k = 0; k < n; k++) {
        const a = atoms[next(atoms.length)];
        t += next(5) === 0 ? a.repeat(1 + next(40)) : a;
      }
      expect(cleanPemToken(t)).toBe(original(t));
    }
  });
});

describe('narrow folds cost about what 1.13.4 cost', () => {
  it('1000 headers at 24 columns are judged in well under a second each thousand', () => {
    const texts = Array.from({ length: 1000 }, (_, i) => wrap(fold(randomBody(1200, 7000 + i), 24)));
    const t0 = Date.now();
    for (const t of texts) isPemHeaderWithoutBody(t, HDR.length);
    // About 0.1 ms each unloaded (1.13.4: about 0.07 ms); the bound is for a loaded CI machine.
    expect(Date.now() - t0).toBeLessThan(3000);
  });
});
