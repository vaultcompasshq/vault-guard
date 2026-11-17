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
