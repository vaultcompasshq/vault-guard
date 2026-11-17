import { SecretScanner } from '../secret-scanner';
import { isPemHeaderWithoutBody } from '../../utils/placeholder';

const HEADER = '-----BEGIN RSA PRIVATE KEY-----';
const FOOTER = '-----END RSA PRIVATE KEY-----';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function body(n = 1200): string {
  let x = 4242;
  let out = '';
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out += B64[x % 64];
  }
  return out;
}

/** Fold with a pseudo-random width in [lo, hi] for every line. */
function foldUneven(s: string, lo: number, hi: number): string[] {
  let x = 99;
  const out: string[] = [];
  for (let i = 0; i < s.length; ) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    const w = lo + ((x >> 8) % (hi - lo + 1));
    out.push(s.slice(i, i + w));
    i += w;
  }
  return out;
}

const withFooter = (lines: string[], sep = '\n'): string => [HEADER, ...lines, FOOTER].join(sep) + '\n';
const noFooter = (lines: string[]): string => [HEADER, ...lines].join('\n') + '\n';
const declines = (text: string): boolean => isPemHeaderWithoutBody(text, text.indexOf(HEADER) + HEADER.length);

describe('with a footer, the body is whatever lies between the armor lines', () => {
  it('uneven widths between 20 and 39', () => {
    const lines = foldUneven(body(), 20, 39);
    expect(new Set(lines.slice(0, -1).map(l => l.length)).size).toBeGreaterThan(5);
    expect(declines(withFooter(lines))).toBe(false);
  });

  it.each([8, 12])('width %i', n => {
    expect(declines(withFooter(foldUneven(body(), n, n)))).toBe(false);
  });

  it('blank lines between the base64 lines', () => {
    expect(declines(withFooter(foldUneven(body(), 30, 40), '\n\n'))).toBe(false);
  });

  it('lines padded with spaces and tabs', () => {
    expect(declines(withFooter(foldUneven(body(), 25, 35).map(l => `   ${l}  \t`)))).toBe(false);
  });

  it('uneven widths with CRLF and indentation', () => {
    const text = ['  ' + HEADER, ...foldUneven(body(), 20, 39).map(l => `  ${l}`), '  ' + FOOTER].join('\r\n') + '\r\n';
    expect(declines(text)).toBe(false);
  });

  it('a legacy encrypted key: Proc-Type and DEK-Info lines, then an uneven body', () => {
    const lines = ['Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF', '', ...foldUneven(body(), 20, 39)];
    expect(declines(withFooter(lines))).toBe(false);
  });

  it('the scanner reports an unevenly folded key', () => {
    expect(new SecretScanner({}).scanContent(withFooter(foldUneven(body(), 20, 39)), { filePath: '/r/x.pem' })).toHaveLength(1);
  });
});

describe('what still reads as a label', () => {
  it('uneven lines with no footer (the same-width rule applies there)', () => {
    expect(declines(noFooter(foldUneven(body(), 20, 39)))).toBe(true);
  });
  it('an empty body between header and footer', () => expect(declines(withFooter([]))).toBe(true));
  it('blank lines only', () => expect(declines(`${HEADER}\n\n\n${FOOTER}\n`)).toBe(true));
  it('an ellipsis', () => expect(declines(withFooter(['...'])).valueOf()).toBe(true));
  it('prose', () => {
    expect(declines(withFooter(['Paste your private key here.', 'It starts with the line above and ends below.']))).toBe(true);
  });
  it('a long sentence on several lines', () => {
    expect(declines(withFooter(['The quick brown fox jumps over the lazy dog and keeps on running far away']))).toBe(true);
  });
  it('a sentence of words, capitals and digits (several tokens per line)', () => {
    expect(declines(withFooter(['Step 1 Paste Your Key 2 Here Then Press Enter To Continue On Line 3 Of The Form']))).toBe(true);
  });
  it('single words one per line, without a digit', () => {
    const words = Array.from({ length: 12 }, (_, i) => ['Alpha', 'Bravo', 'Charlie', 'Delta', 'Echo', 'Foxtrot'][i % 6] + 'word');
    expect(declines(withFooter(words))).toBe(true);
  });
  it('prose among otherwise valid uneven lines (a parser would reject it, and it must not pass as a body)', () => {
    const lines = foldUneven(body(), 20, 39);
    lines.splice(3, 0, 'this line is not base64, it is text with spaces and a colon: no');
    expect(declines(withFooter(lines))).toBe(true);
  });
  it('too short to be key material', () => expect(declines(withFooter(['AbCdEfGh1234', 'AbCdEfGh1234', 'AbCd']))).toBe(true));
  it('a label in code', () => expect(declines(`const begins = '${HEADER}'\n`)).toBe(true));
});
