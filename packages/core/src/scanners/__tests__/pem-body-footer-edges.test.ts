import { isPemHeaderWithoutBody } from '../../utils/placeholder';

const HEADER = '-----BEGIN RSA PRIVATE KEY-----';
const FOOTER = '-----END RSA PRIVATE KEY-----';
const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function body(n: number, seed: number): string {
  let x = seed;
  let out = '';
  for (let i = 0; i < n; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out += B64[(x >> 8) % 64];
  }
  return out;
}

const withFooter = (lines: string[]): string => [HEADER, ...lines, FOOTER].join('\n') + '\n';
const declines = (text: string): boolean => isPemHeaderWithoutBody(text, text.indexOf(HEADER) + HEADER.length);

describe('padding folded onto its own line', () => {
  const lines = [body(31, 1), body(29, 2), body(33, 3), body(17, 4)];
  it('a lone = is still part of the body', () => expect(declines(withFooter([...lines, '=']))).toBe(false));
  it('a lone == is still part of the body', () => expect(declines(withFooter([...lines, '==']))).toBe(false));
  it('the same body without padding', () => expect(declines(withFooter(lines))).toBe(false));
});

describe('an ellipsis between the armor lines marks a truncated example, when little base64 surrounds it', () => {
  const head = [body(20, 5)];
  const tail = [body(16, 7), 'wT1abcDEF=='];

  it.each([
    ['three dots', '...'],
    ['the Unicode ellipsis', '\u2026'],
    ['bracketed dots', '[...]'],
    ['a snip marker', '<snip>'],
    ['a comment-led ellipsis', '# ...'],
    ['indented dots', '    ...'],
  ])('%s', (_name, mark) => {
    expect(declines(withFooter([...head, mark, ...tail]))).toBe(true);
  });

  it('the truncated example from a README', () => {
    expect(declines(withFooter(['MIIEpAIBAAKCAQEAx7Kf9mQ2pL8vB3nR5', '...', 'wT1abcDEF==']))).toBe(true);
  });

  it('a truncated example with a long first line (40+ characters) still declines', () => {
    expect(declines(withFooter([body(44, 8), '...', 'wT1abcDEF==']))).toBe(true);
  });

  it('a full-length body with an ellipsis line in it is still a body (64 or more characters around it)', () => {
    const full = [body(32, 9), body(32, 10), '...', body(32, 11)];
    expect(declines(withFooter(full))).toBe(false);
  });

  it('exactly 64 characters around the ellipsis is a body, 63 is not', () => {
    expect(declines(withFooter([body(32, 12), '...', body(32, 13)]))).toBe(false);
    expect(declines(withFooter([body(32, 12), '...', body(31, 13)]))).toBe(true);
  });
});
