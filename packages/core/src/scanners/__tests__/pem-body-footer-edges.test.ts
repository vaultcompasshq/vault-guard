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

describe('padding on its own line counts only as the last line, and adds no length', () => {
  it('a = in the middle is not a body line', () => {
    expect(declines(withFooter([body(31, 1), '=', body(29, 2), body(33, 3), body(17, 4)]))).toBe(true);
  });
  it('the = line adds nothing to the length check (63 characters plus padding is not 64)', () => {
    expect(declines(withFooter([body(31, 20), body(32, 21), '=']))).toBe(true);
    expect(declines(withFooter([body(31, 20), body(33, 21), '=']))).toBe(false);
  });
});

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

  it('a truncated example whose first line is 36 characters still declines', () => {
    expect(declines(withFooter([body(36, 8), '...', 'wT1abcDEF==']))).toBe(true);
  });

  it('a full-length body with an ellipsis line in it is still a body', () => {
    const full = [body(32, 9), body(32, 10), '...', body(32, 11)];
    expect(declines(withFooter(full))).toBe(false);
  });

  it('48 base64 characters around the ellipsis are not a truncated example, 47 are', () => {
    // One 40-character line is a body by the single-token rule; the ellipsis cap is what declines it.
    expect(declines(withFooter([body(40, 12), '...', body(8, 13)]))).toBe(false);
    expect(declines(withFooter([body(40, 12), '...', body(7, 13)]))).toBe(true);
  });

  it('an Ed25519-length body (64 characters) ending in "+" with an ellipsis line is reported', () => {
    // The peeling of a trailing "+" counts it as 63; counted before the peeling it is 64.
    expect(declines(withFooter([`${body(63, 14)}+`, '...']))).toBe(false);
  });
});
