import { isPemHeaderWithoutBody } from '../../utils/placeholder';
import { randomBody } from './pem-test-bodies';

const HEADER = '-----BEGIN RSA PRIVATE KEY-----';
const FOOTER = '-----END RSA PRIVATE KEY-----';

const body = (n: number, seed: number): string => randomBody(n, seed);

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

describe('an ellipsis between the armor lines splits the span: short pieces are a truncated example', () => {
  const head = [body(20, 5)];
  const tail = [body(16, 7), 'wT1abcDEF=='];

  it.each([
    ['three dots', '...'],
    ['the Unicode ellipsis', '…'],
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

  it('two 28-character lines around the ellipsis are not one 56-character run', () => {
    expect(declines(withFooter([body(28, 30), '...', body(28, 31)]))).toBe(true);
  });

  it('two 36-character lines then an ellipsis are a truncated example', () => {
    expect(declines(withFooter([body(36, 32), body(36, 33), '...']))).toBe(true);
  });

  it('a first line of 40 or more characters still reports, as it did in 1.13.4', () => {
    expect(declines(withFooter([body(44, 8), '...', 'wT1abcDEF==']))).toBe(false);
  });

  it('a full-length narrow-fold body with a stray ellipsis line in it is reported: both pieces are bodies', () => {
    const lines = Array.from({ length: 36 }, (_, i) => body(32, 100 + i));
    lines.splice(18, 0, '...');
    expect(declines(withFooter(lines))).toBe(false);
  });

  it('a piece must be twice the smallest body (128 characters) when an ellipsis cuts the span', () => {
    expect(declines(withFooter([body(32, 40), body(32, 41), body(32, 42), body(32, 43), '...']))).toBe(false);
    expect(declines(withFooter([body(32, 40), body(32, 41), body(32, 42), '...']))).toBe(true);
  });

  it('an Ed25519-length body (64 characters) ending in "+" with an ellipsis line is reported', () => {
    // A single 63-character token after the peeling of its trailing "+": the long-token rule.
    expect(declines(withFooter([`${body(63, 14)}+`, '...']))).toBe(false);
  });
});
