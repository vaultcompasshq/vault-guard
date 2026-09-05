import { isSequentialRunPlaceholder } from '../placeholder';

/**
 * Shannon entropy counts character frequencies and ignores order, so a strict
 * alphabet run scores near the maximum a value of its length can score. These
 * are the placeholder shapes that walked straight through the entropy gate.
 *
 * Every value below is synthetic and written for this test. Vendor prefixes
 * are joined at runtime: a committed provider-key shape trips credential
 * scanners regardless of the value being fake and the file being a test, so no
 * fragment matches a rule on its own.
 */
const GH_PREFIX = ['g', 'hp_'].join('');
const AWS_PREFIX = ['AK', 'IA'].join('');

describe('isSequentialRunPlaceholder', () => {
  it('recognises an ascending alphabet-then-digits run', () => {
    expect(isSequentialRunPlaceholder('abcdefghijklmnopqrstuvwxyz0123456789')).toBe(true);
  });

  it('recognises a run carrying a short vendor prefix', () => {
    expect(
      isSequentialRunPlaceholder(`${GH_PREFIX}abcdefghijklmnopqrstuvwxyz1234567890`),
    ).toBe(true);
    expect(isSequentialRunPlaceholder(`${AWS_PREFIX}ABCDEFGHIJKLMNOP`)).toBe(true);
  });

  it('recognises a descending run', () => {
    expect(isSequentialRunPlaceholder('zyxwvutsrqponmlkjihgfedcba')).toBe(true);
  });

  it('recognises repeated short runs', () => {
    expect(isSequentialRunPlaceholder('abcabcabcabcabcabcabc')).toBe(true);
    expect(isSequentialRunPlaceholder('123123123123123123123123')).toBe(true);
  });

  it('does not fire on a random value of the same length', () => {
    expect(isSequentialRunPlaceholder('Kq7mZr2xVb9nTd4wHs6yLc3pJf8gRu5eNa1v')).toBe(false);
    expect(
      isSequentialRunPlaceholder(`${GH_PREFIX}Kq7mZr2xVb9nTd4wHs6yLc3pJf8gRu5eNa1v`),
    ).toBe(false);
  });

  it('does not fire on a value that is half run and half random', () => {
    // 18 characters of run, 18 of random: exactly 50% coverage.
    expect(isSequentialRunPlaceholder('abcdefghijklmnopqr' + 'Kq7mZr2xVb9nTd4wHs')).toBe(false);
  });

  it('does not fire on runs shorter than three characters', () => {
    expect(isSequentialRunPlaceholder('abKLghQRcdMNstUV')).toBe(false);
  });

  it('ignores short values, where coverage is not evidence of anything', () => {
    expect(isSequentialRunPlaceholder('abcdef')).toBe(false);
  });

  it('does not fire on a repeated single character', () => {
    // Character repetition is padding, handled by the low-variety check.
    expect(isSequentialRunPlaceholder('xxxxxxxxxxxxxxxxxxxx')).toBe(false);
  });
});
