import { reportIncomplete, shortenMiddle } from '../commands/scan';
import type { UnreadableFile } from '../utils/scan-utils';

/** U9 of the 2026-10-17 design: the INCOMPLETE block is sorted and its first line names the first file. */
describe('reportIncomplete', () => {
  let lines: string[];
  beforeEach(() => {
    lines = [];
    jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      lines.push(a.map(String).join(' '));
    });
  });
  afterEach(() => jest.restoreAllMocks());

  it('three files completed in reverse order are printed sorted, and the first line names the first', () => {
    const entries: UnreadableFile[] = [
      { kind: 'too_large', file: 'c/three.json', reason: '33.0 MiB: over 32 MiB, not scanned' },
      { kind: 'read_error', file: 'b/two.txt', reason: 'EACCES' },
      { kind: 'scan_budget', file: 'a/one.ts', reason: 'scan exceeded the 5000 ms CPU budget twice' },
    ];
    reportIncomplete(entries, false, undefined);
    expect(lines[0]).toMatch(/INCOMPLETE: First: a\/one\.ts\. 1 file\(s\) or target\(s\) could not be read/);
    const order = ['a/one.ts', 'b/two.txt', 'c/three.json'].map(f => lines.findIndex(l => l.trim() === f));
    expect(order.every(i => i > 0)).toBe(true);
    expect([...order].sort((x, y) => x - y)).toEqual(order);
    // The caller's list is not reordered.
    expect(entries[0].file).toBe('c/three.json');
  });

  it('a 90-character path is shortened in the middle to 60 characters with ...', () => {
    const long = `${'d'.repeat(40)}/${'e'.repeat(44)}.json`;
    expect(long.length).toBe(90);
    const short = shortenMiddle(long);
    expect(short.length).toBe(60);
    expect(short).toContain('...');
    expect(short.startsWith('dddd')).toBe(true);
    expect(short.endsWith('e.json')).toBe(true);
    reportIncomplete([{ kind: 'too_large', file: long, reason: 'big' }], false, undefined);
    expect(lines[0]).toContain(`First: ${short}.`);
    expect(shortenMiddle('short/path.ts')).toBe('short/path.ts');
  });
});
