import { pathScanProfile } from '../path-severity';
import { classifyMode, parseTree } from '../verified-head-tree';

const row = (mode: string, name: string): Buffer => Buffer.concat([Buffer.from(`${mode} ${name}\0`), Buffer.alloc(20, 1)]);

describe('parseTree', () => {
  it('spends its row budget while parsing and stops there, before the rows after it', () => {
    // Six good rows, then bytes that would be "malformed" if the parse got there.
    const bytes = Buffer.concat([...Array.from({ length: 6 }, (_, i) => row('100644', `f${i}`)), Buffer.from('garbage')]);
    expect(() => parseTree(bytes, 20, 't', { left: 5 })).toThrow(/too large to list/);
    expect(() => parseTree(bytes, 20, 't', { left: 100 })).toThrow(/malformed/);
  });

  it('shares one budget across trees', () => {
    const budget = { left: 3 };
    expect(parseTree(Buffer.concat([row('100644', 'a'), row('100644', 'b')]), 20, 't1', budget)).toHaveLength(2);
    expect(() => parseTree(Buffer.concat([row('100644', 'c'), row('100644', 'd')]), 20, 't2', budget)).toThrow(
      /too large to list/,
    );
  });
});

describe('classifyMode', () => {
  it('reads octal by file-type bits', () => {
    expect(classifyMode('0040000')).toBe('tree');
    expect(classifyMode('100664')).toBe('file');
    expect(classifyMode('0120000')).toBe('symlink');
    expect(classifyMode('0160000')).toBe('gitlink');
    for (const bad of ['', 'abc', '1', '170000', '010644', '10064x']) expect(classifyMode(bad)).toBeNull();
  });
});

describe('pathScanProfile', () => {
  it('is equal for paths that scan alike and differs where path-dependent rules differ', () => {
    expect(pathScanProfile('/r/a/x.txt', '/r')).toBe(pathScanProfile('/r/b/x.txt', '/r'));
    expect(pathScanProfile('/r/docs/x.txt', '/r')).not.toBe(pathScanProfile('/r/src/x.txt', '/r'));
    expect(pathScanProfile('/r/test/x.js', '/r')).not.toBe(pathScanProfile('/r/src/x.js', '/r'));
    expect(pathScanProfile('/r/a/x.py', '/r')).not.toBe(pathScanProfile('/r/a/x.txt', '/r'));
  });
});
