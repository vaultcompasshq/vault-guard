import path from 'path';

import { climbsOut } from '../utils/dot-dot';

describe('climbsOut', () => {
  it('is true only for the .. segment, never for a name that starts with two dots', () => {
    for (const rel of ['..', '../x', '../../a/b']) expect([rel, climbsOut(rel)]).toEqual([rel, true]);
    for (const rel of ['..env', '..cfg/creds.txt', '...', '.', '', 'a/../b', 'x..']) {
      expect([rel, climbsOut(rel)]).toEqual([rel, false]);
    }
  });

  it('accepts both separators for a Windows-style path, only the slash otherwise', () => {
    expect(climbsOut('..\\x', path.win32)).toBe(true);
    expect(climbsOut('../x', path.win32)).toBe(true);
    expect(climbsOut('..\\x', path.posix)).toBe(false);
    expect(climbsOut('..env\\x', path.win32)).toBe(false);
  });
});
