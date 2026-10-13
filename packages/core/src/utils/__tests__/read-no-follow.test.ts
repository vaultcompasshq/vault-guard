import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { readRegularFileNoFollow, writeFileAtomically } from '../read-no-follow';

/**
 * Control files on disk are never read or written through a link (design
 * 2026-10-12, section 4.1 and 4.3).
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

describe('readRegularFileNoFollow', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-nofollow-')));
  });

  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('U15: a regular file is read, a missing one is absent', () => {
    fs.writeFileSync(path.join(dir, 'a.json'), '{"x":1}');
    expect(readRegularFileNoFollow(path.join(dir, 'a.json'))).toEqual({ kind: 'file', text: '{"x":1}' });
    expect(readRegularFileNoFollow(path.join(dir, 'nope.json'))).toEqual({ kind: 'absent' });
  });

  itPosix('U15: a symlink to a file, to a directory, or to nowhere is refused as a symlink', () => {
    fs.writeFileSync(path.join(dir, 'target.json'), '{"x":1}');
    fs.mkdirSync(path.join(dir, 'sub'));
    fs.symlinkSync('target.json', path.join(dir, 'to-file'));
    fs.symlinkSync('sub', path.join(dir, 'to-dir'));
    fs.symlinkSync('missing.json', path.join(dir, 'dangling'));
    for (const name of ['to-file', 'to-dir', 'dangling']) {
      expect({ name, r: readRegularFileNoFollow(path.join(dir, name)) }).toEqual({
        name,
        r: { kind: 'refused', what: 'symlink' },
      });
    }
  });

  itPosix('U15: a directory or a FIFO is refused as not a file, without blocking', () => {
    fs.mkdirSync(path.join(dir, 'd'));
    execFileSync('mkfifo', [path.join(dir, 'fifo')]);
    expect(readRegularFileNoFollow(path.join(dir, 'd'))).toEqual({ kind: 'refused', what: 'not-a-file' });
    expect(readRegularFileNoFollow(path.join(dir, 'fifo'))).toEqual({ kind: 'refused', what: 'not-a-file' });
  });

  itPosix('U15: a symlink fails at open, not at a separate lstat', () => {
    fs.writeFileSync(path.join(dir, 'target.json'), '{"x":1}');
    fs.symlinkSync('target.json', path.join(dir, 'link'));
    const open = jest.spyOn(fs, 'openSync');
    const lstat = jest.spyOn(fs, 'lstatSync');
    expect(readRegularFileNoFollow(path.join(dir, 'link'))).toEqual({ kind: 'refused', what: 'symlink' });
    expect(open).toHaveBeenCalledTimes(1);
    const flags = open.mock.calls[0][1] as number;
    expect(flags & fs.constants.O_NOFOLLOW).toBe(fs.constants.O_NOFOLLOW);
    expect(lstat).not.toHaveBeenCalled();
  });
});

describe('writeFileAtomically', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-atomic-')));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  itPosix('replaces a link planted before the rename instead of writing through it', () => {
    const victim = path.join(dir, 'victim.txt');
    fs.writeFileSync(victim, 'untouched\n');
    const out = path.join(dir, 'out.json');
    writeFileAtomically(out, '{"new":true}\n', 0o644, {
      beforeRename: () => fs.symlinkSync(victim, out),
    });
    expect(fs.readFileSync(victim, 'utf-8')).toBe('untouched\n');
    expect(fs.lstatSync(out).isFile()).toBe(true);
    expect(fs.readFileSync(out, 'utf-8')).toBe('{"new":true}\n');
    expect(fs.readdirSync(dir).filter(f => f.endsWith('.tmp'))).toEqual([]);
  });

  itPosix('keeps the requested file mode', () => {
    const out = path.join(dir, 'hook');
    writeFileAtomically(out, '#!/bin/sh\n', 0o755);
    expect(fs.statSync(out).mode & 0o777).toBe(0o755);
  });
});
