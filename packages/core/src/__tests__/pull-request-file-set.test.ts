import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  getPullRequestFilesToScan,
  listHeadTreeFiles,
  type PullRequestSkips,
} from '../index';

/** Symlink creation and POSIX mode bits; the Windows job is not a required check. */
const itPosix = process.platform === 'win32' ? it.skip : it;

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function write(root: string, rel: string, text: string): void {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, text);
}

describe('getPullRequestFilesToScan', () => {
  let root: string;

  beforeEach(() => {
    // `.native`: every expectation below is an absolute path built from this
    // root, and on Windows `os.tmpdir()` comes back in 8.3 short form, which
    // plain realpathSync keeps and git does not use.
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pr-fileset-')));
    git(root, ['init', '-q', '-b', 'main']);
    git(root, ['config', 'user.email', 'test@example.invalid']);
    git(root, ['config', 'user.name', 'test']);
    git(root, ['config', 'commit.gpgsign', 'false']);
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  function commitAll(): void {
    git(root, ['add', '-A', '-f']);
    git(root, ['commit', '-q', '-m', 'x']);
  }

  function noSkips(): PullRequestSkips {
    return { dirCount: 0, dirNames: [], typeFilteredFiles: 0 };
  }

  function fileSet(skipped: PullRequestSkips = noSkips(), ignorePatterns: string[] = []) {
    return getPullRequestFilesToScan(root, listHeadTreeFiles(root), ignorePatterns, skipped);
  }

  it('keeps a tracked file that a descendant .gitignore covers', () => {
    write(root, 'src/leak.ts', 'export const a = 1;\n');
    write(root, 'src/.gitignore', 'leak.ts\n');
    commitAll();
    expect(fileSet()).toContain(path.join(root, 'src', 'leak.ts'));
  });

  it('leaves an untracked file out of the set', () => {
    write(root, 'src/tracked.ts', 'export const a = 1;\n');
    commitAll();
    write(root, 'src/untracked.ts', 'export const b = 2;\n');
    expect(fileSet()).not.toContain(path.join(root, 'src', 'untracked.ts'));
  });

  it('scans a committed src/vendor because the skip list is anchored to the scan root', () => {
    write(root, 'src/vendor/leak.ts', 'export const a = 1;\n');
    commitAll();
    expect(fileSet()).toContain(path.join(root, 'src', 'vendor', 'leak.ts'));
  });

  it('keeps a file the index no longer carries but HEAD still does', () => {
    write(root, 'src/leak.ts', 'export const a = 1;\n');
    commitAll();
    // `git rm --cached` drops the path from the index and leaves it on disk and
    // in HEAD. A file set read from the index alone loses it, which is a mute
    // that costs one command and leaves the file exactly where it was.
    git(root, ['rm', '--cached', '-q', 'src/leak.ts']);
    expect(fileSet()).toContain(path.join(root, 'src', 'leak.ts'));
  });

  it('leaves a staged but uncommitted file out of the set', () => {
    write(root, 'src/app.ts', 'export const a = 1;\n');
    commitAll();
    write(root, 'src/staged.ts', 'export const b = 2;\n');
    git(root, ['add', 'src/staged.ts']);
    // The head TREE is the thing under judgment and a staged file is not in
    // it. Reading the index instead would make the set depend on local state
    // that the ref being judged says nothing about; `scan --staged` is the
    // command that reads the index, and it is a different gate.
    expect(fileSet()).not.toContain(path.join(root, 'src', 'staged.ts'));
    expect(fileSet()).toContain(path.join(root, 'src', 'app.ts'));
  });

  it('counts the tracked files dropped by the type and name filters', () => {
    write(root, 'src/leak.min.js', 'var a=1;\n');
    write(root, 'src/leak.lock', 'a\n');
    write(root, 'pnpm-lock.yaml', 'lockfileVersion: 9\n');
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const skipped = noSkips();
    const files = fileSet(skipped);
    expect(files).toEqual([path.join(root, 'src', 'app.ts')]);
    expect(skipped.typeFilteredFiles).toBe(3);
  });

  it('leaves the type filter count at zero when nothing was dropped', () => {
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const skipped = noSkips();
    fileSet(skipped);
    expect(skipped.typeFilteredFiles).toBe(0);
  });

  it('still skips a vendored directory at the scan root and counts it', () => {
    write(root, 'vendor/thing.ts', 'export const a = 1;\n');
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const skipped = noSkips();
    const files = fileSet(skipped);
    expect(files).not.toContain(path.join(root, 'vendor', 'thing.ts'));
    expect(files).toContain(path.join(root, 'src', 'app.ts'));
    expect(skipped.dirCount).toBe(1);
    expect(skipped.dirNames).toEqual(['vendor']);
  });

  it('honours ignore patterns from the base config', () => {
    write(root, 'fixtures/planted.ts', 'export const a = 1;\n');
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const files = fileSet(noSkips(), ['fixtures/**']);
    expect(files).not.toContain(path.join(root, 'fixtures', 'planted.ts'));
    expect(files).toContain(path.join(root, 'src', 'app.ts'));
  });

  itPosix('does not scan a tracked symlink', () => {
    write(root, 'src/real.ts', 'export const a = 1;\n');
    fs.symlinkSync('real.ts', path.join(root, 'src', 'link.ts'));
    commitAll();
    const files = fileSet();
    expect(files).toContain(path.join(root, 'src', 'real.ts'));
    expect(files).not.toContain(path.join(root, 'src', 'link.ts'));
  });

  it('drops a generated artifact the walk would also have dropped', () => {
    write(root, 'src/app.min.js', 'var a=1;\n');
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const files = fileSet();
    expect(files).not.toContain(path.join(root, 'src', 'app.min.js'));
    expect(files).toContain(path.join(root, 'src', 'app.ts'));
  });
});
