import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { getPullRequestFilesToScan, listTrackedFiles } from '../index';

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
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pr-fileset-')));
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

  function fileSet(skipped = { count: 0, names: [] as string[] }, ignorePatterns: string[] = []) {
    return getPullRequestFilesToScan(root, listTrackedFiles(root), ignorePatterns, skipped);
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

  it('still skips a vendored directory at the scan root and counts it', () => {
    write(root, 'vendor/thing.ts', 'export const a = 1;\n');
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const skipped = { count: 0, names: [] as string[] };
    const files = fileSet(skipped);
    expect(files).not.toContain(path.join(root, 'vendor', 'thing.ts'));
    expect(files).toContain(path.join(root, 'src', 'app.ts'));
    expect(skipped.count).toBe(1);
    expect(skipped.names).toEqual(['vendor']);
  });

  it('honours ignore patterns from the base config', () => {
    write(root, 'fixtures/planted.ts', 'export const a = 1;\n');
    write(root, 'src/app.ts', 'export const b = 2;\n');
    commitAll();
    const files = fileSet({ count: 0, names: [] }, ['fixtures/**']);
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
