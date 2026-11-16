import * as path from 'path';

import { scanCommand } from '../../commands/scan';
import { AWS_KEY, capture, commitAll, git, initRepo, parse, tmpDir, write } from './git-fixture';

/**
 * A path whose first segment merely BEGINS with two dots (`..env`,
 * `..cfg/creds.txt`) is inside the repository. Every "is this outside?" check
 * used to be `rel.startsWith('..')`, which matched it, so such a file was
 * dropped without a word in every mode and a committed key in it was never
 * scanned: the run scanned only the clean file and exited 0.
 */

const originalCwd = process.cwd();

function fixture(): string {
  const dir = tmpDir('vg-dotdot-');
  initRepo(dir);
  write(dir, '..env', `aws = "${AWS_KEY}"\n`);
  write(dir, '..cfg/creds.txt', `aws = "${AWS_KEY}"\n`);
  write(dir, 'r.txt', 'clean\n');
  commitAll(dir, 'base');
  return dir;
}

async function scanAt(
  dir: string,
  target: string,
  opts: { staged?: boolean; trustBase?: string } = {},
): Promise<{ code: number; stdout: string; err: string }> {
  process.chdir(dir);
  try {
    return await capture(() => scanCommand(target, 'json', opts.staged ?? false, undefined, opts.trustBase));
  } finally {
    process.chdir(originalCwd);
  }
}

function found(stdout: string): string[] {
  return parse(stdout)
    .results.map(r => r.file)
    .sort();
}

afterEach(() => process.chdir(originalCwd));

describe('paths whose first segment starts with two dots are inside the repository', () => {
  it('plain scan: ..env and ..cfg/creds.txt are scanned', async () => {
    const dir = fixture();
    const r = await scanAt(dir, '.');
    expect(r.code).toBe(1);
    expect(found(r.stdout)).toEqual(['..cfg/creds.txt', '..env']);
    expect(parse(r.stdout).run.files_scanned).toBe(3);
  });

  it('--trust-base: ..env and ..cfg/creds.txt in the head tree are scanned', async () => {
    const dir = fixture();
    git(dir, ['checkout', '-q', '-b', 'pr']);
    write(dir, 'r.txt', 'clean, edited\n');
    commitAll(dir, 'pr');
    const r = await scanAt(dir, '.', { trustBase: 'main' });
    expect(r.code).toBe(1);
    expect(found(r.stdout)).toEqual(['..cfg/creds.txt', '..env']);
    expect(parse(r.stdout).run.files_scanned).toBe(3);
  });

  it('--trust-base: a target named ..env is not refused as outside the repository', async () => {
    const dir = fixture();
    git(dir, ['checkout', '-q', '-b', 'pr']);
    write(dir, 'r.txt', 'clean, edited\n');
    commitAll(dir, 'pr');
    const r = await scanAt(dir, '..env', { trustBase: 'main' });
    expect(r.err).not.toContain('is outside');
    expect(r.code).toBe(1);
    expect(found(r.stdout)).toEqual(['..env']);
  });

  it('--staged: staged ..env and ..cfg/creds.txt are scanned', async () => {
    const dir = tmpDir('vg-dotdot-staged-');
    initRepo(dir);
    write(dir, 'r.txt', 'clean\n');
    commitAll(dir, 'base');
    write(dir, '..env', `aws = "${AWS_KEY}"\n`);
    write(dir, '..cfg/creds.txt', `aws = "${AWS_KEY}"\n`);
    git(dir, ['add', '..env', path.join('..cfg', 'creds.txt')]);
    const r = await scanAt(dir, '.', { staged: true });
    expect(r.code).toBe(1);
    expect(found(r.stdout)).toEqual(['..cfg/creds.txt', '..env']);
  });

  it('a target named ..cfg is scanned as a directory inside the repository', async () => {
    const dir = fixture();
    const r = await scanAt(dir, '..cfg');
    expect(r.code).toBe(1);
    expect(found(r.stdout)).toEqual(['..cfg/creds.txt']);
  });
});
