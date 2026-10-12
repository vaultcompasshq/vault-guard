import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { getFilesToScanAsync, newPlainFileSetInfo } from '@vaultcompass/vault-guard-core';
import { scanCommand } from '../../commands/scan';

/**
 * The plain-scan file set inside git (design 2026-10-11, section 2).
 *
 * Inside a git work tree a plain directory scan takes its files from git:
 * tracked files, whatever `.gitignore` says about them, plus untracked files
 * that are not ignored. Until 1.9.1 the plain scan walked the filesystem and
 * dropped anything `.gitignore` matched, so a committed `.env` was clean on
 * push and blocking in pull-request mode. Outside git the walk is unchanged.
 *
 * Each test names the test-plan row it implements and the mutation it kills.
 */

const FAKE_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

const itPosix = process.platform === 'win32' ? it.skip : it;
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

interface Captured {
  code: number;
  log: string;
  err: string;
  stdout: string;
}

async function capture(fn: () => Promise<number>): Promise<Captured> {
  const logs: string[] = [];
  const errs: string[] = [];
  const outs: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const origOut = process.stdout.write;
  const origErrW = process.stderr.write;
  console.log = (...a: unknown[]): boolean => {
    logs.push(a.map(String).join(' '));
    return true;
  };
  console.error = (...a: unknown[]): boolean => {
    errs.push(a.map(String).join(' '));
    return true;
  };
  process.stdout.write = ((s: string | Uint8Array): boolean => {
    outs.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((): boolean => true) as typeof process.stderr.write;
  let code: number;
  try {
    code = await fn();
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.stdout.write = origOut;
    process.stderr.write = origErrW;
  }
  return { code, log: logs.join('\n'), err: errs.join('\n'), stdout: outs.join('') };
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function initRepo(dir: string): void {
  git(dir, ['init', '-q', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.invalid']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
}

interface JsonDoc {
  run: Record<string, number | string | undefined>;
  results: Array<{ file: string; matches: Array<{ type: string; line: number }> }>;
}

function parse(stdout: string): JsonDoc {
  return JSON.parse(stdout) as JsonDoc;
}

function foundFiles(doc: JsonDoc): string[] {
  return doc.results.map(r => r.file).sort();
}

describe('plain scan inside git: tracked plus untracked-not-ignored', () => {
  const originalCwd = process.cwd();
  const originalPath = process.env.PATH;
  let dir: string;
  let outside: string;

  function write(rel: string, text: string, base = dir): void {
    const abs = path.join(base, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
  }

  function key(rel: string, base = dir): void {
    write(rel, `ANTHROPIC_API_KEY=${FAKE_KEY}\n`, base);
  }

  function commitAll(message: string, cwd = dir): void {
    git(cwd, ['add', '-A', '-f']);
    git(cwd, ['commit', '-q', '-m', message]);
  }

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-git-set-')));
    outside = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-git-set-out-')));
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    for (const locked of ['locked', path.join('src', 'locked')]) {
      try {
        fs.chmodSync(path.join(dir, locked), 0o755);
      } catch {
        /* not created in every case */
      }
    }
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });

  it('T1: a tracked, gitignored .env is scanned and counted', async () => {
    initRepo(dir);
    write('.gitignore', '.env\n');
    write('app.ts', 'export const a = 1;\n');
    key('.env');
    commitAll('base');

    const json = await capture(() => scanCommand('.', 'json', false));
    expect(json.code).toBe(1);
    const doc = parse(json.stdout);
    expect(foundFiles(doc)).toEqual(['.env']);
    expect(doc.run.file_set).toBe('git');
    expect(doc.run.tracked_ignored_files_scanned).toBe(1);

    const text = await capture(() => scanCommand('.', 'text', false));
    expect(text.code).toBe(1);
    expect(text.log).toContain('Tracked files that .gitignore would hide, scanned: 1');
  });

  describe('T2: untracked files', () => {
    it('T2a: an untracked, ignored file is not scanned', async () => {
      initRepo(dir);
      write('.gitignore', 'out/\n');
      write('app.ts', 'export const a = 1;\n');
      commitAll('base');
      key('out/app.js');
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect(parse(r.stdout).run.files_scanned).toBe(2);
    });

    it('T2b: an untracked file that is not ignored is scanned', async () => {
      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      commitAll('base');
      key('notes.txt');
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      expect(foundFiles(parse(r.stdout))).toEqual(['notes.txt']);
    });
  });

  it('T3: plain and --trust-base scan the same path set over one committed tree', async () => {
    initRepo(dir);
    write('app.ts', 'export const a = 1;\n');
    commitAll('base');
    git(dir, ['branch', 'base-snapshot']);
    key('src/vendor/k.js');
    write('.gitignore', 'secret.env\n');
    key('secret.env');
    write('lib/util.ts', 'export const u = 2;\n');
    commitAll('feature');

    const plain = await capture(() => scanCommand('.', 'json', false));
    const pr = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    const plainDoc = parse(plain.stdout);
    const prDoc = parse(pr.stdout);
    expect(plain.code).toBe(1);
    expect(pr.code).toBe(1);
    expect(foundFiles(plainDoc)).toEqual(['secret.env', 'src/vendor/k.js']);
    expect(foundFiles(prDoc)).toEqual(foundFiles(plainDoc));
    expect(plainDoc.run.files_scanned).toBe(prDoc.run.files_scanned);
    expect(prDoc.run.file_set).toBe('head-tree');
    expect(prDoc.run.tracked_ignored_files_scanned).toBe(1);
    expect(prDoc.run.tracked_nested_vendored_scanned).toBe(1);
  });

  it('T4: an untracked, unignored file under a nested node_modules is not scanned', async () => {
    initRepo(dir);
    write('app.ts', 'export const a = 1;\n');
    commitAll('base');
    key('pkg/node_modules/x.js');
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(0);
    expect(parse(r.stdout).run.files_scanned).toBe(1);
  });

  it('T6: a repository with no commits: a staged and an untracked key file are both found', async () => {
    initRepo(dir);
    key('staged.env');
    git(dir, ['add', 'staged.env']);
    key('untracked.env');
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    expect(foundFiles(parse(r.stdout))).toEqual(['staged.env', 'untracked.env']);
  });

  describe('T7: submodules and symlinks', () => {
    itPosix('T7a: a key inside a checked-out submodule is found', async () => {
      initRepo(outside);
      key('inner.env', outside);
      commitAll('sub', outside);

      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      commitAll('base');
      git(dir, ['-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', outside, 'libs/sub']);
      git(dir, ['commit', '-q', '-m', 'add submodule']);

      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      expect(foundFiles(parse(r.stdout))).toEqual(['libs/sub/inner.env']);
    });

    itPosix('T7b: a tracked symlink to a key file outside the repository is not followed', async () => {
      key('target.env', outside);
      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      fs.symlinkSync(path.join(outside, 'target.env'), path.join(dir, 'link.env'));
      commitAll('base');
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect(parse(r.stdout).run.files_scanned).toBe(1);
    });
  });

  describe('T8: nested repositories that are not submodules', () => {
    it('an untracked nested repository is scanned', async () => {
      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      commitAll('base');
      fs.mkdirSync(path.join(dir, 'nested'));
      initRepo(path.join(dir, 'nested'));
      key('nested/k.env');
      commitAll('nested', path.join(dir, 'nested'));
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      expect(foundFiles(parse(r.stdout))).toEqual(['nested/k.env']);
    });

    it('the same nested repository, gitignored by the outer one, is not scanned', async () => {
      initRepo(dir);
      write('.gitignore', 'nested/\n');
      write('app.ts', 'export const a = 1;\n');
      commitAll('base');
      fs.mkdirSync(path.join(dir, 'nested'));
      initRepo(path.join(dir, 'nested'));
      key('nested/k.env');
      commitAll('nested', path.join(dir, 'nested'));
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
    });
  });

  /**
   * Driven through the built CLI as a subprocess: jest gives the test its own
   * copy of process.env, so a PATH set in-process never reaches the git that
   * child_process starts. Needs a built dist, like exit-codes-usage.test.ts.
   */
  describe('T9: deciding "inside git" fails closed', () => {
    const cliEntry = path.join(__dirname, '..', '..', '..', 'dist', 'cli-entry.js');

    function runWithStubGit(args: string[]): { status: number | null; stdout: string; stderr: string } {
      const bin = path.join(outside, 'bin');
      fs.mkdirSync(bin, { recursive: true });
      const stub = path.join(bin, 'git');
      fs.writeFileSync(
        stub,
        '#!/bin/sh\n' +
          "echo \"fatal: detected dubious ownership in repository at '$PWD'\" >&2\n" +
          'exit 128\n',
      );
      fs.chmodSync(stub, 0o755);
      const r = spawnSync(process.execPath, [cliEntry, ...args], {
        cwd: dir,
        encoding: 'utf-8',
        env: { ...process.env, PATH: `${bin}${path.delimiter}${originalPath ?? ''}` },
      });
      return { status: r.status, stdout: r.stdout, stderr: r.stderr };
    }

    itPosix('T9a/b: a .git is present and git refuses: exit 2, git quoted', () => {
      fs.mkdirSync(path.join(dir, '.git'));
      key('tracked.env');
      const r = runWithStubGit(['scan', '.']);
      expect(r.status).toBe(2);
      expect(r.stderr).toContain('detected dubious ownership');
      expect(r.stdout).not.toMatch(/SUCCESS/);
    });

    itPosix('the same stub with no .git present: the walk runs and finds the key', () => {
      key('tracked.env');
      const r = runWithStubGit(['scan', '.', '--format', 'json']);
      expect(r.status).toBe(1);
      expect(parse(r.stdout).run.file_set).toBe('walk');
    });
  });

  describe('T18: tracked paths that cannot be examined', () => {
    it('T18b: a tracked file deleted in the work tree is counted, not fatal', async () => {
      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      write('gone.ts', 'export const g = 1;\n');
      commitAll('base');
      fs.rmSync(path.join(dir, 'gone.ts'));
      const json = await capture(() => scanCommand('.', 'json', false));
      expect(json.code).toBe(0);
      expect(parse(json.stdout).run.tracked_files_missing).toBe(1);
      const text = await capture(() => scanCommand('.', 'text', false));
      expect(text.code).toBe(0);
      expect(text.log).toContain('Tracked files missing from the working tree: 1');
    });

    it('T18b: a file left out by a sparse checkout is counted, not fatal', async () => {
      initRepo(dir);
      write('keep/app.ts', 'export const a = 1;\n');
      write('drop/b.ts', 'export const b = 1;\n');
      commitAll('base');
      git(dir, ['sparse-checkout', 'set', 'keep']);
      expect(fs.existsSync(path.join(dir, 'drop', 'b.ts'))).toBe(false);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect(parse(r.stdout).run.tracked_files_missing).toBe(1);
    });

    itPosix('T18a: a tracked file under a directory that cannot be entered exits 2', async () => {
      if (isRoot) return;
      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      write('locked/creds.txt', 'hello\n');
      commitAll('base');
      fs.chmodSync(path.join(dir, 'locked'), 0o000);
      const r = await capture(() => scanCommand('.', 'text', false));
      expect(r.code).toBe(2);
      expect(r.err).toContain('creds.txt');
    });

    itPosix('an untracked directory git cannot open is a warning, as the walk made it', async () => {
      if (isRoot) return;
      initRepo(dir);
      write('app.ts', 'export const a = 1;\n');
      commitAll('base');
      write('locked/notes.txt', 'hello\n');
      fs.chmodSync(path.join(dir, 'locked'), 0o000);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      const diags = (JSON.parse(r.stdout) as { diagnostics?: Array<{ code: string; ctx: { detail?: string } }> })
        .diagnostics ?? [];
      const denied = diags.filter(d => d.code === 'fs.permission_denied');
      expect(denied.length).toBeGreaterThan(0);
      expect(JSON.stringify(denied)).toContain('locked');
    });
  });

  describe('T19: a target is a literal path, never a pathspec', () => {
    it('brackets in a subdirectory target do not glob', async () => {
      initRepo(dir);
      key('sub/[x]/k.env');
      key('sub/x/other.env');
      commitAll('base');
      const r = await capture(() => scanCommand('sub/[x]', 'json', false));
      expect(r.code).toBe(1);
      const doc = parse(r.stdout);
      expect(foundFiles(doc)).toEqual([path.join('sub', '[x]', 'k.env')]);
      expect(doc.run.files_scanned).toBe(1);
    });

    itPosix('a leading colon in a target is not read as pathspec magic', async () => {
      initRepo(dir);
      key(':x/k.env');
      commitAll('base');
      const r = await capture(() => scanCommand(':x', 'json', false));
      expect(r.code).toBe(1);
      expect(foundFiles(parse(r.stdout))).toEqual([path.join(':x', 'k.env')]);
    });
  });

  it('T22: nested vendored tracked files are scanned and counted; a root vendor/ is skipped and said', async () => {
    initRepo(dir);
    key('app/build/k.js');
    key('src/vendor/k.js');
    key('vendor/k.js');
    commitAll('base');

    const json = await capture(() => scanCommand('.', 'json', false));
    const doc = parse(json.stdout);
    expect(json.code).toBe(1);
    expect(foundFiles(doc)).toEqual(['app/build/k.js', 'src/vendor/k.js']);
    expect(doc.run.tracked_nested_vendored_scanned).toBe(2);
    expect(doc.run.vendored_dirs_skipped).toBe(1);

    const text = await capture(() => scanCommand('.', 'text', false));
    expect(text.log).toContain('Vendored directories skipped: 1 (vendor)');
    expect(text.log).toContain('Tracked files under nested vendored directories, scanned: 2');
  });

  describe('T23', () => {
    it('T23a: a conflicted tracked key file is scanned once and reported once', async () => {
      initRepo(dir);
      write('k.env', 'A=1\n');
      commitAll('base');
      git(dir, ['checkout', '-q', '-b', 'other']);
      write('k.env', `B=2\nANTHROPIC_API_KEY=${FAKE_KEY}\n`);
      commitAll('other');
      git(dir, ['checkout', '-q', 'main']);
      write('k.env', `C=3\nANTHROPIC_API_KEY=${FAKE_KEY}\n`);
      commitAll('main');
      try {
        git(dir, ['merge', '-q', 'other']);
      } catch {
        /* the conflict is the point */
      }
      expect(git(dir, ['ls-files', '-u']).trim().split('\n').length).toBe(3);
      const r = await capture(() => scanCommand('.', 'json', false));
      const doc = parse(r.stdout);
      expect(doc.run.files_scanned).toBe(1);
      expect(doc.results).toHaveLength(1);
      expect(doc.results[0].matches.length).toBeGreaterThanOrEqual(1);
      const lines = doc.results[0].matches.map(m => m.line);
      expect(new Set(lines).size).toBe(lines.length);
    });

    itPosix('T23b: a target reached through a symlinked parent has the same file set', async () => {
      initRepo(dir);
      key('a/k.env');
      write('a/b.ts', 'export const b = 1;\n');
      commitAll('base');
      const link = path.join(outside, 'link');
      fs.symlinkSync(dir, link);

      const viaPhysical = await getFilesToScanAsync(dir, false, undefined, [], undefined, newPlainFileSetInfo());
      const info = newPlainFileSetInfo();
      const viaLink = await getFilesToScanAsync(link, false, undefined, [], undefined, info);
      const rel = (root: string, files: string[]): string[] =>
        files.map(f => path.relative(root, f)).sort();
      expect(info.fileSet).toBe('git');
      expect(rel(link, viaLink)).toEqual(rel(dir, viaPhysical));
      expect(rel(link, viaLink)).toEqual([path.join('a', 'b.ts'), path.join('a', 'k.env')]);
    });
  });
});
