import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import * as fx from './git-fixture';

/**
 * Plain-scan git calls run with a clean git environment; `--staged` keeps the
 * inherited one (design 2026-10-12, section 6). Every case is a subprocess,
 * because a real hook or a GIT_DIR-only repository needs one.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

/** A pre-commit hook that runs the built CLI and records its exit code. */
function installHook(repo: string, cliArgs: string[], cwd: string, out: string): void {
  const quoted = cliArgs.map(a => `'${a}'`).join(' ');
  const script = [
    '#!/bin/sh',
    `cd '${cwd}' || exit 99`,
    `'${process.execPath}' '${fx.CLI_ENTRY}' ${quoted} > '${out}.log' 2>&1`,
    `echo $? > '${out}.code'`,
    'exit 0',
    '',
  ].join('\n');
  const hook = path.join(repo, '.git', 'hooks', 'pre-commit');
  fs.writeFileSync(hook, script, { mode: 0o755 });
}

function hookResult(out: string): { code: number; log: string } {
  return {
    code: Number.parseInt(fs.readFileSync(`${out}.code`, 'utf-8').trim(), 10),
    log: fs.readFileSync(`${out}.log`, 'utf-8'),
  };
}

describe('hook environment', () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function fresh(prefix: string): string {
    const d = fx.tmpDir(prefix);
    dirs.push(d);
    return d;
  }

  itPosix("F16: a plain scan from a pre-commit hook reads a submodule's own index", () => {
    const sub = fresh('vg-hook-sub-');
    fx.initRepo(sub);
    fx.write(sub, 'lib/key.ts', `export const k = "${fx.AWS_KEY}";\n`);
    fx.commitAll(sub, 'sub');
    const sup = fresh('vg-hook-sup-');
    fx.initRepo(sup);
    fx.write(sup, 'app.ts', 'export const a = 1;\n');
    fx.commitAll(sup, 'base');
    fx.git(sup, ['-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', sub, 'sub']);
    fx.commitAll(sup, 'submodule');
    const out = path.join(fresh('vg-hook-out-'), 'r');
    installHook(sup, ['scan', '.'], sup, out);
    fx.write(sup, 'notes.md', 'unrelated\n');
    fx.git(sup, ['add', 'notes.md']);
    fx.git(sup, ['commit', '-q', '-m', 'unrelated']);
    const r = hookResult(out);
    expect(r.log).not.toContain('index file open failed');
    expect(r.code).toBe(1);
    expect(r.log).toContain('sub/lib/key.ts');
  });

  itPosix('F17: a hook in one repository that scans another lists the other repository through its own index', () => {
    const b = fresh('vg-hook-b-');
    fx.initRepo(b);
    fx.write(b, '.gitignore', '.env\n');
    fx.write(b, 'app.ts', 'export const a = 1;\n');
    fx.write(b, '.env', `AWS_ACCESS_KEY_ID=${fx.AWS_KEY}\n`);
    fx.commitAll(b, 'b');
    const a = fresh('vg-hook-a-');
    fx.initRepo(a);
    fx.write(a, 'main.ts', 'export const m = 1;\n');
    fx.commitAll(a, 'a');
    const out = path.join(fresh('vg-hook-out-'), 'r');
    installHook(a, ['scan', '.'], b, out);
    fx.write(a, 'main.ts', 'export const m = 2;\n');
    fx.git(a, ['commit', '-q', '-a', '-m', 'edit']);
    const r = hookResult(out);
    expect(r.code).toBe(1);
    expect(r.log).toContain('.env');
    expect(r.log).not.toContain('Tracked files missing');
  });

  itPosix("U17: --staged in a commit -a hook still reads the hook's index", () => {
    const repo = fresh('vg-hook-staged-');
    fx.initRepo(repo);
    fx.write(repo, 'app.ts', 'export const a = 1;\n');
    fx.commitAll(repo, 'base');
    const out = path.join(fresh('vg-hook-out-'), 'r');
    installHook(repo, ['scan', '--staged'], repo, out);
    fx.write(repo, 'app.ts', `export const k = "${fx.AWS_KEY}";\n`);
    fx.git(repo, ['commit', '-q', '-a', '-m', 'edit']);
    expect(hookResult(out).code).toBe(1);
  });

  itPosix("U14 (design 2026-10-17): --staged head reads in a commit -a hook use the hook's index", () => {
    const repo = fresh('vg-hook-head-');
    fx.initRepo(repo);
    fx.write(repo, 'app.ts', 'export const a = 1;\n');
    fx.write(repo, 'img/logo.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]));
    fx.commitAll(repo, 'base');
    const outDir = fresh('vg-hook-head-out-');
    const log = path.join(outDir, 'git.log');
    const bin = fx.gitStub(outDir, log);
    const out = path.join(outDir, 'r');
    const script = [
      '#!/bin/sh',
      `cd '${repo}' || exit 99`,
      `PATH='${bin}':"$PATH" '${process.execPath}' '${fx.CLI_ENTRY}' scan --staged --format json > '${out}.json' 2> '${out}.err'`,
      `echo $? > '${out}.code'`,
      'exit 0',
      '',
    ].join('\n');
    fs.writeFileSync(path.join(repo, '.git', 'hooks', 'pre-commit'), script, { mode: 0o755 });
    // A staged real .woff2, and -a stages logo.png replaced with text holding a key:
    // that content exists only in the temporary index GIT_INDEX_FILE names.
    fx.write(repo, 'fonts/a.woff2', Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]));
    fx.git(repo, ['add', 'fonts/a.woff2']);
    fx.write(repo, 'img/logo.png', `aws_access_key_id = ${fx.AWS_KEY}\n`);
    fx.git(repo, ['commit', '-q', '-a', '-m', 'edit']);
    expect(Number.parseInt(fs.readFileSync(`${out}.code`, 'utf-8').trim(), 10)).toBe(1);
    const doc = JSON.parse(fs.readFileSync(`${out}.json`, 'utf-8')) as {
      run: { binary_files_skipped: number; binary_files_skipped_by_family: Record<string, number>; binary_type_mismatch: unknown };
      results: Array<{ file: string }>;
    };
    expect(doc.results.map(r => r.file)).toEqual(['img/logo.png']);
    expect(doc.run.binary_files_skipped_by_family.font).toBe(1);
    expect(doc.run.binary_type_mismatch).toEqual([{ file: 'img/logo.png', family: 'image' }]);
    const batches = fx
      .stubCalls(log)
      .filter(c => fx.subcommand(c.args) === 'cat-file' && c.args.includes('--batch'));
    expect(batches).toHaveLength(1);
    expect(batches[0].indexFile).not.toBeNull();
  });

  /** A bare repository whose work tree has no .git entry: the dotfiles layout. */
  function dotfiles(): { env: NodeJS.ProcessEnv; work: string; gitDir: string } {
    const root = fresh('vg-dotfiles-');
    const gitDir = path.join(root, 'repo.git');
    const work = path.join(root, 'home');
    fs.mkdirSync(work);
    fx.git(root, ['init', '-q', '--bare', '-b', 'main', gitDir]);
    const env = { ...process.env, GIT_DIR: gitDir, GIT_WORK_TREE: work };
    fx.git(work, ['config', 'user.email', 'test@example.invalid'], env);
    fx.git(work, ['config', 'user.name', 'Test'], env);
    fx.git(work, ['config', 'commit.gpgsign', 'false'], env);
    return { env, work, gitDir };
  }

  itPosix('U20: --staged in a GIT_DIR-only repository reads blobs through GIT_DIR', () => {
    const { env, work } = dotfiles();
    fx.write(work, '.profile', 'export A=1\n');
    fx.git(work, ['add', '.profile'], env);
    fx.git(work, ['commit', '-q', '-m', 'base'], env);
    fx.write(work, '.aws_env', `AWS_ACCESS_KEY_ID=${fx.AWS_KEY}\n`);
    fx.git(work, ['add', '.aws_env'], env);
    const log = path.join(fresh('vg-dotfiles-log-'), 'git.log');
    const bin = fx.gitStub(path.dirname(log), log);
    const r = fx.runCli(['scan', '--staged'], work, { ...env, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` });
    expect(r.code).toBe(1);
    const catFile = fx.stubCalls(log).filter(c => fx.subcommand(c.args) === 'cat-file');
    expect(catFile.length).toBeGreaterThan(0);
    expect(catFile.every(c => c.gitDir !== null)).toBe(true);
  });

  itPosix('U22: a pull-request run that finds its repository only through GIT_DIR is exit 2', () => {
    const { env, work } = dotfiles();
    fx.write(work, '.profile', 'export A=1\n');
    fx.git(work, ['add', '.profile'], env);
    fx.git(work, ['commit', '-q', '-m', 'base'], env);
    fx.git(work, ['branch', 'base'], env);
    fx.write(work, '.aws_env', `AWS_ACCESS_KEY_ID=${fx.AWS_KEY}\n`);
    fx.git(work, ['add', '.aws_env'], env);
    fx.git(work, ['commit', '-q', '-m', 'head'], env);
    const r = fx.runCli(['scan', '.', '--trust-base', 'base'], work, env);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('not inside a git worktree');
  });

  itPosix('U1: the root lookups and file-set calls of a plain scan run without the hook index', () => {
    const repo = fresh('vg-hook-roots-');
    fx.initRepo(repo);
    fx.write(repo, 'app.ts', `export const k = "${fx.AWS_KEY}";\n`);
    fx.commitAll(repo, 'base');
    const log = path.join(fresh('vg-hook-log-'), 'git.log');
    const bin = fx.gitStub(path.dirname(log), log);
    const r = fx.runCli(['scan', '.'], repo, {
      ...process.env,
      GIT_INDEX_FILE: path.join(repo, '.git', 'index'),
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
    });
    expect(r.code).toBe(1);
    const calls = fx.stubCalls(log);
    expect(calls.length).toBeGreaterThan(5);
    const roots = calls.filter(c => fx.subcommand(c.args) === 'rev-parse');
    expect(roots.length).toBe(3);
    expect(calls.filter(c => c.indexFile !== null)).toEqual([]);
  });
});

// Not every git version accepts every argument used above; fail loudly if the
// environment cannot run a hook at all.
beforeAll(() => {
  expect(spawnSync('git', ['--version']).status).toBe(0);
});
