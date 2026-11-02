import * as fs from 'fs';
import * as path from 'path';

import * as fx from './git-fixture';

/**
 * `vault-guard install-hook` exits 1 on every refusal the command can reach,
 * and 0 when the install succeeds. A Commander usage error stays 2.
 * Driven through the built CLI.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

describe('install-hook exit codes', () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) {
      try {
        fs.chmodSync(d, 0o755);
      } catch {
        // The directory may already be writable, or already removed.
      }
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  function freshRepo(): { repo: string; hooks: string } {
    const repo = fx.tmpDir('vg-hook-exit-');
    dirs.push(repo);
    fx.initRepo(repo);
    const hooks = path.join(repo, '.git', 'hooks');
    // Pin the hooks directory so a global core.hooksPath cannot redirect the run.
    fx.git(repo, ['config', '--local', 'core.hooksPath', hooks]);
    return { repo, hooks };
  }

  function combined(r: { stdout: string; stderr: string }): string {
    return `${r.stdout}${r.stderr}`;
  }

  function linkOutside(repo: string, rel: string, text: string): string {
    const outside = fx.tmpDir('vg-hook-exit-out-');
    dirs.push(outside);
    const target = path.join(outside, 'target');
    fs.writeFileSync(target, text);
    const link = path.join(repo, rel);
    fs.mkdirSync(path.dirname(link), { recursive: true });
    fs.symlinkSync(target, link);
    return target;
  }

  it('exits 1 when run from a subdirectory, and does not write a hook', () => {
    const { repo, hooks } = freshRepo();
    const sub = path.join(repo, 'packages', 'app');
    fs.mkdirSync(sub, { recursive: true });

    const r = fx.runCli(['install-hook'], sub);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/Not a git repository/);
    expect(fs.existsSync(path.join(hooks, 'pre-commit'))).toBe(false);
  });

  it('exits 1 for an unknown manager', () => {
    const { repo } = freshRepo();

    const r = fx.runCli(['install-hook', '--manager', 'nope'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/Unknown manager: nope/);
    expect(fs.existsSync(path.join(repo, '.git', 'hooks', 'pre-commit'))).toBe(false);
  });

  it('exits 2 for a usage error', () => {
    const { repo } = freshRepo();

    const r = fx.runCli(['install-hook', '--bogus'], repo);

    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/unknown option/i);
  });

  it('exits 1 when the native hook is not a shell script, and leaves the file unchanged', () => {
    const { repo, hooks } = freshRepo();
    const hook = path.join(hooks, 'pre-commit');
    const text = '#!/usr/bin/env python3\nprint("py hook")\n';
    fs.writeFileSync(hook, text, { mode: 0o755 });

    const r = fx.runCli(['install-hook'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/not a shell script/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(text);
    expect(fs.existsSync(path.join(hooks, 'pre-commit.cmd'))).toBe(false);
  });

  it('exits 1 when the native hooks path is a file, and leaves that file in place', () => {
    const { repo, hooks } = freshRepo();
    fs.rmSync(hooks, { recursive: true, force: true });
    fs.writeFileSync(hooks, 'not a directory\n');

    const r = fx.runCli(['install-hook'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/Failed to install hook/);
    expect(fs.readFileSync(hooks, 'utf-8')).toBe('not a directory\n');
  });

  it('exits 1 when .husky is a file, and leaves that file in place', () => {
    const { repo } = freshRepo();
    const husky = path.join(repo, '.husky');
    fs.writeFileSync(husky, 'not a directory\n');

    const r = fx.runCli(['install-hook', '--manager', 'husky'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/Failed to install Husky hook/);
    expect(fs.readFileSync(husky, 'utf-8')).toBe('not a directory\n');
  });

  it('exits 1 when lefthook-local.yml already exists without vault-guard, and leaves it unchanged', () => {
    const { repo } = freshRepo();
    const file = path.join(repo, 'lefthook-local.yml');
    const text = 'pre-commit:\n  commands:\n    lint:\n      run: echo hi\n';
    fs.writeFileSync(file, text);

    const r = fx.runCli(['install-hook', '--manager', 'lefthook'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/lefthook-local\.yml already exists/);
    expect(fs.readFileSync(file, 'utf-8')).toBe(text);
  });

  it('exits 1 when .pre-commit-config.yaml already exists without vault-guard, and leaves it unchanged', () => {
    const { repo } = freshRepo();
    const file = path.join(repo, '.pre-commit-config.yaml');
    const text = 'repos: []\n';
    fs.writeFileSync(file, text);

    const r = fx.runCli(['install-hook', '--manager', 'precommit'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/\.pre-commit-config\.yaml already exists/);
    expect(fs.readFileSync(file, 'utf-8')).toBe(text);
  });

  itPosix.each([
    ['native pre-commit', ['install-hook'], '.git/hooks/pre-commit', '#!/bin/sh\necho foreign\n'],
    ['native pre-commit.cmd', ['install-hook'], '.git/hooks/pre-commit.cmd', '@echo foreign\r\n'],
    ['husky pre-commit', ['install-hook', '--manager', 'husky'], '.husky/pre-commit', '#!/bin/sh\necho foreign\n'],
    ['lefthook-local.yml', ['install-hook', '--manager', 'lefthook'], 'lefthook-local.yml', 'pre-commit:\n  commands: {}\n'],
    ['.pre-commit-config.yaml', ['install-hook', '--manager', 'precommit'], '.pre-commit-config.yaml', 'repos: []\n'],
  ])('exits 1 when %s is a symlink, and leaves the target unchanged', (_name, args, rel, outsideText) => {
    const { repo } = freshRepo();
    const target = linkOutside(repo, rel, outsideText);

    const r = fx.runCli(args, repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/is a symlink, not a regular file/);
    expect(fs.readFileSync(target, 'utf-8')).toBe(outsideText);
    expect(fs.lstatSync(path.join(repo, rel)).isSymbolicLink()).toBe(true);
  });

  itPosix.each([
    ['native pre-commit', ['install-hook'], '.git/hooks/pre-commit'],
    ['native pre-commit.cmd', ['install-hook'], '.git/hooks/pre-commit.cmd'],
    ['husky pre-commit', ['install-hook', '--manager', 'husky'], '.husky/pre-commit'],
    ['lefthook-local.yml', ['install-hook', '--manager', 'lefthook'], 'lefthook-local.yml'],
    ['.pre-commit-config.yaml', ['install-hook', '--manager', 'precommit'], '.pre-commit-config.yaml'],
  ])('exits 1 when %s is not a regular file, and leaves it in place', (_name, args, rel) => {
    const { repo } = freshRepo();
    const abs = path.join(repo, rel);
    fs.mkdirSync(abs, { recursive: true });
    fs.writeFileSync(path.join(abs, 'keep.txt'), 'keep\n');

    const r = fx.runCli(args, repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/is not a regular file/);
    expect(fs.readFileSync(path.join(abs, 'keep.txt'), 'utf-8')).toBe('keep\n');
  });

  itPosix('exits 1 when the native hooks directory is a symlink, and writes nothing through it', () => {
    const { repo, hooks } = freshRepo();
    const real = fx.tmpDir('vg-hook-exit-hooks-');
    dirs.push(real);
    for (const name of fs.readdirSync(hooks)) {
      fs.renameSync(path.join(hooks, name), path.join(real, name));
    }
    fs.rmdirSync(hooks);
    fs.symlinkSync(real, hooks);
    const before = fs.readdirSync(real).sort();

    const r = fx.runCli(['install-hook'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/\.git\/hooks is a symlink/);
    expect(fs.readdirSync(real).sort()).toEqual(before);
  });

  itPosix('exits 1 when .husky is a symlink, and writes nothing through it', () => {
    const { repo } = freshRepo();
    const real = fx.tmpDir('vg-hook-exit-husky-');
    dirs.push(real);
    fs.symlinkSync(real, path.join(repo, '.husky'));

    const r = fx.runCli(['install-hook', '--manager', 'husky'], repo);

    expect(r.code).toBe(1);
    expect(combined(r)).toMatch(/\.husky is a symlink/);
    expect(fs.readdirSync(real)).toEqual([]);
  });

  itPosix('exits 1 when lefthook-local.yml cannot be written', () => {
    const { repo } = freshRepo();
    fs.chmodSync(repo, 0o555);
    try {
      const r = fx.runCli(['install-hook', '--manager', 'lefthook'], repo);
      expect(r.code).toBe(1);
      expect(combined(r)).toMatch(/Failed to write lefthook-local\.yml/);
      expect(fs.existsSync(path.join(repo, 'lefthook-local.yml'))).toBe(false);
    } finally {
      fs.chmodSync(repo, 0o755);
    }
  });

  itPosix('exits 1 when .pre-commit-config.yaml cannot be written', () => {
    const { repo } = freshRepo();
    fs.chmodSync(repo, 0o555);
    try {
      const r = fx.runCli(['install-hook', '--manager', 'precommit'], repo);
      expect(r.code).toBe(1);
      expect(combined(r)).toMatch(/Failed to write \.pre-commit-config\.yaml/);
      expect(fs.existsSync(path.join(repo, '.pre-commit-config.yaml'))).toBe(false);
    } finally {
      fs.chmodSync(repo, 0o755);
    }
  });

  itPosix('exits 1, not 2, when .pre-commit-config.yaml cannot be read', () => {
    const { repo } = freshRepo();
    const cfg = path.join(repo, '.pre-commit-config.yaml');
    fs.writeFileSync(cfg, 'repos: []\n');
    fs.chmodSync(cfg, 0o000);
    try {
      const r = fx.runCli(['install-hook', '--manager', 'precommit'], repo);
      expect(r.code).toBe(1);
      expect(combined(r)).toMatch(/Failed to read \.pre-commit-config\.yaml/);
    } finally {
      fs.chmodSync(cfg, 0o644);
    }
  });

  it('exits 0 when a native hook is installed into an empty repository', () => {
    const { repo, hooks } = freshRepo();

    const r = fx.runCli(['install-hook'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/Pre-commit hook installed/);
    expect(fs.existsSync(path.join(hooks, 'pre-commit'))).toBe(true);
  });

  it('exits 0 when a native install merges into a shell hook', () => {
    const { repo, hooks } = freshRepo();
    const hook = path.join(hooks, 'pre-commit');
    fs.writeFileSync(hook, '#!/bin/sh\necho team\n', { mode: 0o755 });

    const r = fx.runCli(['install-hook'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/merged into your existing hook/);
    expect(fs.readFileSync(hook, 'utf-8')).toContain('# --- vault-guard ---');
  });

  it('exits 0 when the native hook is already installed', () => {
    const { repo } = freshRepo();
    expect(fx.runCli(['install-hook'], repo).code).toBe(0);

    const second = fx.runCli(['install-hook'], repo);

    expect(second.code).toBe(0);
    expect(combined(second)).toMatch(/already installed/i);
  });

  it('exits 0 when a husky hook is created, including a differently cased manager name', () => {
    const { repo } = freshRepo();

    const r = fx.runCli(['install-hook', '--manager', 'Husky'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/Created \.husky\/pre-commit/);
    expect(fs.existsSync(path.join(repo, '.husky', 'pre-commit'))).toBe(true);
  });

  it('exits 0 when lefthook-local.yml is created', () => {
    const { repo } = freshRepo();

    const r = fx.runCli(['install-hook', '--manager', 'lefthook'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/Wrote lefthook-local\.yml/);
    expect(fs.existsSync(path.join(repo, 'lefthook-local.yml'))).toBe(true);
  });

  it('exits 0 when lefthook-local.yml already runs vault-guard', () => {
    const { repo } = freshRepo();
    const file = path.join(repo, 'lefthook-local.yml');
    const text = 'pre-commit:\n  commands:\n    vault-guard:\n      run: vault-guard scan --staged\n';
    fs.writeFileSync(file, text);

    const r = fx.runCli(['install-hook', '--manager', 'lefthook'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/already configures vault-guard/);
    expect(fs.readFileSync(file, 'utf-8')).toBe(text);
  });

  it('exits 0 when .pre-commit-config.yaml is created', () => {
    const { repo } = freshRepo();

    const r = fx.runCli(['install-hook', '--manager', 'precommit'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/Created \.pre-commit-config\.yaml/);
    expect(fs.existsSync(path.join(repo, '.pre-commit-config.yaml'))).toBe(true);
  });

  it('exits 0 when .pre-commit-config.yaml already includes vault-guard', () => {
    const { repo } = freshRepo();
    const file = path.join(repo, '.pre-commit-config.yaml');
    const text = 'repos:\n  - repo: local\n    hooks:\n      - entry: vault-guard scan --staged\n';
    fs.writeFileSync(file, text);

    const r = fx.runCli(['install-hook', '--manager', 'precommit'], repo);

    expect(r.code).toBe(0);
    expect(combined(r)).toMatch(/already includes vault-guard/);
    expect(fs.readFileSync(file, 'utf-8')).toBe(text);
  });
});
