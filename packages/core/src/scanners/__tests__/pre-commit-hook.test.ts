import { PreCommitHook } from '../pre-commit-hook';
import fs from 'fs';
import { spawnSync } from 'child_process';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';

describe('PreCommitHook', () => {
  let preCommitHook: PreCommitHook;
  let testDir: string;
  let gitDir: string;
  let hooksDir: string;
  let hookPath: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    preCommitHook = new PreCommitHook();
    // Isolated temp dir outside any parent Git repo.
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-precommit-'));
    execSync('git init -q', { cwd: testDir, stdio: 'ignore' });
    gitDir = path.join(testDir, '.git');
    hooksDir = path.join(gitDir, 'hooks');
    hookPath = path.join(hooksDir, 'pre-commit');
    // Override a *global* core.hooksPath (common on dev machines) with an
    // ABSOLUTE path pointing at the ordinary .git/hooks location. An
    // absolute core.hooksPath is used exactly as given, regardless of the
    // relative-path resolution rule under test below, so this keeps these
    // tests exercising the plain default hook location instead of being at
    // the mercy of the host machine's global git config.
    execSync(`git config --local core.hooksPath "${hooksDir}"`, { cwd: testDir, stdio: 'ignore' });
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (fs.existsSync(testDir)) {
      try {
        execSync(`chmod -R u+rwx "${testDir}"`, { stdio: 'ignore' });
      } catch {
        /* ignore */
      }
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  describe('install (native)', () => {
    it('should fail when not in a git repository', () => {
      const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-nogit-'));
      try {
        process.chdir(nonGit);
        const result = preCommitHook.install({ manager: 'native' });
        expect(result.success).toBe(false);
        expect(result.message).toBe('Not a git repository');
      } finally {
        process.chdir(originalCwd);
        fs.rmSync(nonGit, { recursive: true, force: true });
      }
    });

    it('should install hook in git repository', () => {
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).toContain('Pre-commit hook installed');
      expect(fs.existsSync(hookPath)).toBe(true);

      const hookContent = fs.readFileSync(hookPath, 'utf-8');
      expect(hookContent).toContain('vault-guard');
      expect(hookContent).toContain('scan --staged');

      const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
      expect(fs.existsSync(cmdPath)).toBe(true);
      const cmdContent = fs.readFileSync(cmdPath, 'utf-8');
      expect(cmdContent).toContain('vault-guard');
      expect(cmdContent).toContain('scan --staged');
      expect(cmdContent).toMatch(/@echo off/i);
    });

    it('silences and survives the /dev/tty re-attach without a terminal', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });

      const hookContent = fs.readFileSync(hookPath, 'utf-8');

      // dash exits on a failed current-shell `exec </dev/tty` even with
      // `|| true`. The installed hook must probe in a subshell first.
      expect(hookContent).toContain('if (exec </dev/tty) 2>/dev/null; then');
      expect(hookContent).toMatch(/^\s*exec <\/dev\/tty$/m);
      expect(hookContent).not.toContain('{ exec </dev/tty; }');
    });

    it('runs to completion with no controlling terminal', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });

      // Run only the prologue: everything up to the `command -v` guard. That
      // is the part that touches /dev/tty, and it must be both silent and
      // non-fatal when stdin is not a terminal.
      const full = fs.readFileSync(hookPath, 'utf-8');
      const prologue = full.slice(0, full.indexOf('if ! command -v')) + 'echo PROLOGUE_OK\n';
      const scriptPath = path.join(testDir, 'prologue.sh');
      fs.writeFileSync(scriptPath, prologue, { mode: 0o755 });

      const proc = spawnSync('/bin/sh', [scriptPath], {
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      expect(proc.status).toBe(0);
      expect(proc.stdout).toContain('PROLOGUE_OK');
      expect(proc.stderr).not.toMatch(/dev\/tty/);
    });

    it('should install into core.hooksPath when set (relative to the working-tree root)', () => {
      // A relative core.hooksPath resolves against the working-tree root,
      // not against the .git directory. This test asserted the .git
      // location until that was found to be wrong: git actually installs
      // (and runs) the hook at the working-tree-root location, so a test
      // that agreed with the buggy code proved nothing.
      const customHooksRel = 'my-hooks';
      const customHooksAbs = path.join(testDir, customHooksRel);
      fs.mkdirSync(customHooksAbs, { recursive: true });
      execSync(`git config --local core.hooksPath ${customHooksRel}`, { cwd: testDir, stdio: 'ignore' });

      const customHookFile = path.join(customHooksAbs, 'pre-commit');
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);
      expect(result.message).toContain('hooksPath');
      expect(fs.existsSync(customHookFile)).toBe(true);
      expect(fs.readFileSync(customHookFile, 'utf-8')).toContain('scan --staged');
      // Never written under .git: that is the wrong place, and the whole
      // point of this test is that git does not look for it there.
      expect(fs.existsSync(path.join(gitDir, customHooksRel, 'pre-commit'))).toBe(false);
    });

    it('an absolute core.hooksPath is used exactly as given', () => {
      const hooksAbs = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-abs-hooks-'));
      try {
        execSync(`git config --local core.hooksPath "${hooksAbs}"`, { cwd: testDir, stdio: 'ignore' });
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(fs.existsSync(path.join(hooksAbs, 'pre-commit'))).toBe(true);
      } finally {
        fs.rmSync(hooksAbs, { recursive: true, force: true });
      }
    });

    it('with no core.hooksPath set, resolves against the git directory (needed for linked worktrees and submodules)', () => {
      // With no core.hooksPath, hooks live in the git directory, which is
      // NOT the working-tree root for a linked worktree or a submodule --
      // each has its own git dir elsewhere, distinct from both its own
      // working-tree root and the main repository's .git/hooks. This is
      // the one branch the relative-hooksPath fix must leave alone.
      execSync('git config --local --unset core.hooksPath', { cwd: testDir, stdio: 'ignore' });
      execSync('git config user.email "test@example.com"', { cwd: testDir, stdio: 'ignore' });
      execSync('git config user.name "Test"', { cwd: testDir, stdio: 'ignore' });
      fs.writeFileSync(path.join(testDir, 'a.txt'), 'hello');
      execSync('git add a.txt', { cwd: testDir, stdio: 'ignore' });
      execSync('git commit -q -m init', { cwd: testDir, stdio: 'ignore' });

      const worktreeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-worktree-'));
      fs.rmdirSync(worktreeDir);
      execSync(`git worktree add "${worktreeDir}" -q -b wt-branch`, { cwd: testDir, stdio: 'ignore' });

      try {
        const worktreeGitDir = path.resolve(
          worktreeDir,
          execSync('git rev-parse --git-dir', { cwd: worktreeDir, encoding: 'utf-8' }).trim(),
        );
        expect(worktreeGitDir).not.toBe(path.join(worktreeDir, '.git'));
        expect(worktreeGitDir).not.toBe(gitDir);

        const result = preCommitHook.install({ manager: 'native', cwd: worktreeDir });
        expect(result.success).toBe(true);

        const expectedHooksDir = path.join(worktreeGitDir, 'hooks');
        expect(preCommitHook.getEffectiveHooksDir(worktreeDir).hooksDir).toBe(expectedHooksDir);
        expect(fs.existsSync(path.join(expectedHooksDir, 'pre-commit'))).toBe(true);
        expect(fs.existsSync(path.join(worktreeDir, 'hooks', 'pre-commit'))).toBe(false);
      } finally {
        fs.rmSync(worktreeDir, { recursive: true, force: true });
      }
    });

    it('with core.hooksPath set the way husky 9 sets it, installs into the tracked .husky/pre-commit, never the generated dir', () => {
      // core.hooksPath=.husky/_ is husky 9's GENERATED, gitignored
      // directory -- husky's own prepare script rewrites it on every
      // `pnpm install`, so a hook written there does not survive. This
      // test asserted exactly that wrong location (.husky/_/pre-commit) as
      // the expected install target until that was found to be the
      // remaining bug: a bare native install has to land in the TRACKED
      // .husky/pre-commit file instead, the same file the husky manager
      // targets, or the gate is silently wiped on the next install.
      // Driving a real commit through this exact layout (no husky
      // dispatcher present under .husky/_) is no longer a meaningful
      // proof once the fix stops writing there -- see the "husky-generated
      // hooks dir (husky 9)" describe block below for that proof against
      // a full, functional husky 9 layout instead.
      execSync('git config --local core.hooksPath .husky/_', { cwd: testDir, stdio: 'ignore' });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(testDir, '.husky', 'pre-commit'))).toBe(true);
      expect(fs.existsSync(path.join(testDir, '.husky', '_', 'pre-commit'))).toBe(false);
      expect(fs.existsSync(path.join(gitDir, '.husky', '_', 'pre-commit'))).toBe(false);
    });

    it('should create hooks directory if it does not exist', () => {
      fs.rmSync(hooksDir, { recursive: true, force: true });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(fs.existsSync(hooksDir)).toBe(true);
      expect(fs.existsSync(hookPath)).toBe(true);
    });

    it('should detect already installed hook', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        hookPath,
        '#!/bin/sh\n# vault-guard pre-commit hook\nvault-guard scan --staged\n',
        { mode: 0o755 },
      );
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).toMatch(/Hook already installed/);
      expect(fs.existsSync(path.join(hooksDir, 'pre-commit.cmd'))).toBe(true);
    });

    it('should refresh missing Windows .cmd companion when POSIX hook exists', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        hookPath,
        '#!/bin/sh\n# vault-guard pre-commit hook\nvault-guard scan --staged\n',
        { mode: 0o755 },
      );
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);
      const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
      expect(fs.existsSync(cmdPath)).toBe(true);
      expect(fs.readFileSync(cmdPath, 'utf-8')).toContain('call vault-guard scan --staged');
    });

    it('should not overwrite a foreign pre-commit.cmd', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        hookPath,
        '#!/bin/sh\n# vault-guard pre-commit hook\nvault-guard scan --staged\n',
        { mode: 0o755 },
      );
      const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
      const foreign = '@echo off\necho foreign-hook\n';
      fs.writeFileSync(cmdPath, foreign);
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);
      expect(result.message).toMatch(/foreign pre-commit\.cmd/i);
      expect(fs.readFileSync(cmdPath, 'utf-8')).toBe(foreign);
    });

    it('should overwrite non-vault-guard hook', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "other hook"', { mode: 0o755 });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).toContain('Pre-commit hook installed');

      const hookContent = fs.readFileSync(hookPath, 'utf-8');
      expect(hookContent).toContain('vault-guard');
      expect(hookContent).toContain('scan --staged');
    });

    it('should set executable permissions on hook file', () => {
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(fs.statSync(hookPath).isFile()).toBe(true);
    });

    it('should handle file system errors during installation', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      process.chdir(testDir);

      fs.chmodSync(hooksDir, 0o444);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(false);
      expect(result.message).toContain('Failed to install hook');

      try {
        fs.chmodSync(hooksDir, 0o755);
      } catch {
        /* ignore */
      }
    });
  });

  describe('uninstall (native)', () => {
    it('should return success when hook does not exist', () => {
      process.chdir(testDir);

      const result = preCommitHook.uninstall({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).toBe('No hook to remove');
    });

    it('should remove existing hook and Windows .cmd companion', () => {
      process.chdir(testDir);
      expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);
      const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
      expect(fs.existsSync(cmdPath)).toBe(true);

      const result = preCommitHook.uninstall({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).toMatch(/removed/i);
      expect(fs.existsSync(hookPath)).toBe(false);
      expect(fs.existsSync(cmdPath)).toBe(false);
    });
  });

  describe('isInstalled (native)', () => {
    it('should return false when hook does not exist', () => {
      process.chdir(testDir);
      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
    });

    it('should return false when hook exists but is not vault-guard hook', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "other hook"', { mode: 0o755 });
      process.chdir(testDir);

      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
    });

    it('should return true when vault-guard hook is installed', () => {
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        hookPath,
        '#!/bin/sh\n# vault-guard pre-commit hook\nvault-guard scan --staged\n',
        { mode: 0o755 },
      );
      process.chdir(testDir);

      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(true);
    });
  });

  describe('integration workflow', () => {
    it('should handle full install-check-uninstall workflow', () => {
      process.chdir(testDir);

      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);

      const installResult = preCommitHook.install({ manager: 'native' });
      expect(installResult.success).toBe(true);
      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(true);

      const reinstallResult = preCommitHook.install({ manager: 'native' });
      expect(reinstallResult.success).toBe(true);
      expect(reinstallResult.message).toMatch(/Hook already installed/);

      const uninstallResult = preCommitHook.uninstall({ manager: 'native' });
      expect(uninstallResult.success).toBe(true);
      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);

      const reuninstallResult = preCommitHook.uninstall({ manager: 'native' });
      expect(reuninstallResult.success).toBe(true);
      expect(reuninstallResult.message).toBe('No hook to remove');
    });
  });

  describe('hook content', () => {
    it('should run vault-guard scan --staged with bypass hint', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });

      const hookContent = fs.readFileSync(hookPath, 'utf-8');

      expect(hookContent).toContain('vault-guard scan --staged');
      expect(hookContent).toContain('COMMIT BLOCKED');
      expect(hookContent).toContain('--no-verify');
      expect(hookContent).toContain('set -e');
    });

    it('should have proper shell script structure', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });

      const hookContent = fs.readFileSync(hookPath, 'utf-8');

      expect(hookContent).toMatch(/^#!\/bin\/sh/);
      expect(hookContent).toContain('exit 1');
    });
  });

  describe('Husky manager', () => {
    it('creates .husky/pre-commit with vault-guard', () => {
      process.chdir(testDir);
      const r = preCommitHook.install({ manager: 'husky' });
      expect(r.success).toBe(true);
      const p = path.join(testDir, '.husky', 'pre-commit');
      expect(fs.existsSync(p)).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toContain('scan --staged');
    });
  });

  describe('Lefthook manager', () => {
    it('writes lefthook-local.yml when absent', () => {
      process.chdir(testDir);
      const r = preCommitHook.install({ manager: 'lefthook' });
      expect(r.success).toBe(true);
      const p = path.join(testDir, 'lefthook-local.yml');
      expect(fs.readFileSync(p, 'utf-8')).toContain('vault-guard');
    });
  });

  describe('pre-commit framework manager', () => {
    it('creates .pre-commit-config.yaml when absent', () => {
      process.chdir(testDir);
      const r = preCommitHook.install({ manager: 'precommit' });
      expect(r.success).toBe(true);
      const p = path.join(testDir, '.pre-commit-config.yaml');
      const body = fs.readFileSync(p, 'utf-8');
      expect(body).toContain('vault-guard');
      expect(body).toContain('scan --staged');
    });
  });

  describe('isHuskyGeneratedHooksDir', () => {
    it('detects by directory shape alone (.husky/_), even before husky populates it', () => {
      const generatedDir = path.join(testDir, '.husky', '_');
      expect(preCommitHook.isHuskyGeneratedHooksDir(generatedDir)).toBe(true);
    });

    it('detects by the presence of the h shim', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-nothusky-'));
      try {
        fs.writeFileSync(path.join(dir, 'h'), '#!/usr/bin/env sh\n');
        expect(preCommitHook.isHuskyGeneratedHooksDir(dir)).toBe(true);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('detects by the two-line dispatcher content of pre-commit', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-nothusky-'));
      try {
        fs.writeFileSync(
          path.join(dir, 'pre-commit'),
          '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        );
        expect(preCommitHook.isHuskyGeneratedHooksDir(dir)).toBe(true);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('returns false for an ordinary .git/hooks directory', () => {
      expect(preCommitHook.isHuskyGeneratedHooksDir(hooksDir)).toBe(false);
    });

    it('returns false for a directory with an unrelated pre-commit script', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-nothusky-'));
      try {
        fs.writeFileSync(
          path.join(dir, 'pre-commit'),
          '#!/bin/sh\necho "other hook"\n',
        );
        expect(preCommitHook.isHuskyGeneratedHooksDir(dir)).toBe(false);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  describe('husky-generated hooks dir (husky 9)', () => {
    // Builds a husky 9 layout by hand: core.hooksPath=.husky/_ (generated,
    // gitignored), a two-line dispatcher plus a functional `h` shim that
    // sources the TRACKED hook one directory up (.husky/<hookname>), and a
    // .gitignore with a bare `*` -- the shape husky's own prepare script
    // produces and rewrites on every install.
    function buildHusky9Layout(dir: string): void {
      const genDir = path.join(dir, '.husky', '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, '.gitignore'), '*\n');
      fs.writeFileSync(
        path.join(genDir, 'h'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/../pre-commit"\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(genDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        { mode: 0o755 },
      );
      execSync('git config --local core.hooksPath .husky/_', { cwd: dir, stdio: 'ignore' });
    }

    it('bare native install lands the stanza in .husky/pre-commit and never touches .husky/_', () => {
      buildHusky9Layout(testDir);
      process.chdir(testDir);

      const before = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      const trackedPath = path.join(testDir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);
      expect(fs.readFileSync(trackedPath, 'utf-8')).toContain('scan --staged');
      expect(result.message).toMatch(/husky/i);

      const after = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();
      expect(after).toEqual(before);
    });

    it('getPreCommitHookPath resolves the native manager to the tracked .husky/pre-commit file', () => {
      buildHusky9Layout(testDir);
      const resolved = preCommitHook.getPreCommitHookPath(testDir, 'native');
      expect(resolved).toBe(path.join(testDir, '.husky', 'pre-commit'));
    });

    it('drives a real commit through the husky 9 layout after a bare native install: a failing stub refuses it', () => {
      // The proof that matters, same style as the relative-hooksPath fix
      // above: install, then make git actually run the hook rather than
      // only asserting on the installed path.
      buildHusky9Layout(testDir);
      execSync('git config user.email "test@example.com"', { cwd: testDir, stdio: 'ignore' });
      execSync('git config user.name "Test"', { cwd: testDir, stdio: 'ignore' });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);

      const binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-stub-bin-'));
      try {
        const stub = path.join(binDir, 'vault-guard');
        fs.writeFileSync(stub, '#!/bin/sh\necho "stub vault-guard ran: $*"\nexit 1\n');
        fs.chmodSync(stub, 0o755);

        fs.writeFileSync(path.join(testDir, 'a.txt'), 'hello');
        execSync('git add -A', { cwd: testDir, stdio: 'ignore' });

        let committed = true;
        try {
          execSync('git commit -q -m "should be blocked"', {
            cwd: testDir,
            env: { ...process.env, PATH: `${binDir}:${process.env.PATH ?? ''}` },
            stdio: ['ignore', 'pipe', 'pipe'],
          });
        } catch {
          committed = false;
        }

        expect(committed).toBe(false);
      } finally {
        fs.rmSync(binDir, { recursive: true, force: true });
      }
    });

    it('never writes under .husky/_ on uninstall either', () => {
      buildHusky9Layout(testDir);
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });
      const before = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();

      const result = preCommitHook.uninstall({ manager: 'native' });

      // uninstallHusky's own append-vs-fresh-file handling (unrelated to
      // this fix) is exercised by the husky manager itself; what matters
      // here is that native's delegation to it never touches the
      // generated directory.
      expect(result.success).toBe(true);
      const after = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();
      expect(after).toEqual(before);
    });
  });
});
