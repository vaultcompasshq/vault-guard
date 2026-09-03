import { PreCommitHook } from '../pre-commit-hook';
import fs from 'fs';
import { spawnSync } from 'child_process';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';

// Drives a real commit with a stub vault-guard exiting `exitCode` on PATH,
// and returns both whether the commit was refused and the captured output
// -- so tests can assert the hook's own explanation actually printed, not
// merely that the commit failed for some other reason (a crashed hook must
// never pass as a block). Shared across describe blocks (plain husky 9,
// nested husky 9, husky 8) since it depends only on the repo dir passed in.
function driveCommitWithStub(
  dir: string,
  exitCode: number,
): { committed: boolean; output: string } {
  const binDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-stub-bin-'));
  try {
    const stub = path.join(binDir, 'vault-guard');
    fs.writeFileSync(stub, `#!/bin/sh\necho "stub vault-guard ran: $*"\nexit ${exitCode}\n`);
    fs.chmodSync(stub, 0o755);

    fs.writeFileSync(path.join(dir, 'a.txt'), `hello ${exitCode}`);
    execSync('git add -A', { cwd: dir, stdio: 'ignore' });

    let committed = true;
    let output = '';
    try {
      execSync(`git commit -q -m "should be blocked (exit ${exitCode})"`, {
        cwd: dir,
        env: { ...process.env, PATH: `${binDir}:${process.env.PATH ?? ''}` },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      committed = false;
      const e = error as { stdout?: Buffer; stderr?: Buffer };
      output = `${e.stdout?.toString('utf-8') ?? ''}${e.stderr?.toString('utf-8') ?? ''}`;
    }

    return { committed, output };
  } finally {
    fs.rmSync(binDir, { recursive: true, force: true });
  }
}

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

    // False positives caught by review before shipping: the h-shim and
    // dispatcher-content signals used to trigger the redirect on their
    // own. Directory shape (basename `_` under a directory named
    // `.husky`) is now the ONLY thing that may trigger it; these two
    // signals may confirm a shape match, never cause one.

    it('does NOT redirect on an h file alone: an unrelated .githooks dir with a file literally named h', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-githooks-'));
      try {
        fs.writeFileSync(path.join(dir, 'h'), '#!/usr/bin/env sh\necho unrelated\n');
        expect(preCommitHook.isHuskyGeneratedHooksDir(dir)).toBe(false);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('does NOT redirect on dispatcher-shaped content alone: a two-line pre-commit outside .husky/_', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-dispatcher-shaped-'));
      try {
        fs.writeFileSync(
          path.join(dir, 'pre-commit'),
          '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        );
        expect(preCommitHook.isHuskyGeneratedHooksDir(dir)).toBe(false);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('derives the redirect target as the parent of the generated dir, not a fixed cwd/.husky: a nested relative hooksPath targets the nested tracked hook', () => {
      // core.hooksPath can be any relative path shaped like `.../.husky/_`
      // (basename `_` under a directory named `.husky`), not necessarily
      // directly under the repo root -- this is the ordinary shape for a
      // monorepo package that owns husky's "prepare" script but is not
      // itself the git root. Husky's own `h` shim resolves the tracked
      // hook it actually executes as the PARENT of the generated `_`
      // directory plus the hook name, so the redirect target here MUST be
      // <cwd>/nested/.husky/pre-commit, never the fixed
      // <cwd>/.husky/pre-commit a hardcoded cwd-based computation would
      // produce. This test previously asserted the fixed-cwd answer as
      // correct; independent review proved that wrong with a functional
      // shim and a real commit (see the nested-layout describe block
      // below), so this assertion is inverted to match reality, not kept.
      const nestedGenDir = path.join(testDir, 'nested', '.husky', '_');
      fs.mkdirSync(nestedGenDir, { recursive: true });
      execSync('git config --local core.hooksPath nested/.husky/_', {
        cwd: testDir,
        stdio: 'ignore',
      });

      // realpathSync normalizes macOS's /var -> /private/var symlink so
      // this compares the same way fs.existsSync would (path identity,
      // not string identity): a relative core.hooksPath is resolved
      // against git's own (symlink-resolved) worktree root.
      const realTestDir = fs.realpathSync(testDir);
      const resolved = preCommitHook.getPreCommitHookPath(testDir, 'native');
      expect(resolved).toBe(path.join(realTestDir, 'nested', '.husky', 'pre-commit'));
      expect(resolved).not.toBe(path.join(realTestDir, '.husky', 'pre-commit'));
    });
  });

  describe('husky-generated hooks dir (husky 9)', () => {
    // Builds a husky 9 layout by hand: core.hooksPath=.husky/_ (generated,
    // gitignored), a two-line dispatcher, and a .gitignore with a bare `*`
    // -- the shape husky's own prepare script produces and rewrites on
    // every install. The `h` shim re-executes the TRACKED hook one
    // directory up (.husky/<hookname>) via `sh -e "$tracked" "$@"`,
    // matching real husky 9's own mechanism -- not merely sourcing it --
    // so tests that drive a real commit through this fixture actually
    // exercise the same `sh -e` semantics the generated hook script runs
    // under in a real husky 9 repo.
    function buildHusky9Layout(dir: string): void {
      const genDir = path.join(dir, '.husky', '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, '.gitignore'), '*\n');
      fs.writeFileSync(
        path.join(genDir, 'h'),
        '#!/usr/bin/env sh\n' +
          'tracked="$(dirname "$(dirname "$0")")/$(basename "$0")"\n' +
          'sh -e "$tracked" "$@"\n' +
          'exit $?\n',
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
      // realpathSync normalizes macOS's /var -> /private/var symlink; see
      // the nested-hooksPath test above for why this matters here.
      expect(resolved).toBe(path.join(fs.realpathSync(testDir), '.husky', 'pre-commit'));
    });

    it('getPreCommitCmdPath returns undefined under a husky-generated hooks dir: the .cmd companion is native-only and never written there', () => {
      buildHusky9Layout(testDir);
      expect(preCommitHook.getPreCommitCmdPath(testDir)).toBeUndefined();
    });

    it('drives a real commit through the husky 9 layout after a bare native install: a failing stub refuses it', () => {
      // The proof that matters, same style as the relative-hooksPath fix
      // above: install, then make git actually run the hook rather than
      // only asserting on the installed path. Asserts the stub's own
      // announce line actually printed, not merely that the commit
      // failed -- a crashed hook (wrong shebang, missing interpreter,
      // permission error) would also make git exit non-zero, and must
      // never be mistaken for a real block.
      buildHusky9Layout(testDir);
      execSync('git config user.email "test@example.com"', { cwd: testDir, stdio: 'ignore' });
      execSync('git config user.name "Test"', { cwd: testDir, stdio: 'ignore' });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);

      const { committed, output } = driveCommitWithStub(testDir, 1);

      expect(committed).toBe(false);
      expect(output).toContain('stub vault-guard ran: scan --staged');
      expect(output).toContain('COMMIT BLOCKED');
    });

    // Amendment: husky's own `h` shim re-executes the tracked hook via
    // `sh -e "$tracked" "$@"` (see buildHusky9Layout above) -- a fresh
    // shell explicitly in errexit mode, regardless of whether the tracked
    // hook itself declares `set -e`. HUSKY_HOOK_SCRIPT's status check
    // (`vault-guard scan --staged || { ... }`) is written so `-e` never
    // fires on the scan command's own failure: it is the first command of
    // an OR list, which POSIX exempts from errexit, so the explanation
    // block always runs. A naive rewrite that captured the status with a
    // bare `vault-guard scan --staged` line followed by `status=$?` would
    // NOT be exempt -- `-e` would abort the script right at the scan line,
    // before `status=$?` ever ran, silently losing the "COMMIT BLOCKED"
    // explanation and surfacing vault-guard's raw exit code instead.
    // Proven empirically in a scratch repro before writing this test:
    // the current script prints the explanation for both exit statuses
    // below; the naive bare-`$?` rewrite does not, for either.
    it.each([1, 2])(
      'explanation survives husky\'s sh -e re-exec when the stub exits %i',
      exitCode => {
        buildHusky9Layout(testDir);
        execSync('git config user.email "test@example.com"', { cwd: testDir, stdio: 'ignore' });
        execSync('git config user.name "Test"', { cwd: testDir, stdio: 'ignore' });
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });
        expect(result.success).toBe(true);

        const { committed, output } = driveCommitWithStub(testDir, exitCode);

        expect(committed).toBe(false);
        expect(output).toContain('stub vault-guard ran: scan --staged');
        expect(output).toContain('COMMIT BLOCKED');
      },
    );

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

  describe('husky 9 with a nested core.hooksPath (monorepo package not at git root)', () => {
    // BLOCKING finding from independent review: the ordinary monorepo
    // shape has the package that owns package.json's "prepare": "husky"
    // script somewhere other than the git root. Husky still writes its
    // generated dir and tracked hook inside THAT package's own .husky,
    // and core.hooksPath (set repo-wide, from the root) points at
    // "<package>/.husky/_" -- nested below cwd, not directly under it.
    // Husky's own `h` shim resolves the tracked hook it actually executes
    // as the PARENT of the generated `_` directory plus the hook name:
    // <package>/.husky/pre-commit, never <cwd>/.husky/pre-commit. A fixed
    // cwd-based redirect target reports success at a path git never
    // reads while git actually runs the nested one, unguarded -- proven
    // by the reviewer with a functional shim and a real commit, and
    // reproduced the same way here.
    const subdir = 'packages/app';

    function buildNestedHusky9Layout(rootDir: string): void {
      const genDir = path.join(rootDir, subdir, '.husky', '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, '.gitignore'), '*\n');
      fs.writeFileSync(
        path.join(genDir, 'h'),
        '#!/usr/bin/env sh\n' +
          'tracked="$(dirname "$(dirname "$0")")/$(basename "$0")"\n' +
          'sh -e "$tracked" "$@"\n' +
          'exit $?\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(genDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        { mode: 0o755 },
      );
      execSync(`git config --local core.hooksPath ${subdir}/.husky/_`, {
        cwd: rootDir,
        stdio: 'ignore',
      });
    }

    it('getPreCommitHookPath resolves to the nested tracked hook, not <cwd>/.husky/pre-commit', () => {
      buildNestedHusky9Layout(testDir);
      // realpathSync normalizes macOS's /var -> /private/var symlink; see
      // the isHuskyGeneratedHooksDir describe block above for why this
      // matters here (a relative core.hooksPath resolves against git's
      // own, symlink-resolved worktree root).
      const realTestDir = fs.realpathSync(testDir);
      const resolved = preCommitHook.getPreCommitHookPath(testDir, 'native');
      expect(resolved).toBe(path.join(realTestDir, subdir, '.husky', 'pre-commit'));
      expect(resolved).not.toBe(path.join(realTestDir, '.husky', 'pre-commit'));
    });

    it('bare native install, run from the repo root, writes the nested tracked hook and never creates <cwd>/.husky', () => {
      buildNestedHusky9Layout(testDir);
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      const trackedPath = path.join(testDir, subdir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);
      expect(fs.readFileSync(trackedPath, 'utf-8')).toContain('scan --staged');
      expect(result.message).toContain(`${subdir}/.husky/pre-commit`);
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);
    });

    it('drives a real commit through the nested husky 9 layout: a failing stub refuses it, with the announce line present', () => {
      buildNestedHusky9Layout(testDir);
      execSync('git config user.email "test@example.com"', { cwd: testDir, stdio: 'ignore' });
      execSync('git config user.name "Test"', { cwd: testDir, stdio: 'ignore' });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);

      const { committed, output } = driveCommitWithStub(testDir, 1);

      expect(committed).toBe(false);
      expect(output).toContain('stub vault-guard ran: scan --staged');
      expect(output).toContain('COMMIT BLOCKED');
    });

    it('uninstall targets the nested tracked hook, not <cwd>/.husky', () => {
      buildNestedHusky9Layout(testDir);
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });
      const trackedPath = path.join(testDir, subdir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);

      const result = preCommitHook.uninstall({ manager: 'native' });

      // uninstallHusky's own append-vs-fresh-file handling (unrelated to
      // this fix, and already exercised by the plain husky-9 "never
      // writes under .husky/_ on uninstall either" test above) leaves a
      // freshly-written (non-appended) hook file in place with a "review
      // manually" message rather than deleting it. What matters here is
      // that native's delegation to it targets the NESTED tracked file
      // -- succeeding, not erroring -- rather than a fixed
      // <cwd>/.husky/pre-commit that was never written.
      expect(result.success).toBe(true);
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);
    });

    it('idempotence: isInstalled and a second bare install both read the nested tracked hook', () => {
      buildNestedHusky9Layout(testDir);
      process.chdir(testDir);
      expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);

      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(true);

      const second = preCommitHook.install({ manager: 'native' });
      expect(second.success).toBe(true);
      expect(second.message).toMatch(/already contains vault-guard/i);
    });
  });

  describe('husky 8 (core.hooksPath=.husky, no generated dir) keeps working unchanged', () => {
    // Husky 8's shape is entirely different from husky 9's: core.hooksPath
    // points AT .husky itself (basename ".husky", not "_"), git executes
    // .husky/<hookname> directly with no dispatcher and no h-shim re-exec,
    // and the tracked hook file carries a preamble sourcing
    // .husky/_/husky.sh. isHuskyGeneratedHooksDir's basename check must
    // not match this shape, so the redirect never fires; the native
    // manager's existing default write path already targets
    // .husky/pre-commit directly, unchanged by this fix.
    function buildHusky8Layout(dir: string): void {
      const huskyDir = path.join(dir, '.husky');
      const genDir = path.join(huskyDir, '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(
        path.join(genDir, 'husky.sh'),
        '#!/usr/bin/env sh\nif [ -z "$husky_skip_init" ]; then\n  export husky_skip_init=1\nfi\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(huskyDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname -- "$0")/_/husky.sh"\n\necho "pre-existing user hook"\n',
        { mode: 0o755 },
      );
      execSync('git config --local core.hooksPath .husky', { cwd: dir, stdio: 'ignore' });
    }

    it('does not redirect: isHuskyGeneratedHooksDir is false for the husky 8 shape', () => {
      buildHusky8Layout(testDir);
      const { hooksDir } = preCommitHook.getEffectiveHooksDir(testDir);
      expect(preCommitHook.isHuskyGeneratedHooksDir(hooksDir)).toBe(false);
      // realpathSync normalizes macOS's /var -> /private/var symlink so
      // this compares the same way fs.existsSync would (path identity,
      // not string identity): getPreCommitHookPath resolves the relative
      // core.hooksPath against git's own (symlink-resolved) worktree root.
      expect(preCommitHook.getPreCommitHookPath(testDir, 'native')).toBe(
        path.join(fs.realpathSync(testDir), '.husky', 'pre-commit'),
      );
    });

    it('bare native install writes .husky/pre-commit directly (existing behavior, no "managed by husky" message)', () => {
      buildHusky8Layout(testDir);
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).not.toMatch(/managed by husky/i);
      const trackedPath = path.join(testDir, '.husky', 'pre-commit');
      expect(fs.readFileSync(trackedPath, 'utf-8')).toContain('scan --staged');
      // husky.sh is untouched -- the redirect delegation path was never
      // entered, so nothing besides the hook file (and its optional
      // .cmd companion) was written.
      expect(fs.existsSync(path.join(testDir, '.husky', '_', 'husky.sh'))).toBe(true);
    });

    it('drives a real commit through the husky 8 layout after a bare native install: a failing stub refuses it', () => {
      buildHusky8Layout(testDir);
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
        let output = '';
        try {
          execSync('git commit -q -m "should be blocked"', {
            cwd: testDir,
            env: { ...process.env, PATH: `${binDir}:${process.env.PATH ?? ''}` },
            stdio: ['ignore', 'pipe', 'pipe'],
          });
        } catch (error) {
          committed = false;
          const e = error as { stdout?: Buffer; stderr?: Buffer };
          output = `${e.stdout?.toString('utf-8') ?? ''}${e.stderr?.toString('utf-8') ?? ''}`;
        }

        expect(committed).toBe(false);
        expect(output).toContain('stub vault-guard ran: scan --staged');
        expect(output).toContain('COMMIT BLOCKED');
      } finally {
        fs.rmSync(binDir, { recursive: true, force: true });
      }
    });
  });

  describe('false positives: must not redirect (install-level)', () => {
    // Amendment: the h-shim and dispatcher-content signals must never
    // trigger the redirect on their own -- only directory shape may. Each
    // scenario below is shaped to defeat the OLD (now removed) OR-based
    // detection while failing the shape check, proving the redirect does
    // not fire, no .husky directory gets created, and the install
    // message never claims husky manages the hooks.

    it('core.hooksPath=.githooks containing an unrelated file named h does not redirect', () => {
      const hooksDirAbs = path.join(testDir, '.githooks');
      fs.mkdirSync(hooksDirAbs, { recursive: true });
      fs.writeFileSync(path.join(hooksDirAbs, 'h'), '#!/usr/bin/env sh\necho unrelated\n');
      execSync('git config --local core.hooksPath .githooks', { cwd: testDir, stdio: 'ignore' });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      expect(result.success).toBe(true);
      expect(result.message).not.toMatch(/managed by husky/i);
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);
      const installedPath = path.join(hooksDirAbs, 'pre-commit');
      expect(fs.existsSync(installedPath)).toBe(true);
      expect(fs.readFileSync(installedPath, 'utf-8')).toContain('scan --staged');
    });

    it('no core.hooksPath with a dispatcher-shaped .git/hooks/pre-commit does not redirect', () => {
      execSync('git config --local --unset core.hooksPath', { cwd: testDir, stdio: 'ignore' });
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(
        path.join(hooksDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
      );
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });

      // Foreign, non-vault-guard content at the REAL (non-redirected)
      // location -- install()'s existing "overwrite a foreign hook"
      // behavior applies here exactly as it would for any other foreign
      // hook, never redirected to .husky/pre-commit.
      expect(result.success).toBe(true);
      expect(result.message).not.toMatch(/managed by husky/i);
      expect(fs.existsSync(path.join(testDir, '.husky'))).toBe(false);
      const content = fs.readFileSync(path.join(hooksDir, 'pre-commit'), 'utf-8');
      expect(content).toContain('vault-guard');
      expect(content).toContain('scan --staged');
    });
  });
});
