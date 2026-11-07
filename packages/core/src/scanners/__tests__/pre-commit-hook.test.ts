import { PreCommitHook } from '../pre-commit-hook';
import fs from 'fs';
import { spawnSync } from 'child_process';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';

const GIT_IDENTITY =
  'git -c user.name=Test -c user.email=test@example.invalid -c commit.gpgsign=false';

/** The whole native script the 1.0.x template wrote, byte for byte. */
const LEGACY_1_0_SCRIPT = [
  '#!/bin/sh',
  '# vault-guard pre-commit hook',
  'echo "🔍 Running Vault Guard security scan..."',
  'vault-guard scan',
  '',
  'if [ $? -ne 0 ]; then',
  '  echo ""',
  '  echo "❌ COMMIT BLOCKED: Secrets detected"',
  `  echo "💡 Run 'vault-guard fix' to auto-fix issues"`,
  '  exit 1',
  'fi',
  '',
  'echo "✅ No secrets found, proceeding with commit"',
  '',
].join('\n');

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
      // The fixture carries its own identity and never signs, so the test does
      // not depend on a global git config (CI runners have none).
      execSync(`${GIT_IDENTITY} commit -q -m "should be blocked (exit ${exitCode})"`, {
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
        LEGACY_1_0_SCRIPT,
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
        LEGACY_1_0_SCRIPT,
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
        LEGACY_1_0_SCRIPT,
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

    describe('a foreign pre-commit hook is merged into, never overwritten', () => {
      const FOREIGN = '#!/bin/sh\n# team hook\nnpm run lint-staged\necho "team hook ran"\n';

      function writeForeign(text: string, mode = 0o755): void {
        fs.mkdirSync(hooksDir, { recursive: true });
        fs.writeFileSync(hookPath, text, { mode });
        fs.chmodSync(hookPath, mode);
      }

      it('keeps every foreign line byte for byte, adds the marked stanza, and keeps the executable bit', () => {
        writeForeign(FOREIGN);
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(result.message).toContain('Pre-commit hook installed');
        expect(result.message).toContain('merged into your existing hook');
        const after = fs.readFileSync(hookPath, 'utf-8');
        expect(after).toContain('# --- vault-guard ---');
        expect(after).toContain('# --- end vault-guard ---');
        expect(after).toContain('vault-guard scan --staged');
        // Removing the stanza gives the foreign hook back exactly.
        expect(after.replace(/# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/, '')).toBe(FOREIGN);
        expect(fs.statSync(hookPath).mode & 0o777).toBe(0o755);
      });

      it('merges rather than adopts a foreign hook whose comment mentions vault-guard and scan --staged (NB5)', () => {
        const text =
          '#!/bin/sh\n# team lint hook. TODO: also run vault-guard (scan --staged) once the team agrees.\nnpm run lint-staged\n';
        writeForeign(text);
        process.chdir(testDir);

        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(result.message).not.toMatch(/already installed/i);
        const after = fs.readFileSync(hookPath, 'utf-8');
        expect(after).toContain('# --- vault-guard ---');
        expect(after).toContain('npm run lint-staged');
        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(true);
      });

      it('leaves an own hook unchanged and says it is already installed', () => {
        process.chdir(testDir);
        expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);
        const first = fs.readFileSync(hookPath, 'utf-8');

        const again = preCommitHook.install({ manager: 'native' });

        expect(again.message).toMatch(/Hook already installed/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(first);
      });

      it('writes the full script over an empty or whitespace-only hook', () => {
        writeForeign('  \n\n');
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        const after = fs.readFileSync(hookPath, 'utf-8');
        expect(after).toContain('# vault-guard pre-commit (installed by @vaultcompass/vault-guard)');
        expect(after).not.toContain('# --- vault-guard ---');
      });

      it('appends nothing the second time (idempotent)', () => {
        writeForeign(FOREIGN);
        process.chdir(testDir);
        expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);
        const once = fs.readFileSync(hookPath, 'utf-8');

        const twice = preCommitHook.install({ manager: 'native' });

        expect(twice.message).toMatch(/Hook already installed/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(once);
      });

      const WIRED_MESSAGE =
        'The pre-commit hook already mentions vault-guard scan --staged; vault-guard cannot verify that line blocks, so its own stanza was added as well';

      it('adds its own stanza to a hook that already runs vault-guard scan --staged on a live line, and says so', () => {
        const text = '#!/bin/sh\nnpm test\nvault-guard scan --staged || exit 1\n';
        writeForeign(text);
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(result.message).toBe(WIRED_MESSAGE);
        const after = fs.readFileSync(hookPath, 'utf-8');
        expect(after).toContain('# --- vault-guard ---');
        expect(after.replace(/# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/, '')).toBe(text);
      });

      it.each([
        ['a heredoc body', '#!/bin/sh\ncat <<EOF\nvault-guard scan --staged\nEOF\n'],
        ['a multi-line string', "#!/bin/sh\n: '\nvault-guard scan --staged\n'\n"],
        ['a command substitution', '#!/bin/sh\nout=$(vault-guard scan --staged)\n'],
        ['an || true', '#!/bin/sh\nvault-guard scan --staged || true\n'],
        ['dead code after exit', '#!/bin/sh\nexit 0\nvault-guard scan --staged\n'],
      ])('adds its own stanza to a hook that mentions the command in %s, blocks a staged secret, and adds one stanza on a second install', (_label, text) => {
        writeForeign(text);
        process.chdir(testDir);

        const first = preCommitHook.install({ manager: 'native' });
        expect(first.success).toBe(true);
        expect(first.message).toBe(WIRED_MESSAGE);
        const once = fs.readFileSync(hookPath, 'utf-8');
        expect(once.split('# --- vault-guard ---\n')).toHaveLength(2);

        const blocked = driveCommitWithStub(testDir, 1);
        expect(blocked.committed).toBe(false);
        expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');

        const second = preCommitHook.install({ manager: 'native' });
        expect(second.message).toMatch(/Hook already installed/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(once);
        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(true);
      });

      it('isInstalled is false for a hook that only mentions the command, so init calls install', () => {
        writeForeign('#!/bin/sh\nvault-guard scan --staged\n');
        process.chdir(testDir);
        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
      });

      it.each([
        ['a trailing comment', '#!/bin/sh\nnpm --version >/dev/null  # TODO: && vault-guard scan --staged once the team agrees\n'],
        ['an echoed double-quoted string', '#!/bin/sh\necho "Reminder: run (vault-guard scan --staged) before pushing"\n'],
      ])('merges rather than adopts a hook that mentions the command in %s, and the merged hook blocks a staged secret', (_label, text) => {
        writeForeign(text);
        process.chdir(testDir);

        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(result.message).toContain('merged into your existing hook');
        expect(fs.readFileSync(hookPath, 'utf-8')).toContain('# --- vault-guard ---');
        const blocked = driveCommitWithStub(testDir, 1);
        expect(blocked.committed).toBe(false);
        expect(blocked.output).toContain('stub vault-guard ran: scan --staged');
      });

      it('still classifies vault-guard scan --staged after && on a code line as wired (the message names it)', () => {
        writeForeign('#!/bin/sh\nnpm test && vault-guard scan --staged  # gate\n');
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.message).toBe(WIRED_MESSAGE);
      });

      it('uninstall of a hook that only mentions the command refuses, and leaves it and pre-commit.cmd in place', () => {
        const text = '#!/bin/sh\nvault-guard scan --staged\n';
        writeForeign(text);
        const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
        fs.writeFileSync(
          cmdPath,
          '@echo off\nREM vault-guard pre-commit (installed by @vaultcompass/vault-guard)\ncall vault-guard scan --staged\n',
        );
        process.chdir(testDir);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(text);
        expect(fs.existsSync(cmdPath)).toBe(true);
      });

      it('refuses to uninstall a merged hook whose stanza lost its end marker, and changes nothing', () => {
        writeForeign(FOREIGN);
        process.chdir(testDir);
        preCommitHook.install({ manager: 'native' });
        const damaged = fs.readFileSync(hookPath, 'utf-8').replace('# --- end vault-guard ---\n', '');
        fs.writeFileSync(hookPath, damaged);
        const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
        expect(fs.existsSync(cmdPath)).toBe(true);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(result.message).toMatch(/damaged/);
        expect(result.message).toMatch(/by hand/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(damaged);
        expect(fs.existsSync(cmdPath)).toBe(true);
      });

      it('refuses to merge into a hook that is not a shell script, and changes nothing', () => {
        const text = '#!/usr/bin/env python3\nprint("py hook")\n';
        writeForeign(text);
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(result.message).toMatch(/not a shell script/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(text);
      });

      it('puts the stanza before a trailing exit 0, so the scan cannot be skipped', () => {
        writeForeign('#!/bin/sh\necho team\nexit 0\n');
        process.chdir(testDir);
        preCommitHook.install({ manager: 'native' });

        const blocked = driveCommitWithStub(testDir, 1);
        expect(blocked.committed).toBe(false);
        expect(blocked.output).toContain('stub vault-guard ran: scan --staged');
      });

      it('blocks a real commit when the scan exits 1, and lets the foreign hook run and the commit through on 0', () => {
        writeForeign('#!/bin/sh\necho "team hook ran"\n');
        process.chdir(testDir);
        preCommitHook.install({ manager: 'native' });

        const blocked = driveCommitWithStub(testDir, 1);
        expect(blocked.committed).toBe(false);
        expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');

        const incomplete = driveCommitWithStub(testDir, 2);
        expect(incomplete.committed).toBe(false);
        expect(incomplete.output).toContain('could not complete the scan');

        const clean = driveCommitWithStub(testDir, 0);
        expect(clean.committed).toBe(true);
      });

      it('uninstall after a merge gives the foreign hook back byte for byte', () => {
        writeForeign(FOREIGN);
        process.chdir(testDir);
        preCommitHook.install({ manager: 'native' });

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(result.message).toMatch(/stanza/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(FOREIGN);
        expect(fs.statSync(hookPath).mode & 0o777).toBe(0o755);
        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
      });

      it('uninstall leaves a foreign hook that only mentions vault-guard in a comment alone', () => {
        const text = '#!/bin/sh\n# TODO run vault-guard (scan --staged) someday\nnpm test\n';
        writeForeign(text);
        process.chdir(testDir);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(text);
      });

      it('uninstall of an owned hook removes the whole file', () => {
        process.chdir(testDir);
        preCommitHook.install({ manager: 'native' });

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(fs.existsSync(hookPath)).toBe(false);
      });

      it('says a merged hook that is not executable will not run until chmod +x', () => {
        writeForeign(FOREIGN, 0o644);
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(result.message).toContain('is not executable, so git will not run it until you chmod +x it');
      });
    });

    describe('a hook is vault-guard\'s whole only when its bytes are a script vault-guard wrote', () => {
      function writeHook(text: string, mode = 0o755): void {
        fs.mkdirSync(hooksDir, { recursive: true });
        fs.writeFileSync(hookPath, text, { mode });
        fs.chmodSync(hookPath, mode);
      }

      function installedScript(): string {
        process.chdir(testDir);
        expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);
        return fs.readFileSync(hookPath, 'utf-8');
      }

      it('uninstall deletes a hook equal to the current script, also with CRLF line ends or no final newline', () => {
        const script = installedScript();
        for (const variant of [script, script.replace(/\n/g, '\r\n'), script.replace(/\n$/, '')]) {
          writeHook(variant);
          const result = preCommitHook.uninstall({ manager: 'native' });
          expect(result.success).toBe(true);
          expect(fs.existsSync(hookPath)).toBe(false);
        }
      });

      it('uninstall deletes a hook equal to the 1.0.x script', () => {
        writeHook(LEGACY_1_0_SCRIPT);
        process.chdir(testDir);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(fs.existsSync(hookPath)).toBe(false);
      });

      it('uninstall refuses a vault-guard script with lines added to it, names the file, and changes nothing', () => {
        const script = installedScript();
        const edited = `${script}# team addition\nnpm run lint-staged\n`;
        writeHook(edited);
        const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
        expect(fs.existsSync(cmdPath)).toBe(true);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(result.message).toContain('pre-commit');
        expect(result.message).toContain('vault-guard did not write all of it');
        expect(result.message).toMatch(/by hand/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(edited);
        expect(fs.existsSync(cmdPath)).toBe(true);
      });

      it('isInstalled is false for a vault-guard script with lines added to it, and install refuses it, names the file, and changes nothing', () => {
        const script = installedScript();
        const edited = `${script}# team addition\n`;
        writeHook(edited);

        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
        const result = preCommitHook.install({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(result.message).toContain('.git/hooks/pre-commit');
        expect(result.message).toMatch(/edited after install/);
        expect(result.message).toMatch(/remove the edits/);
        expect(result.message).toContain('--force');
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(edited);
      });

      it('install refuses a released vault-guard script with lines added to it, and a hook whose CRLF copy of the script has lines added', () => {
        const released = [
          '#!/bin/sh',
          '# vault-guard pre-commit (installed by @vaultcompass/vault-guard)',
          'set -e',
          '',
          '# Re-attach stdin for GUI git clients.',
          'if [ -t 0 ]; then :; else exec </dev/tty 2>/dev/null || true; fi',
          '',
          'if ! command -v vault-guard >/dev/null 2>&1; then',
          '  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"',
          '  exit 1',
          'fi',
          '',
          'echo "🔍 vault-guard: scanning staged files..."',
          'if vault-guard scan --staged; then',
          '  echo "✅ vault-guard: no secrets in staged files"',
          '  exit 0',
          'fi',
          '',
          'echo ""',
          'echo "❌ COMMIT BLOCKED: secrets detected in staged files"',
          'echo "💡 Fix or unstage, then retry. Emergency bypass (discouraged): git commit --no-verify"',
          'exit 1',
          '',
        ].join('\n');
        process.chdir(testDir);
        for (const edited of [
          `${released}\n# team addition\n`,
          `${installedScript().replace(/\n/g, '\r\n')}npm test\r\n`,
          `${LEGACY_1_0_SCRIPT}npm test\n`,
        ]) {
          writeHook(edited);
          const result = preCommitHook.install({ manager: 'native' });
          expect(result.success).toBe(false);
          expect(result.message).toMatch(/edited after install/);
          expect(fs.readFileSync(hookPath, 'utf-8')).toBe(edited);
        }
      });

      it('install --force rewrites a vault-guard script with lines added to it and says the edits were discarded', () => {
        const script = installedScript();
        writeHook(`${script}npm run lint-staged\n`);

        const result = preCommitHook.install({ manager: 'native', force: true });

        expect(result.success).toBe(true);
        expect(result.message).toMatch(/edits .*discarded/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(script);
        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(true);
      });

      it('install --force still merges into a foreign hook that only carries the header line', () => {
        const foreign =
          '#!/bin/sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\necho "team hook ran"\n';
        writeHook(foreign);
        process.chdir(testDir);

        const result = preCommitHook.install({ manager: 'native', force: true });

        expect(result.success).toBe(true);
        const after = fs.readFileSync(hookPath, 'utf-8');
        expect(after.replace(/# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/, '')).toBe(foreign);
      });

      it('uninstall refuses a merged hook whose remainder is still a vault-guard script with edits, and changes nothing', () => {
        const script = installedScript();
        // A stanza merged into an edited vault-guard script (what an earlier
        // install on this branch's history could leave): after the stanza is
        // removed, the rest still runs vault-guard's own scan.
        writeHook('#!/bin/sh\necho "team hook ran"\n');
        expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);
        const stanza = /# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/.exec(fs.readFileSync(hookPath, 'utf-8'))![0];
        const nl = script.indexOf('\n');
        const merged = `${script.slice(0, nl + 1)}${stanza}${script.slice(nl + 1)}npm test\n`;
        writeHook(merged);
        const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
        expect(fs.existsSync(cmdPath)).toBe(true);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(result.message).toContain('.git/hooks/pre-commit');
        expect(result.message).toMatch(/still a hook vault-guard wrote/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(merged);
        expect(fs.existsSync(cmdPath)).toBe(true);
      });

      it('uninstall deletes a vault-guard script with extra trailing blank lines', () => {
        const script = installedScript();
        writeHook(`${script}\n\n`);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(true);
        expect(fs.existsSync(hookPath)).toBe(false);
      });

      it('uninstall leaves a hook that only runs vault-guard on a line of its own in place, and says it was kept', () => {
        const wired = '#!/bin/sh\nvault-guard scan --staged\n';
        writeHook(wired);
        process.chdir(testDir);

        const result = preCommitHook.uninstall({ manager: 'native' });

        expect(result.success).toBe(false);
        expect(result.kept).toBe(true);
        expect(result.message).toMatch(/Leaving it unchanged/);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(wired);
      });

      it('uninstall with dryRun changes nothing and gives the same answer as the real run', () => {
        const script = installedScript();
        const cmdPath = path.join(hooksDir, 'pre-commit.cmd');
        const owned = preCommitHook.uninstall({ manager: 'native', dryRun: true });
        expect(owned.success).toBe(true);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(script);
        expect(fs.existsSync(cmdPath)).toBe(true);

        writeHook(`${script}npm test\n`);
        const claimed = preCommitHook.uninstall({ manager: 'native', dryRun: true });
        expect(claimed.success).toBe(false);
        expect(claimed.kept).toBeUndefined();

        writeHook('#!/bin/sh\nvault-guard scan --staged\n');
        const wired = preCommitHook.uninstall({ manager: 'native', dryRun: true });
        expect(wired.success).toBe(false);
        expect(wired.kept).toBe(true);

        writeHook('#!/bin/sh\necho "team hook ran"\n');
        expect(preCommitHook.install({ manager: 'native' }).success).toBe(true);
        const before = fs.readFileSync(hookPath, 'utf-8');
        const merged = preCommitHook.uninstall({ manager: 'native', dryRun: true });
        expect(merged.success).toBe(true);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(before);
        expect(fs.existsSync(cmdPath)).toBe(true);
      });

      it('merges into a foreign hook that only carries the header line, the merged hook blocks a staged secret, and uninstall gives it back byte for byte', () => {
        const foreign =
          '#!/bin/sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\necho "team hook ran"\n';
        writeHook(foreign);
        process.chdir(testDir);

        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
        const install = preCommitHook.install({ manager: 'native' });
        expect(install.success).toBe(true);
        expect(install.message).not.toMatch(/already installed/i);
        expect(fs.readFileSync(hookPath, 'utf-8')).toContain('# --- end vault-guard ---');

        const blocked = driveCommitWithStub(testDir, 1);
        expect(blocked.committed).toBe(false);
        expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');

        const result = preCommitHook.uninstall({ manager: 'native' });
        expect(result.success).toBe(true);
        expect(fs.readFileSync(hookPath, 'utf-8')).toBe(foreign);
      });

      it('install merges rather than adopts a hook whose stanza lost its end marker', () => {
        const damaged = '#!/bin/sh\n# --- vault-guard ---\necho "team hook ran"\nexit 0\n';
        writeHook(damaged);
        process.chdir(testDir);

        expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
        const install = preCommitHook.install({ manager: 'native' });
        expect(install.message).not.toMatch(/already installed/i);

        const blocked = driveCommitWithStub(testDir, 1);
        expect(blocked.committed).toBe(false);
        expect(blocked.output).toContain('stub vault-guard ran: scan --staged');
      });
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
        LEGACY_1_0_SCRIPT,
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

    it('uninstall strips only the appended stanza when vault-guard was appended to a pre-existing foreign hook', () => {
      process.chdir(testDir);
      fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
      const hookPath = path.join(testDir, '.husky', 'pre-commit');
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "pre-existing foreign hook"\n', { mode: 0o755 });

      const installResult = preCommitHook.install({ manager: 'husky' });
      expect(installResult.message).toMatch(/Added the vault-guard stanza/);
      expect(fs.readFileSync(hookPath, 'utf-8')).toContain('pre-existing foreign hook');
      expect(preCommitHook.isInstalled({ manager: 'husky' })).toBe(true);

      const result = preCommitHook.uninstall({ manager: 'husky' });

      // Only the stanza vault-guard itself appended comes out; the
      // pre-existing foreign content the user already had stays, and the
      // file is not deleted (it is not ours to delete outright -- unlike
      // a hook vault-guard wrote whole from the template).
      expect(result.success).toBe(true);
      expect(fs.existsSync(hookPath)).toBe(true);
      const remaining = fs.readFileSync(hookPath, 'utf-8');
      expect(remaining).toContain('pre-existing foreign hook');
      expect(remaining).not.toContain('vault-guard');
      expect(preCommitHook.isInstalled({ manager: 'husky' })).toBe(false);
    });

    it('uninstall leaves foreign content that merely mentions vault-guard alone, with an honest message, and does not falsely report success', () => {
      process.chdir(testDir);
      fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
      const hookPath = path.join(testDir, '.husky', 'pre-commit');
      // Contains both substrings isInstalled checks for, but in NEITHER
      // shape vault-guard itself ever writes (no whole-file header, no
      // "# --- vault-guard ---" appended marker) -- e.g. hand-edited, or
      // a vault-guard-written file with its header line since removed.
      const foreignContent =
        '#!/bin/sh\n# ask on #vault-guard-questions before touching this\nvault-guard scan --staged\necho done\n';
      fs.writeFileSync(hookPath, foreignContent, { mode: 0o755 });
      // A mention is not an installation: only a script vault-guard wrote
      // whole, or a complete stanza, is.
      expect(preCommitHook.isInstalled({ manager: 'husky' })).toBe(false);

      const result = preCommitHook.uninstall({ manager: 'husky' });

      expect(fs.readFileSync(hookPath, 'utf-8')).toBe(foreignContent);
      // The file still runs the command and vault-guard left it untouched
      // rather than guess at what to remove, so this must not claim success.
      expect(result.success).toBe(false);
      expect(result.message.toLowerCase()).toMatch(/review|manually|unchanged/);
    });

    function writeHuskyHook(text: string): string {
      fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
      const p = path.join(testDir, '.husky', 'pre-commit');
      fs.writeFileSync(p, text, { mode: 0o755 });
      return p;
    }

    it('husky install merges into a hook that only mentions vault-guard in a comment, rather than adopting it', () => {
      process.chdir(testDir);
      const text = '#!/usr/bin/env sh\n# later: vault-guard scan --staged\nnpm test\n';
      const p = writeHuskyHook(text);

      expect(preCommitHook.isInstalled({ manager: 'husky' })).toBe(false);
      const result = preCommitHook.install({ manager: 'husky' });

      expect(result.success).toBe(true);
      expect(result.message).not.toMatch(/already contains/i);
      const after = fs.readFileSync(p, 'utf-8');
      expect(after.replace(/# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/, '')).toBe(text);
      expect(preCommitHook.isInstalled({ manager: 'husky' })).toBe(true);
      expect(preCommitHook.install({ manager: 'husky' }).message).toMatch(/already contains/i);
      expect(fs.readFileSync(p, 'utf-8')).toBe(after);
    });

    it('husky uninstall after a merge gives the hook back byte for byte', () => {
      process.chdir(testDir);
      const text = '#!/usr/bin/env sh\nnpm test\nexit 0\n';
      const p = writeHuskyHook(text);
      preCommitHook.install({ manager: 'husky' });

      const result = preCommitHook.uninstall({ manager: 'husky' });

      expect(result.success).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toBe(text);
    });

    it('husky uninstall refuses a vault-guard script with lines added to it, names the file, and changes nothing', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'husky' });
      const p = path.join(testDir, '.husky', 'pre-commit');
      const edited = `${fs.readFileSync(p, 'utf-8')}npm run lint-staged\n`;
      fs.writeFileSync(p, edited);

      const result = preCommitHook.uninstall({ manager: 'husky' });

      expect(result.success).toBe(false);
      expect(result.message).toContain('.husky/pre-commit');
      expect(result.message).toContain('vault-guard did not write all of it');
      expect(fs.readFileSync(p, 'utf-8')).toBe(edited);
    });

    it.each([
      ['the header line alone', '# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\n'],
      ['the header line and exit 0', '#!/usr/bin/env sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\nexit 0\n'],
    ])('husky install merges into a hook with %s rather than adopting it, the staged secret is blocked, and uninstall gives the bytes back', (_shape, text) => {
      process.chdir(testDir);
      const p = writeHuskyHook(text);
      execSync(`git config --local core.hooksPath "${path.join(testDir, '.husky')}"`, { cwd: testDir, stdio: 'ignore' });

      expect(preCommitHook.isInstalled({ manager: 'husky' })).toBe(false);
      const install = preCommitHook.install({ manager: 'husky' });
      expect(install.success).toBe(true);
      expect(install.message).not.toMatch(/already contains/i);
      expect(install.message).toMatch(/Added the vault-guard stanza/);
      expect(fs.readFileSync(p, 'utf-8')).toContain('# --- end vault-guard ---');

      const blocked = driveCommitWithStub(testDir, 1);
      expect(blocked.committed).toBe(false);
      expect(blocked.output).toContain('stub vault-guard ran: scan --staged');
      expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');

      const result = preCommitHook.uninstall({ manager: 'husky' });
      expect(result.success).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toBe(text);
    });

    it('husky install refuses a vault-guard script with lines added to it, names the file, and --force rewrites it', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'husky' });
      const p = path.join(testDir, '.husky', 'pre-commit');
      const script = fs.readFileSync(p, 'utf-8');
      const edited = `${script}npm run lint-staged\n`;
      fs.writeFileSync(p, edited);

      const refused = preCommitHook.install({ manager: 'husky' });
      expect(refused.success).toBe(false);
      expect(refused.message).toContain('.husky/pre-commit');
      expect(refused.message).toMatch(/edited after install/);
      expect(refused.message).toContain('--force');
      expect(fs.readFileSync(p, 'utf-8')).toBe(edited);

      const forced = preCommitHook.install({ manager: 'husky', force: true });
      expect(forced.success).toBe(true);
      expect(forced.message).toMatch(/edits .*discarded/);
      expect(fs.readFileSync(p, 'utf-8')).toBe(script);
    });

    it('husky install refuses the 1.0.0 husky script, which has no header line, with lines added to it', () => {
      process.chdir(testDir);
      const legacy = [
        '#!/usr/bin/env sh',
        'if [ -f "$(dirname "$0")/_/husky.sh" ]; then',
        '  . "$(dirname "$0")/_/husky.sh"',
        'fi',
        '',
        'if ! command -v vault-guard >/dev/null 2>&1; then',
        '  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"',
        '  exit 1',
        'fi',
        '',
        'echo "🔍 vault-guard: scanning staged files..."',
        'vault-guard scan --staged || {',
        '  echo ""',
        '  echo "❌ COMMIT BLOCKED: secrets detected in staged files"',
        '  echo "💡 git commit --no-verify to bypass (discouraged)"',
        '  exit 1',
        '}',
        'echo "✅ vault-guard: no secrets in staged files"',
        '',
      ].join('\n');
      const edited = `${legacy}npm test\n`;
      const p = writeHuskyHook(edited);

      const result = preCommitHook.install({ manager: 'husky' });

      expect(result.success).toBe(false);
      expect(result.message).toMatch(/edited after install/);
      expect(fs.readFileSync(p, 'utf-8')).toBe(edited);
    });

    it('husky uninstall refuses a merged hook whose remainder is still a vault-guard script with edits', () => {
      process.chdir(testDir);
      preCommitHook.install({ manager: 'husky' });
      const p = path.join(testDir, '.husky', 'pre-commit');
      const script = fs.readFileSync(p, 'utf-8');
      fs.writeFileSync(p, '#!/usr/bin/env sh\nnpm test\n');
      preCommitHook.install({ manager: 'husky' });
      const stanza = /# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/.exec(fs.readFileSync(p, 'utf-8'))![0];
      const nl = script.indexOf('\n');
      const merged = `${script.slice(0, nl + 1)}${stanza}${script.slice(nl + 1)}npm test\n`;
      fs.writeFileSync(p, merged);

      const result = preCommitHook.uninstall({ manager: 'husky' });

      expect(result.success).toBe(false);
      expect(result.message).toMatch(/still a hook vault-guard wrote/);
      expect(fs.readFileSync(p, 'utf-8')).toBe(merged);
    });

    it('husky uninstall marks a hook that only mentions the command as kept', () => {
      process.chdir(testDir);
      const text = '#!/bin/sh\nvault-guard scan --staged\n';
      const p = writeHuskyHook(text);

      const result = preCommitHook.uninstall({ manager: 'husky' });

      expect(result.success).toBe(false);
      expect(result.kept).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toBe(text);
    });

    it('husky uninstall still removes the stanza earlier versions appended at the end of a hook', () => {
      process.chdir(testDir);
      const text = '#!/bin/sh\necho "pre-existing foreign hook"\n';
      const p = writeHuskyHook(
        `${text}\n# --- vault-guard ---\nvault-guard scan --staged || {\n  echo "❌ vault-guard blocked commit"\n  exit 1\n}\n`,
      );

      const result = preCommitHook.uninstall({ manager: 'husky' });

      expect(result.success).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toBe(text);
    });
  });

  describe('a vault-guard script edited anywhere, not only at the end, is still vault-guard\'s', () => {
    // Released scripts from the checked-in fixture (the em dash is a token there).
    const released = (
      JSON.parse(
        fs.readFileSync(path.join(__dirname, 'fixtures', 'released-hook-scripts.json'), 'utf8'),
      ) as { scripts: Array<{ manager: string; versions: string; lines: string[] }> }
    ).scripts;
    const releasedScript = (manager: string, versions: string): string =>
      released
        .find(s => s.manager === manager && s.versions === versions)!
        .lines.join('\n')
        .replace(/\{EM_DASH\}/g, String.fromCharCode(0x2014));

    function currentScript(manager: 'native' | 'husky'): string {
      process.chdir(testDir);
      const p = manager === 'native' ? hookPath : path.join(testDir, '.husky', 'pre-commit');
      if (fs.existsSync(p)) fs.rmSync(p);
      expect(preCommitHook.install({ manager }).success).toBe(true);
      const text = fs.readFileSync(p, 'utf-8');
      fs.rmSync(p);
      const cmd = path.join(hooksDir, 'pre-commit.cmd');
      if (fs.existsSync(cmd)) fs.rmSync(cmd);
      return text;
    }

    function place(manager: 'native' | 'husky', text: string): string {
      const p = manager === 'native' ? hookPath : path.join(testDir, '.husky', 'pre-commit');
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, text, { mode: 0o755 });
      return p;
    }

    const edits: Array<[string, (t: string) => string]> = [
      ['a line inserted at line 3', t => { const l = t.split('\n'); l.splice(2, 0, 'export PATH="$HOME/bin:$PATH"'); return l.join('\n'); }],
      ['a template line deleted in the middle', t => t.split('\n').filter(l => !l.includes('command -v vault-guard')).join('\n')],
      ['a line prepended before the shebang', t => `echo "team prelude"\n${t}`],
    ];

    const cases: Array<[string, 'native' | 'husky', () => string]> = [
      ['the current native script', 'native', () => currentScript('native')],
      ['the 1.4.6 native script', 'native', () => releasedScript('native', '1.4.6 to 1.8.1')],
      ['the 1.0.0 native script', 'native', () => releasedScript('native', '1.0.0 to 1.3.0')],
      ['the current husky script', 'husky', () => currentScript('husky')],
      ['the 1.4.4 husky script', 'husky', () => releasedScript('husky', '1.4.4 to 1.4.5')],
      ['the headerless 1.0.0 husky script', 'husky', () => releasedScript('husky', '1.0.0 to 1.4.3')],
    ];

    for (const [label, manager, script] of cases) {
      for (const [editLabel, edit] of edits) {
        it(`install refuses ${label} with ${editLabel}, uninstall refuses it, and --force rewrites it`, () => {
          const current = currentScript(manager);
          const edited = edit(script());
          const p = place(manager, edited);

          const install = preCommitHook.install({ manager });
          expect(install.success).toBe(false);
          expect(install.message).toMatch(/edited after install/);
          expect(fs.readFileSync(p, 'utf-8')).toBe(edited);

          const uninstall = preCommitHook.uninstall({ manager });
          expect(uninstall.success).toBe(false);
          expect(uninstall.kept).toBeUndefined();
          expect(fs.readFileSync(p, 'utf-8')).toBe(edited);

          const forced = preCommitHook.install({ manager, force: true });
          expect(forced.success).toBe(true);
          expect(forced.discardedEdits).toBe(true);
          expect(fs.readFileSync(p, 'utf-8')).toBe(current);
        });
      }

      it(`uninstall refuses a merged hook whose remainder is ${label} with a line inserted at line 3`, () => {
        const p = place(manager, '#!/bin/sh\necho "team hook ran"\n');
        process.chdir(testDir);
        expect(preCommitHook.install({ manager }).success).toBe(true);
        const stanza = /# --- vault-guard ---[\s\S]*# --- end vault-guard ---\n/.exec(fs.readFileSync(p, 'utf-8'))![0];
        const lines = script().split('\n');
        lines.splice(2, 0, 'export PATH="$HOME/bin:$PATH"');
        const merged = `${lines[0]}\n${stanza}${lines.slice(1).join('\n')}`;
        fs.writeFileSync(p, merged);

        const result = preCommitHook.uninstall({ manager });

        expect(result.success).toBe(false);
        expect(result.message).toMatch(/still a hook vault-guard wrote/);
        expect(fs.readFileSync(p, 'utf-8')).toBe(merged);
      });
    }

    it.each([
      ['native', '#!/bin/sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\nnpm test\n'],
      ['husky', '#!/usr/bin/env sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\nnpm test\n'],
      ['native', '#!/bin/sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\nnpx vault-guard scan --staged\n'],
    ] as const)('a %s hook with the header line but no scan line of a vault-guard script still gets the stanza', (manager, text) => {
      process.chdir(testDir);
      const p = place(manager, text);

      const install = preCommitHook.install({ manager });

      expect(install.success).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toContain('# --- end vault-guard ---');
      expect(preCommitHook.uninstall({ manager }).success).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toBe(text);
    });

    it.each(['owned', 'merged'] as const)('a husky dry-run uninstall of a hook that is %s changes no byte', kind => {
      process.chdir(testDir);
      const p = path.join(testDir, '.husky', 'pre-commit');
      if (kind === 'merged') place('husky', '#!/usr/bin/env sh\nnpm test\n');
      expect(preCommitHook.install({ manager: 'husky' }).success).toBe(true);
      const before = fs.readFileSync(p, 'utf-8');

      const result = preCommitHook.uninstall({ manager: 'husky', dryRun: true });

      expect(result.success).toBe(true);
      expect(fs.readFileSync(p, 'utf-8')).toBe(before);
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

    it('puts the stanza before a trailing exit 0 in .husky/pre-commit, so a staged secret is blocked', () => {
      buildHusky9Layout(testDir);
      fs.writeFileSync(path.join(testDir, '.husky', 'pre-commit'), '#!/usr/bin/env sh\necho team\nexit 0\n', {
        mode: 0o755,
      });
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);

      const { committed, output } = driveCommitWithStub(testDir, 1);
      expect(committed).toBe(false);
      expect(output).toContain('stub vault-guard ran: scan --staged');
      expect(output).toContain('COMMIT BLOCKED: secrets detected');
    });

    it('merges into a .husky/pre-commit that only mentions vault-guard in a comment, so a staged secret is blocked', () => {
      buildHusky9Layout(testDir);
      fs.writeFileSync(
        path.join(testDir, '.husky', 'pre-commit'),
        '#!/usr/bin/env sh\n# later: vault-guard scan --staged\necho team\n',
        { mode: 0o755 },
      );
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);
      expect(result.message).not.toMatch(/already contains/i);

      const { committed, output } = driveCommitWithStub(testDir, 1);
      expect(committed).toBe(false);
      expect(output).toContain('stub vault-guard ran: scan --staged');
    });

    it('never writes under .husky/_ on uninstall either, and actually removes the tracked hook (isInstalled false afterwards)', () => {
      buildHusky9Layout(testDir);
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });
      const before = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();
      const trackedPath = path.join(testDir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);

      const result = preCommitHook.uninstall({ manager: 'native' });

      // The redirect writes .husky/pre-commit WHOLE from HUSKY_HOOK_SCRIPT
      // (the fresh-install path, never appended-to), so uninstall must
      // recognize that shape and remove the file entirely -- not merely
      // report success while leaving isInstalled true.
      expect(result.success).toBe(true);
      expect(fs.existsSync(trackedPath)).toBe(false);
      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
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

    it('uninstall targets the nested tracked hook, not <cwd>/.husky, and actually removes it (isInstalled false afterwards)', () => {
      buildNestedHusky9Layout(testDir);
      process.chdir(testDir);
      preCommitHook.install({ manager: 'native' });
      const trackedPath = path.join(testDir, subdir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);

      const result = preCommitHook.uninstall({ manager: 'native' });

      // The redirect writes the nested tracked hook WHOLE from
      // HUSKY_HOOK_SCRIPT (the fresh-install path, never appended-to), so
      // uninstall must recognize that shape and remove the file entirely
      // at the NESTED path -- not a fixed <cwd>/.husky/pre-commit that
      // was never written, and not merely report success while leaving
      // isInstalled true.
      expect(result.success).toBe(true);
      expect(fs.existsSync(trackedPath)).toBe(false);
      expect(preCommitHook.isInstalled({ manager: 'native' })).toBe(false);
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
          execSync(`${GIT_IDENTITY} commit -q -m "should be blocked"`, {
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
      // location -- install()'s "merge a stanza into a foreign hook"
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

  /**
   * Exit 2 means vault-guard could not finish the scan, not that it found
   * something. Reporting that as "secrets detected" and offering
   * `--no-verify` in the same breath is the worst possible advice: the check
   * did not run, and the suggested response is to skip it entirely. Both
   * templates must tell the truth and withhold the bypass hint here, while
   * keeping the existing wording for exit 1.
   *
   * Driven as real commits with a stub `vault-guard` on PATH, because the
   * bug is in shell control flow (`$?` after a bare `if` is the `if`'s own
   * status, not the command's), which reading the template cannot catch.
   */
  describe('hook messaging distinguishes an incomplete scan from a finding', () => {
    const setUpRepo = (): void => {
      execSync('git config user.email "test@example.com"', { cwd: testDir, stdio: 'ignore' });
      execSync('git config user.name "Test"', { cwd: testDir, stdio: 'ignore' });
      process.chdir(testDir);
    };

    describe.each([
      ['native', () => preCommitHook.install({ manager: 'native' })],
      ['husky', () => preCommitHook.install({ manager: 'husky' })],
    ] as const)('%s template', (manager, install) => {
      beforeEach(() => {
        setUpRepo();
        if (manager === 'husky') {
          // The husky manager writes .husky/pre-commit; point git at it so a
          // real commit actually runs the template under test.
          fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
          execSync('git config --local core.hooksPath .husky', {
            cwd: testDir,
            stdio: 'ignore',
          });
        }
        expect(install().success).toBe(true);
      });

      it('refuses the commit and says the scan did not complete on exit 2', () => {
        const { committed, output } = driveCommitWithStub(testDir, 2);

        expect(committed).toBe(false);
        expect(output).toMatch(/could not complete the scan/i);
        expect(output).not.toMatch(/secrets detected/i);
      });

      it('offers no bypass hint on exit 2', () => {
        const { output } = driveCommitWithStub(testDir, 2);

        expect(output).not.toContain('--no-verify');
      });

      it('still reports a finding as secrets detected on exit 1', () => {
        const { committed, output } = driveCommitWithStub(testDir, 1);

        expect(committed).toBe(false);
        expect(output).toMatch(/secrets detected/i);
        expect(output).toContain('--no-verify');
      });

      it('still lets a clean scan through on exit 0', () => {
        const { committed } = driveCommitWithStub(testDir, 0);

        expect(committed).toBe(true);
      });
    });

    it('checks errorlevel 2 before errorlevel 1 in the Windows .cmd companion', () => {
      setUpRepo();
      preCommitHook.install({ manager: 'native' });

      const cmd = fs.readFileSync(path.join(hooksDir, 'pre-commit.cmd'), 'utf-8');

      // Anchor after the scan call: an earlier `if errorlevel 1` guards the
      // command-not-found check and is not part of this ordering.
      const afterScan = cmd.slice(cmd.indexOf('call vault-guard scan --staged'));
      expect(afterScan).toContain('errorlevel 2');
      // `if errorlevel N` is true for anything >= N, so the 2 branch is only
      // ever reachable when it is tested first.
      expect(afterScan.indexOf('errorlevel 2')).toBeLessThan(afterScan.indexOf('errorlevel 1'));
    });
  });
});
