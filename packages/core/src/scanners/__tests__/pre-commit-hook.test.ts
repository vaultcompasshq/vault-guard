import { PreCommitHook } from '../pre-commit-hook';
import fs from 'fs';
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
    // Override a *global* core.hooksPath (common on dev machines) so hooks resolve to .git/hooks.
    execSync('git config --local core.hooksPath hooks', { cwd: testDir, stdio: 'ignore' });
    gitDir = path.join(testDir, '.git');
    hooksDir = path.join(gitDir, 'hooks');
    hookPath = path.join(hooksDir, 'pre-commit');
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

    it('should install into core.hooksPath when set (relative to .git)', () => {
      const customHooksRel = 'my-hooks';
      const customHooksAbs = path.join(gitDir, customHooksRel);
      fs.mkdirSync(customHooksAbs, { recursive: true });
      execSync(`git config --local core.hooksPath ${customHooksRel}`, { cwd: testDir, stdio: 'ignore' });

      const customHookFile = path.join(customHooksAbs, 'pre-commit');
      process.chdir(testDir);

      const result = preCommitHook.install({ manager: 'native' });
      expect(result.success).toBe(true);
      expect(result.message).toContain('hooksPath');
      expect(fs.existsSync(customHookFile)).toBe(true);
      expect(fs.readFileSync(customHookFile, 'utf-8')).toContain('scan --staged');
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
});
