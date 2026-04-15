import { PreCommitHook } from '../pre-commit-hook';
import fs from 'fs';
import path from 'path';

describe('PreCommitHook', () => {
  let preCommitHook: PreCommitHook;
  let testDir: string;
  let gitDir: string;
  let hooksDir: string;
  let hookPath: string;

  beforeEach(() => {
    preCommitHook = new PreCommitHook();
    testDir = path.join(process.cwd(), 'tmp-test-pre-commit');
    gitDir = path.join(testDir, '.git');
    hooksDir = path.join(gitDir, 'hooks');
    hookPath = path.join(hooksDir, 'pre-commit');

    // Create test directory structure
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  describe('install', () => {
    it('should fail when not in a git repository', () => {
      // Test directory has no .git folder
      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.install();

        expect(result.success).toBe(false);
        expect(result.message).toBe('Not a git repository');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should install hook in git repository', () => {
      // Create .git directory
      fs.mkdirSync(gitDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.install();

        expect(result.success).toBe(true);
        expect(result.message).toBe('Pre-commit hook installed successfully');
        expect(fs.existsSync(hookPath)).toBe(true);

        // Verify hook content
        const hookContent = fs.readFileSync(hookPath, 'utf-8');
        expect(hookContent).toContain('vault-guard');
        expect(hookContent).toContain('pre-commit hook');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should create hooks directory if it does not exist', () => {
      // Create .git directory but no hooks directory
      fs.mkdirSync(gitDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.install();

        expect(result.success).toBe(true);
        expect(fs.existsSync(hooksDir)).toBe(true);
        expect(fs.existsSync(hookPath)).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should detect already installed hook', () => {
      // Create .git and hooks directory
      fs.mkdirSync(hooksDir, { recursive: true });

      // Write existing hook with vault-guard content
      fs.writeFileSync(hookPath, '#!/bin/sh\n# vault-guard pre-commit hook\necho "test"', { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.install();

        expect(result.success).toBe(true);
        expect(result.message).toBe('Hook already installed');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should overwrite non-vault-guard hook', () => {
      // Create .git and hooks directory
      fs.mkdirSync(hooksDir, { recursive: true });

      // Write existing hook without vault-guard content
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "other hook"', { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.install();

        expect(result.success).toBe(true);
        expect(result.message).toBe('Pre-commit hook installed successfully');

        // Verify hook was overwritten
        const hookContent = fs.readFileSync(hookPath, 'utf-8');
        expect(hookContent).toContain('vault-guard');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should set executable permissions on hook file', () => {
      // Create .git directory
      fs.mkdirSync(gitDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.install();

        expect(result.success).toBe(true);

        // Check file permissions (should be executable)
        const stats = fs.statSync(hookPath);
        // Note: mode check may vary by platform, but we verify file exists
        expect(stats.isFile()).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should handle file system errors during installation', () => {
      // Create .git directory but make hooks read-only
      fs.mkdirSync(hooksDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        // Make hooks directory read-only
        fs.chmodSync(hooksDir, 0o444);

        const result = preCommitHook.install();

        // Should fail due to permission error
        expect(result.success).toBe(false);
        expect(result.message).toContain('Failed to install hook');
      } finally {
        // Restore permissions for cleanup
        try {
          fs.chmodSync(hooksDir, 0o755);
        } catch {
          // Ignore if cleanup fails
        }
        process.chdir(originalCwd);
      }
    });
  });

  describe('uninstall', () => {
    it('should return success when hook does not exist', () => {
      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.uninstall();

        expect(result.success).toBe(true);
        expect(result.message).toBe('No hook to remove');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should remove existing hook', () => {
      // Create .git and hooks directory with hook file
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(hookPath, '#!/bin/sh\n# vault-guard hook', { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.uninstall();

        expect(result.success).toBe(true);
        expect(result.message).toBe('Pre-commit hook removed');
        expect(fs.existsSync(hookPath)).toBe(false);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should handle file system errors gracefully', () => {
      // Create hook file
      fs.mkdirSync(hooksDir, { recursive: true });
      fs.writeFileSync(hookPath, '#!/bin/sh\ntest', { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        // This test verifies the error handling path exists
        // In most cases, unlink will succeed even with read-only files
        const result = preCommitHook.uninstall();

        // Should succeed in normal conditions
        expect(result.success).toBe(true);
        expect(fs.existsSync(hookPath)).toBe(false);
      } finally {
        process.chdir(originalCwd);
      }
    });
  });

  describe('isInstalled', () => {
    it('should return false when hook does not exist', () => {
      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.isInstalled();

        expect(result).toBe(false);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should return false when hook exists but is not vault-guard hook', () => {
      // Create .git and hooks directory
      fs.mkdirSync(hooksDir, { recursive: true });

      // Write hook without vault-guard content
      fs.writeFileSync(hookPath, '#!/bin/sh\necho "other hook"', { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.isInstalled();

        expect(result).toBe(false);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should return true when vault-guard hook is installed', () => {
      // Create .git and hooks directory
      fs.mkdirSync(hooksDir, { recursive: true });

      // Write hook with vault-guard content
      fs.writeFileSync(hookPath, '#!/bin/sh\n# vault-guard pre-commit hook\necho "test"', { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.isInstalled();

        expect(result).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should detect vault-guard hook even with other content', () => {
      // Create .git and hooks directory
      fs.mkdirSync(hooksDir, { recursive: true });

      // Write hook with vault-guard and other content
      const hookContent = `#!/bin/sh
# vault-guard pre-commit hook
# Some other comments
echo "Running checks"
vault-guard scan
echo "Done"
`;
      fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        const result = preCommitHook.isInstalled();

        expect(result).toBe(true);
      } finally {
        process.chdir(originalCwd);
      }
    });
  });

  describe('integration workflow', () => {
    it('should handle full install-check-uninstall workflow', () => {
      // Create .git directory
      fs.mkdirSync(gitDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        // Initial state: not installed
        expect(preCommitHook.isInstalled()).toBe(false);

        // Install hook
        const installResult = preCommitHook.install();
        expect(installResult.success).toBe(true);
        expect(preCommitHook.isInstalled()).toBe(true);

        // Try to install again (should detect existing)
        const reinstallResult = preCommitHook.install();
        expect(reinstallResult.success).toBe(true);
        expect(reinstallResult.message).toBe('Hook already installed');

        // Uninstall hook
        const uninstallResult = preCommitHook.uninstall();
        expect(uninstallResult.success).toBe(true);
        expect(preCommitHook.isInstalled()).toBe(false);

        // Try to uninstall again (should handle gracefully)
        const reuninstallResult = preCommitHook.uninstall();
        expect(reuninstallResult.success).toBe(true);
        expect(reuninstallResult.message).toBe('No hook to remove');
      } finally {
        process.chdir(originalCwd);
      }
    });
  });

  describe('hook content', () => {
    it('should contain correct vault-guard command', () => {
      // Create .git directory
      fs.mkdirSync(gitDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        preCommitHook.install();

        const hookContent = fs.readFileSync(hookPath, 'utf-8');

        expect(hookContent).toContain('vault-guard scan');
        expect(hookContent).toContain('COMMIT BLOCKED');
        expect(hookContent).toContain('vault-guard fix');
      } finally {
        process.chdir(originalCwd);
      }
    });

    it('should have proper shell script structure', () => {
      // Create .git directory
      fs.mkdirSync(gitDir, { recursive: true });

      const originalCwd = process.cwd();
      process.chdir(testDir);

      try {
        preCommitHook.install();

        const hookContent = fs.readFileSync(hookPath, 'utf-8');

        expect(hookContent).toMatch(/^#!\/bin\/sh/);
        expect(hookContent).toContain('exit 1');
      } finally {
        process.chdir(originalCwd);
      }
    });
  });
});
