import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { HookError } from '../errors';

export type HookManager = 'native' | 'husky' | 'lefthook' | 'precommit';

export interface InstallHookOptions {
  manager?: HookManager;
  /** Working directory (git repo root). Defaults to `process.cwd()`. */
  cwd?: string;
}

/**
 * Shell hook body for **native** Git hooks (`core.hooksPath` or `.git/hooks`).
 * Scans **staged files only** — fast and matches what will actually be committed.
 */
const NATIVE_HOOK_SCRIPT = `#!/bin/sh
# vault-guard pre-commit (installed by @vaultcompass/vault-guard)
set -e

# Re-attach stdin for GUI git clients.
if [ -t 0 ]; then :; else exec </dev/tty 2>/dev/null || true; fi

if ! command -v vault-guard >/dev/null 2>&1; then
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi

echo "🔍 vault-guard: scanning staged files..."
if vault-guard scan --staged; then
  echo "✅ vault-guard: no secrets in staged files"
  exit 0
fi

echo ""
echo "❌ COMMIT BLOCKED: secrets detected in staged files"
echo "💡 Fix or unstage, then retry. Emergency bypass (discouraged): git commit --no-verify"
exit 1
`;

/** Husky-friendly hook (sources \`_/husky.sh\` when present). */
const HUSKY_HOOK_SCRIPT = `#!/usr/bin/env sh
if [ -f "$(dirname "$0")/_/husky.sh" ]; then
  . "$(dirname "$0")/_/husky.sh"
fi

if ! command -v vault-guard >/dev/null 2>&1; then
  echo "❌ vault-guard: command not found (install: npm i -g @vaultcompass/vault-guard)"
  exit 1
fi

echo "🔍 vault-guard: scanning staged files..."
vault-guard scan --staged || {
  echo ""
  echo "❌ COMMIT BLOCKED: secrets detected in staged files"
  echo "💡 git commit --no-verify to bypass (discouraged)"
  exit 1
}
echo "✅ vault-guard: no secrets in staged files"
`;

const LEFTHOOK_LOCAL = `# Merged by Lefthook with lefthook.yml — added by vault-guard install-hook
pre-commit:
  commands:
    vault-guard:
      run: vault-guard scan --staged
`;

const PRE_COMMIT_CONFIG = `# See https://pre-commit.com
repos:
  - repo: local
    hooks:
      - id: vault-guard
        name: Vault Guard (staged files)
        entry: vault-guard scan --staged
        language: system
        pass_filenames: false
`;

export class PreCommitHook {
  /**
   * Resolve the directory where Git expects the \`pre-commit\` executable.
   * Honors \`core.hooksPath\` (local then global). Relative paths are resolved
   * against the **.git** directory, per Git documentation.
   */
  getEffectiveHooksDir(cwd: string): { hooksDir: string; viaHooksPath: boolean } {
    const gitDirAbs = this.resolveGitDir(cwd);
    if (!gitDirAbs) {
      return { hooksDir: path.join(cwd, '.git', 'hooks'), viaHooksPath: false };
    }

    let hooksPath = '';
    try {
      hooksPath = execSync('git config --get core.hooksPath', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
    } catch {
      hooksPath = '';
    }

    if (!hooksPath) {
      return { hooksDir: path.join(gitDirAbs, 'hooks'), viaHooksPath: false };
    }

    const hooksDir = path.isAbsolute(hooksPath)
      ? hooksPath
      : path.join(gitDirAbs, hooksPath);

    return { hooksDir, viaHooksPath: true };
  }

  /**
   * Absolute path to the \`pre-commit\` hook file for the given manager.
   */
  getPreCommitHookPath(cwd: string, manager: HookManager = 'native'): string {
    if (manager === 'husky') {
      return path.join(cwd, '.husky', 'pre-commit');
    }
    return path.join(this.getEffectiveHooksDir(cwd).hooksDir, 'pre-commit');
  }

  install(options: InstallHookOptions = {}): { success: boolean; message: string; hookPath?: string } {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';

    if (!fs.existsSync(path.join(cwd, '.git'))) {
      return { success: false, message: 'Not a git repository' };
    }

    switch (manager) {
      case 'native':
        return this.installNative(cwd);
      case 'husky':
        return this.installHusky(cwd);
      case 'lefthook':
        return this.installLefthook(cwd);
      case 'precommit':
        return this.installPreCommitFramework(cwd);
      default:
        return { success: false, message: `Unknown hook manager: ${String(manager)}` };
    }
  }

  uninstall(options: InstallHookOptions = {}): { success: boolean; message: string } {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';

    if (!fs.existsSync(path.join(cwd, '.git'))) {
      return { success: false, message: 'Not a git repository' };
    }

    switch (manager) {
      case 'native':
        return this.uninstallNative(cwd);
      case 'husky':
        return this.uninstallHusky(cwd);
      case 'lefthook':
        return this.uninstallLefthook(cwd);
      case 'precommit':
        return this.uninstallPreCommitFramework(cwd);
      default:
        return { success: false, message: `Unknown hook manager: ${String(manager)}` };
    }
  }

  isInstalled(options: InstallHookOptions = {}): boolean {
    const cwd = options.cwd ?? process.cwd();
    const manager = options.manager ?? 'native';
    const hookPath = this.getPreCommitHookPath(cwd, manager);

    if (!fs.existsSync(hookPath)) return false;
    const content = fs.readFileSync(hookPath, 'utf-8');
    return content.includes('vault-guard') && content.includes('scan --staged');
  }

  // -------------------------------------------------------------------------
  // native (Git hooks / core.hooksPath)
  // -------------------------------------------------------------------------

  private installNative(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const { hooksDir, viaHooksPath } = this.getEffectiveHooksDir(cwd);
    const hookPath = path.join(hooksDir, 'pre-commit');

    try {
      if (!fs.existsSync(hooksDir)) {
        fs.mkdirSync(hooksDir, { recursive: true });
      }

      if (fs.existsSync(hookPath)) {
        const existing = fs.readFileSync(hookPath, 'utf-8');
        if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
          return {
            success: true,
            message: 'Hook already installed',
            hookPath,
          };
        }
      }

      fs.writeFileSync(hookPath, NATIVE_HOOK_SCRIPT, { mode: 0o755 });

      const hint = viaHooksPath
        ? `Installed to hooksPath: ${hooksDir}`
        : 'Installed to .git/hooks/pre-commit';

      return { success: true, message: `Pre-commit hook installed (${hint})`, hookPath };
    } catch (error) {
      const hookError = new HookError(`Failed to install hook: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallNative(cwd: string): { success: boolean; message: string } {
    const hookPath = this.getPreCommitHookPath(cwd, 'native');

    if (!fs.existsSync(hookPath)) {
      return { success: true, message: 'No hook to remove' };
    }

    const content = fs.readFileSync(hookPath, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: 'No vault-guard hook to remove' };
    }

    try {
      fs.unlinkSync(hookPath);
      return { success: true, message: 'Pre-commit hook removed' };
    } catch (error) {
      const hookError = new HookError(`Failed to remove hook: ${error}`, 'uninstall');
      return { success: false, message: hookError.message };
    }
  }

  // -------------------------------------------------------------------------
  // Husky — .husky/pre-commit
  // -------------------------------------------------------------------------

  private installHusky(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const huskyDir = path.join(cwd, '.husky');
    const hookPath = path.join(huskyDir, 'pre-commit');

    try {
      if (!fs.existsSync(huskyDir)) {
        fs.mkdirSync(huskyDir, { recursive: true });
      }

      if (fs.existsSync(hookPath)) {
        const existing = fs.readFileSync(hookPath, 'utf-8');
        if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
          return { success: true, message: 'Husky hook already contains vault-guard', hookPath };
        }
        if (existing.includes('# --- vault-guard ---')) {
          return { success: true, message: 'Husky hook already contains vault-guard block', hookPath };
        }
        fs.appendFileSync(
          hookPath,
          `\n# --- vault-guard ---\nvault-guard scan --staged || {\n  echo "❌ vault-guard blocked commit"\n  exit 1\n}\n`,
          { encoding: 'utf-8' },
        );
        return { success: true, message: 'Appended vault-guard to existing .husky/pre-commit', hookPath };
      }

      fs.writeFileSync(hookPath, HUSKY_HOOK_SCRIPT, { mode: 0o755 });
      return {
        success: true,
        message: 'Created .husky/pre-commit (run `npx husky init` first if _/husky.sh is missing)',
        hookPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to install Husky hook: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallHusky(cwd: string): { success: boolean; message: string } {
    const hookPath = path.join(cwd, '.husky', 'pre-commit');
    if (!fs.existsSync(hookPath)) {
      return { success: true, message: 'No .husky/pre-commit to remove' };
    }
    let content = fs.readFileSync(hookPath, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: 'No vault-guard stanza in .husky/pre-commit' };
    }
    // Remove appended block if present.
    content = content.replace(/\n# --- vault-guard ---[\s\S]*$/m, '');
    // If entire file is only our husky template, delete file.
    if (!content.includes('vault-guard')) {
      if (content.trim().length === 0) {
        fs.unlinkSync(hookPath);
        return { success: true, message: 'Removed .husky/pre-commit' };
      }
      fs.writeFileSync(hookPath, content, { mode: 0o755 });
      return { success: true, message: 'Removed vault-guard stanza from .husky/pre-commit' };
    }
    fs.writeFileSync(hookPath, content, { mode: 0o755 });
    return { success: true, message: 'Updated .husky/pre-commit (review manually if needed)' };
  }

  // -------------------------------------------------------------------------
  // Lefthook — lefthook-local.yml (merged with lefthook.yml)
  // -------------------------------------------------------------------------

  private installLefthook(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    try {
      if (fs.existsSync(localPath)) {
        const existing = fs.readFileSync(localPath, 'utf-8');
        if (existing.includes('vault-guard scan --staged')) {
          return { success: true, message: 'lefthook-local.yml already configures vault-guard', hookPath: localPath };
        }
        return {
          success: false,
          message:
            'lefthook-local.yml already exists. Add under pre-commit.commands:\n' +
            '  vault-guard:\n    run: vault-guard scan --staged\n',
        };
      }
      fs.writeFileSync(localPath, LEFTHOOK_LOCAL, 'utf-8');
      return {
        success: true,
        message: 'Wrote lefthook-local.yml (merged by Lefthook with lefthook.yml). Run: lefthook install',
        hookPath: localPath,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to write lefthook-local.yml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallLefthook(cwd: string): { success: boolean; message: string } {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    if (!fs.existsSync(localPath)) {
      return { success: true, message: 'No lefthook-local.yml' };
    }
    const content = fs.readFileSync(localPath, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: 'lefthook-local.yml does not reference vault-guard' };
    }
    // Only remove the file if it is exactly what we wrote (avoid deleting user merges).
    if (content.replace(/\r\n/g, '\n').trim() !== LEFTHOOK_LOCAL.replace(/\r\n/g, '\n').trim()) {
      return {
        success: true,
        message: 'lefthook-local.yml was edited — remove the vault-guard stanza manually',
      };
    }
    try {
      fs.unlinkSync(localPath);
      return { success: true, message: 'Removed lefthook-local.yml (vault-guard stub)' };
    } catch (error) {
      const hookError = new HookError(`Failed to remove lefthook-local.yml: ${error}`, 'uninstall');
      return { success: false, message: hookError.message };
    }
  }

  // -------------------------------------------------------------------------
  // pre-commit.com framework
  // -------------------------------------------------------------------------

  private installPreCommitFramework(cwd: string): { success: boolean; message: string; hookPath?: string } {
    const cfg = path.join(cwd, '.pre-commit-config.yaml');
    if (fs.existsSync(cfg)) {
      const existing = fs.readFileSync(cfg, 'utf-8');
      if (existing.includes('vault-guard') && existing.includes('scan --staged')) {
        return { success: true, message: '.pre-commit-config.yaml already includes vault-guard', hookPath: cfg };
      }
      return {
        success: false,
        message:
          '.pre-commit-config.yaml already exists. Merge manually:\n\n' +
          PRE_COMMIT_CONFIG +
          '\n(under your existing `repos:` list as an additional item, or combine with `repo: local`)',
      };
    }
    try {
      fs.writeFileSync(cfg, PRE_COMMIT_CONFIG, 'utf-8');
      return {
        success: true,
        message: 'Created .pre-commit-config.yaml — run: pre-commit install',
        hookPath: cfg,
      };
    } catch (error) {
      const hookError = new HookError(`Failed to write .pre-commit-config.yaml: ${error}`, 'install');
      return { success: false, message: hookError.message };
    }
  }

  private uninstallPreCommitFramework(cwd: string): { success: boolean; message: string } {
    const cfg = path.join(cwd, '.pre-commit-config.yaml');
    if (!fs.existsSync(cfg)) {
      return { success: true, message: 'No .pre-commit-config.yaml' };
    }
    const content = fs.readFileSync(cfg, 'utf-8');
    if (!content.includes('vault-guard')) {
      return { success: true, message: '.pre-commit-config.yaml does not reference vault-guard' };
    }
    // Only delete if we created the minimal file (only our hook).
    if (content.includes('id: vault-guard') && content.split('\n').length < 25) {
      try {
        fs.unlinkSync(cfg);
        return { success: true, message: 'Removed .pre-commit-config.yaml (vault-guard-only stub)' };
      } catch (error) {
        const hookError = new HookError(`Failed to remove config: ${error}`, 'uninstall');
        return { success: false, message: hookError.message };
      }
    }
    return {
      success: true,
      message: 'Edit .pre-commit-config.yaml manually to remove the vault-guard hook entry',
    };
  }

  private resolveGitDir(cwd: string): string | null {
    try {
      const rel = execSync('git rev-parse --git-dir', {
        cwd,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }).trim();
      return path.resolve(cwd, rel);
    } catch {
      return null;
    }
  }
}
