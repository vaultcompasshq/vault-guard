import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { GitError } from '../errors';

/**
 * Return absolute paths of files staged for commit (cached index vs HEAD).
 * Excludes deleted paths; only returns paths that still exist on disk.
 *
 * Throws `GitError` on git failure rather than returning an empty list.
 * Returning `[]` silently on git failure would produce a false "✅ nothing
 * staged" result in pre-commit, letting secrets through undetected.
 */
export function getGitStagedFilePaths(cwd: string = process.cwd()): string[] {
  const cmd = 'git diff --cached --name-only --diff-filter=ACMRT';
  let out: string;
  try {
    out = execSync(cmd, {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    throw new GitError(
      `Failed to list staged files — is this a git repository? (cwd: ${cwd})\n` +
        `Run 'git status' to verify.\nUnderlying error: ${String(err)}`,
      cmd,
      err,
    );
  }
  return out
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((rel) => path.resolve(cwd, rel))
    .filter((abs) => fs.existsSync(abs) && fs.statSync(abs).isFile());
}

/** True when `cwd` is inside a work tree with a `.git` directory or file. */
export function isInsideGitWorkTree(cwd: string = process.cwd()): boolean {
  try {
    execSync('git rev-parse --is-inside-work-tree', {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}
