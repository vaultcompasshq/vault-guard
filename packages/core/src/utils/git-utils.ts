import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

/**
 * Return absolute paths of files staged for commit (cached index vs HEAD).
 * Excludes deleted paths; only returns paths that still exist on disk.
 */
export function getGitStagedFilePaths(cwd: string = process.cwd()): string[] {
  try {
    const out = execSync('git diff --cached --name-only --diff-filter=ACMRT', {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return out
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((rel) => path.resolve(cwd, rel))
      .filter((abs) => fs.existsSync(abs) && fs.statSync(abs).isFile());
  } catch {
    return [];
  }
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
