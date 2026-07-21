import { execFileSync } from 'child_process';
import path from 'path';
import { GitError } from '../errors';

/**
 * Return absolute paths of files staged for commit (cached index vs HEAD).
 *
 * Uses `--diff-filter=ACMRT` so deleted index entries are excluded, but
 * **does not** require the path to exist in the worktree. A staged add that
 * was later deleted from disk (`AD` in `git status`) still appears — that
 * blob will be committed and must be scanned.
 *
 * Throws `GitError` on git failure rather than returning an empty list.
 * Returning `[]` silently on git failure would produce a false "✅ nothing
 * staged" result in pre-commit, letting secrets through undetected.
 */
export function getGitStagedFilePaths(cwd: string = process.cwd()): string[] {
  const args = ['diff', '--cached', '--name-only', '--diff-filter=ACMRT', '-z'];
  let out: string;
  try {
    out = execFileSync('git', args, {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    throw new GitError(
      `Failed to list staged files — is this a git repository? (cwd: ${cwd})\n` +
        `Run 'git status' to verify.\nUnderlying error: ${String(err)}`,
      `git ${args.join(' ')}`,
      err,
    );
  }
  return out
    .split('\0')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((rel) => path.resolve(cwd, rel));
}

/**
 * Read a staged blob from the index (`git show :path`), not the worktree.
 * `relativePath` may use OS separators; it is normalized to git's `/` form.
 */
export function readGitIndexFile(cwd: string, relativePath: string): string {
  const normalized = relativePath.split(path.sep).join('/');
  const args = ['show', `:${normalized}`];
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    throw new GitError(
      `Failed to read staged blob for ${normalized}\nUnderlying error: ${String(err)}`,
      `git ${args.join(' ')}`,
      err,
    );
  }
}

/** True when `cwd` is inside a work tree with a `.git` directory or file. */
export function isInsideGitWorkTree(cwd: string = process.cwd()): boolean {
  try {
    execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}
