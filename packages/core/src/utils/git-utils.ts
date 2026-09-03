import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { GitError } from '../errors';

/**
 * Repository config that must never be allowed to decide what vault-guard
 * sees, prepended to every git command this module runs.
 *
 * `diff.relative=false` is the load-bearing one. `diff.relative` is an
 * ordinary, user-settable repo config, and with it on git makes
 * `git diff --cached --name-only` both print paths relative to the process
 * cwd instead of the worktree root AND omit every staged path outside that
 * cwd. A pre-commit gate whose file list can be emptied by a line in
 * `.git/config` is not a gate, so the setting is overridden per invocation
 * rather than trusted.
 *
 * `core.quotePath=false` is belt-and-braces: every command below already
 * passes `-z` or reads a single blob, so git never applies path quoting as
 * things stand. Forcing it here means a future edit that drops `-z` cannot
 * silently reintroduce `"\303\251.env"`-style names that would then resolve
 * to a file that does not exist and be skipped.
 *
 * These are `-c key=value` arguments in the argv array, not a `git config`
 * write: nothing on the user's disk is modified.
 */
const FORCED_GIT_CONFIG = ['-c', 'diff.relative=false', '-c', 'core.quotePath=false'];

/**
 * Resolve symlinks in a directory path, falling back to the input when it
 * cannot be resolved. Git reports the physical worktree root, so a caller
 * that passes a symlinked path (`/var/folders/...` on macOS, where the real
 * directory is `/private/var/folders/...`) would otherwise produce a bogus
 * `path.relative` against it.
 */
function canonicalDir(dir: string): string {
  try {
    return fs.realpathSync.native(dir);
  } catch {
    return dir;
  }
}

/**
 * Successful worktree-root lookups, keyed by the `cwd` asked about.
 *
 * `readGitIndexFile` needs the root for every staged file it reads, and a
 * pre-commit run can have hundreds; without this each one would spawn a
 * second git process on the latency-sensitive path. Only successes are
 * cached, so a failure is retried and still throws. A directory's worktree
 * root does not change under a running scan, and the key set is bounded by
 * the number of distinct directories a single process asks about (one, in
 * every current caller).
 */
const worktreeRootCache = new Map<string, string>();

/**
 * Absolute, symlink-resolved path of the worktree root containing `cwd`.
 *
 * Every path git reports for the index is relative to this directory, and
 * `git show :<path>` resolves its argument against it too, so it is the only
 * correct base for turning git's output into filesystem paths. Deriving it
 * from `cwd` instead (what this module used to do) is right only when the
 * caller happens to be standing at the root.
 *
 * Throws `GitError` rather than falling back to `cwd`: a wrong root silently
 * mis-resolves every staged path, which is exactly the failure this function
 * exists to prevent.
 */
export function getGitWorkTreeRoot(cwd: string = process.cwd()): string {
  const cached = worktreeRootCache.get(cwd);
  if (cached !== undefined) return cached;
  const args = [...FORCED_GIT_CONFIG, 'rev-parse', '--show-toplevel'];
  let out: string;
  try {
    out = execFileSync('git', args, {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    throw new GitError(
      `Failed to locate the git worktree root. Is this a git repository? (cwd: ${cwd})\n` +
        `Run 'git status' to verify.\nUnderlying error: ${String(err)}`,
      `git ${args.join(' ')}`,
      err,
    );
  }
  const root = out.trim();
  if (!root) {
    throw new GitError(
      `git reported no worktree root for ${cwd} (bare repository?).`,
      `git ${args.join(' ')}`,
      undefined,
    );
  }
  const resolved = canonicalDir(root);
  worktreeRootCache.set(cwd, resolved);
  return resolved;
}

/**
 * Exact argv passed to git when listing staged files, exported so the
 * safety-critical parts of it can be asserted directly.
 *
 * The `-c diff.relative=false` override is deliberately BELT AND BRACES with
 * running the command at the worktree root (see getGitStagedFilePaths):
 * either one alone makes git's output root-relative. That redundancy is
 * wanted in a published security gate, but redundant code that no test can
 * observe is code the next person deletes as dead weight -- so
 * `git-utils.test.ts` pins this argv, and removing the flag fails a test
 * even though behaviour would not change.
 */
export const STAGED_DIFF_ARGV: readonly string[] = [
  ...FORCED_GIT_CONFIG,
  'diff',
  '--cached',
  '--name-only',
  '--diff-filter=ACMRT',
  // A staged submodule pointer bump is listed here as an ordinary path,
  // but its index entry is a gitlink (mode 160000) rather than a blob, so
  // `git show :<path>` answers "fatal: bad object". There is no content
  // behind a gitlink for this scanner to read, and treating one as an
  // unreadable file made every routine submodule bump block the commit
  // with a message about detected secrets. Dropping the entry is correct,
  // not a suppression: nothing about the pointer is scannable, and the
  // submodule's own contents are that repository's own gate to run.
  '--ignore-submodules=all',
  '-z',
];

/**
 * Return absolute paths of files staged for commit (cached index vs HEAD).
 *
 * Uses `--diff-filter=ACMRT` so deleted index entries are excluded, but
 * **does not** require the path to exist in the worktree. A staged add that
 * was later deleted from disk (`AD` in `git status`) still appears — that
 * blob will be committed and must be scanned.
 *
 * Three independent things keep `diff.relative` from deciding what the gate
 * sees: the config is forced off in the argv, the command runs AT the
 * worktree root where the setting has nothing to make relative, and the
 * output is resolved against that root rather than against `cwd`. Any one of
 * the first two would do; both are here because this is a pre-commit gate on
 * a published package, and the failure mode is silent under-reporting rather
 * than an error anyone would notice.
 *
 * Throws `GitError` on git failure rather than returning an empty list.
 * Returning `[]` silently on git failure would produce a false "✅ nothing
 * staged" result in pre-commit, letting secrets through undetected.
 */
export function getGitStagedFilePaths(cwd: string = process.cwd()): string[] {
  const root = getGitWorkTreeRoot(cwd);
  const args = [...STAGED_DIFF_ARGV];
  let out: string;
  try {
    out = execFileSync('git', args, {
      cwd: root,
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
  // `-z` gives NUL-separated, unquoted, verbatim paths, so entries are used
  // exactly as git produced them. Trimming here would corrupt the legal (if
  // unusual) filename with leading or trailing whitespace into a path that
  // does not exist.
  return out
    .split('\0')
    .filter(Boolean)
    .map((rel) => path.resolve(root, rel));
}

/**
 * Read a staged blob from the index (`git show :path`), not the worktree.
 *
 * `filePath` may be absolute or relative to `cwd`, and may use OS
 * separators. It is re-expressed relative to the worktree root before it
 * reaches git, because git's `:<path>` revision syntax is root-relative by
 * definition. Handing it a path relative to a subdirectory is what produced
 * "fatal: path 'pkg/deep/staged.ts' is in the index, but not 'staged.ts'"
 * and, one silent downgrade later, a clean bill of health over a real
 * staged credential.
 *
 * Unlike the staged listing, this command needs no worktree-root `cwd` of
 * its own: `:<path>` is defined as root-relative, so once the path has been
 * re-expressed the working directory git runs in cannot change the answer.
 */
export function readGitIndexFile(cwd: string, filePath: string): string {
  const root = getGitWorkTreeRoot(cwd);
  const abs = path.resolve(canonicalDir(cwd), filePath);
  const rootRelative = path.relative(root, abs).split(path.sep).join('/');
  const args = [...FORCED_GIT_CONFIG, 'show', `:${rootRelative}`];
  try {
    return execFileSync('git', args, {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    });
  } catch (err) {
    throw new GitError(
      `Failed to read staged blob for ${rootRelative}\nUnderlying error: ${String(err)}`,
      `git ${args.join(' ')}`,
      err,
    );
  }
}

/** True when `cwd` is inside a work tree with a `.git` directory or file. */
export function isInsideGitWorkTree(cwd: string = process.cwd()): boolean {
  try {
    execFileSync('git', [...FORCED_GIT_CONFIG, 'rev-parse', '--is-inside-work-tree'], {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return true;
  } catch {
    return false;
  }
}
