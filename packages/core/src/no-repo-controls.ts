/**
 * `scan --no-repo-controls`: control inputs come from nowhere (design
 * 2026-10-28, proposal and outside-policy runs, section 6, DECISION 11 and
 * review finding B2).
 *
 * The flag is for assessing a repository the person running the scan does not
 * trust: a directory a client handed over, say. Nothing the repository supplies
 * decides what is reported:
 *
 *  - Built-in defaults only. `.vault-guard.json` and `.vault-guard.local.json`
 *    at any level, `.vault-guard.baseline.json`, `.gitignore` and
 *    `.gitattributes` are never read, and every one present in the HEAD tree
 *    is named in the output as present and not honoured. Inline ignore
 *    directives are not honoured either: a finding one would have hidden is
 *    kept and marked.
 *
 *  - The tree is judged as at HEAD, from blobs only. The file set is
 *    `git ls-tree -r -z HEAD` and content is `git cat-file`. The run never
 *    runs `status`, `hash-object`, `check-attr` or `ls-files`, and never reads
 *    a working-tree copy. That is NOT pull-request mode: `--trust-base` reads
 *    a disk copy that differs from HEAD, through `status`, and `status` runs a
 *    repository-configured clean filter on a stat-dirty file.
 *
 *  - Before any other git call, the repository's local git config is checked
 *    against the allowlist in `utils/local-git-config.ts`; any other key
 *    refuses the run. That check is what stops a `core.fsmonitor` or a filter
 *    driver named in a handed-over `.git/config`.
 *
 * Every git call here is in this order, and nothing else: `config --local
 * --list`, `rev-parse --show-toplevel`, `rev-parse --verify HEAD^{commit}`,
 * `ls-tree -r -z HEAD`; the scan then reads blobs with `cat-file --batch-check`
 * and `cat-file --batch`.
 */

import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';

import { BASELINE_FILENAME } from './baseline';
import { listHeadTreeEntries, type HeadTreeEntry } from './trust-base';
import { fileSetGitEnv } from './utils/git-env';
import { checkLocalGitConfig, localGitConfigRefusal } from './utils/local-git-config';

/** The basenames, matched case-insensitively at any depth, that are this gate's control files. */
export const REPO_CONTROL_BASENAMES: readonly string[] = [
  '.vault-guard.json',
  '.vault-guard.local.json',
  BASELINE_FILENAME,
  '.gitignore',
  '.gitattributes',
];

/**
 * What a `--no-repo-controls` run says about the repository's control files.
 * The JSON `repoControls` block and the SARIF run property of that name.
 */
export interface RepoControlsReport {
  /** Always false: this block exists only on a run that honoured none of them. */
  honoured: false;
  /** Every control file present in the HEAD tree, root-relative, sorted. */
  present: string[];
}

/**
 * A `--no-repo-controls` run that cannot start: refused local git config, not
 * a repository, no commit at HEAD, or a git failure. The CLI prints the
 * message and exits 2 having scanned nothing.
 */
export class NoRepoControlsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NoRepoControlsError';
  }
}

/** The HEAD tree a `--no-repo-controls` run scans. */
export interface HeadOnlyTree {
  /** Symlink-resolved worktree root. */
  repoRoot: string;
  /** The resolved HEAD commit. */
  head: string;
  /** Every regular file in the HEAD tree, absolute, to its blob object id. */
  blobs: Map<string, string>;
  /** See {@link RepoControlsReport.present}. */
  present: string[];
  /** Every gitlink (submodule) path in the HEAD tree, root-relative, sorted: not descended into. */
  submodules: string[];
}

/**
 * What a `--no-repo-controls` run says about the tree it judged: the commit,
 * and the paths it lists but did not scan. JSON `scannedCommit` and
 * `notScanned`, and SARIF run properties of the same names.
 */
export interface HeadOnlyReport {
  /** The full object id of the HEAD commit whose tree was scanned. */
  scannedCommit: string;
  notScanned: {
    /** Gitlink paths: the submodule's content is another repository and was not scanned. */
    submodules: string[];
  };
}

const CLONE_FRESH = 'Clone the repository fresh and assess the clone.';

/**
 * Every control file in a HEAD listing: any entry that is not a directory
 * (a symlink or a gitlink at a control path is still present), by basename,
 * case-insensitively, since a case-insensitive checkout would read
 * `.GitIgnore`.
 */
export function presentRepoControls(entries: Iterable<HeadTreeEntry>): string[] {
  const names = new Set(REPO_CONTROL_BASENAMES.map(n => n.toLowerCase()));
  const out: string[] = [];
  for (const e of entries) {
    if (e.type === 'tree') continue;
    const base = e.path.slice(e.path.lastIndexOf('/') + 1).toLowerCase();
    if (names.has(base)) out.push(e.path);
  }
  return out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function git(cwd: string, args: string[]): { ok: true; out: string } | { ok: false; detail: string } {
  const r = spawnSync('git', ['-c', 'core.quotePath=false', ...args], {
    cwd,
    env: fileSetGitEnv(),
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (r.error === undefined && r.status === 0) return { ok: true, out: r.stdout };
  const stderr = typeof r.stderr === 'string' ? r.stderr.trim() : '';
  return {
    ok: false,
    detail: stderr.length > 0 ? stderr : String(r.error ?? `git exited with status ${String(r.status)}`),
  };
}

/**
 * Check the local git config, then resolve the repository, HEAD and the HEAD
 * tree. Throws {@link NoRepoControlsError} for every way that fails.
 */
export function loadHeadOnlyTree(startDir: string): HeadOnlyTree {
  // FIRST, before any other git call: a handed-over `.git/config` may name a
  // program, and every later call is a chance for git to run it.
  const verdict = checkLocalGitConfig(startDir, fileSetGitEnv());
  if (!verdict.ok) throw new NoRepoControlsError(localGitConfigRefusal(verdict, 'vault-guard'));

  const top = git(startDir, ['rev-parse', '--show-toplevel']);
  if (!top.ok || top.out.trim() === '') {
    throw new NoRepoControlsError(
      `vault-guard: --no-repo-controls needs a git work tree: ${top.ok ? 'git printed no toplevel' : top.detail}. ` +
        'Nothing was scanned.',
    );
  }
  let repoRoot = top.out.trim();
  try {
    repoRoot = fs.realpathSync.native(repoRoot);
  } catch {
    // Keep git's spelling.
  }
  assertOwnObjectStore(repoRoot);

  const head = git(repoRoot, ['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
  if (!head.ok || head.out.trim() === '') {
    throw new NoRepoControlsError(
      'vault-guard: --no-repo-controls judges the tree as at HEAD, and HEAD does not resolve to a ' +
        'commit here (a repository with no commit yet, or a broken HEAD). Nothing was scanned.',
    );
  }

  let entries: HeadTreeEntry[];
  try {
    entries = listHeadTreeEntries(repoRoot);
  } catch (e) {
    throw new NoRepoControlsError(e instanceof Error ? e.message : String(e));
  }
  const blobs = new Map<string, string>();
  const seen = new Set<string>();
  const submodules: string[] = [];
  for (const e of entries) {
    // Paths are decoded as UTF-8, so two raw names that are not valid UTF-8
    // can read as one, and a crafted tree can hold one name twice. Either
    // way one entry would silently replace the other in the scan's map, and
    // a key in the replaced one would never be read: refuse instead.
    const segments = e.path.split('/');
    const key = path.resolve(repoRoot, e.path);
    if (segments.some(s => s === '' || s === '.' || s === '..') || seen.has(key)) {
      throw new NoRepoControlsError(
        `vault-guard: the HEAD tree has entries that cannot be told apart, at ${JSON.stringify(e.path)}: ` +
          'two entries read as the same path (names that are not valid UTF-8, or a name listed twice), or a ' +
          'path with an empty, "." or ".." segment. Scanning it would judge one entry in place of another. ' +
          'Nothing was scanned.',
      );
    }
    seen.add(key);
    if (e.type === 'commit') submodules.push(e.path);
    if (e.type !== 'blob' || (e.mode !== '100644' && e.mode !== '100755')) continue;
    blobs.set(key, e.oid);
  }
  submodules.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { repoRoot, head: head.out.trim(), blobs, present: presentRepoControls(entries), submodules };
}

/**
 * Refuse a repository whose objects may come from somewhere else: a `.git`
 * that is not a directory (a `gitdir:` pointer file, or a link) names another
 * git directory, and `objects/info/alternates` or `http-alternates` makes git
 * read objects from another store. A fresh plain clone has neither, and the
 * remedy is the same as for an unknown config key.
 */
function assertOwnObjectStore(repoRoot: string): void {
  const dotGit = path.join(repoRoot, '.git');
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dotGit);
  } catch (e) {
    throw new NoRepoControlsError(
      `vault-guard: refusing to run: .git at the repository root cannot be examined ` +
        `(${(e as NodeJS.ErrnoException | undefined)?.code ?? 'error'}), so the git directory git uses may not be the ` +
        `repository's own. ${CLONE_FRESH} Nothing was scanned.`,
    );
  }
  if (!st.isDirectory()) {
    throw new NoRepoControlsError(
      'vault-guard: refusing to run: .git at the repository root is a file or a link, not a directory, so ' +
        `git reads this repository from another git directory (a worktree, a submodule, or a pointer). ${CLONE_FRESH} ` +
        'Nothing was scanned.',
    );
  }
  for (const name of ['alternates', 'http-alternates']) {
    const rel = `.git/objects/info/${name}`;
    let exists: boolean;
    try {
      fs.lstatSync(path.join(repoRoot, rel));
      exists = true;
    } catch (e) {
      // Only "not there" is a pass; a file that cannot be examined is not.
      exists = (e as NodeJS.ErrnoException | undefined)?.code !== 'ENOENT';
    }
    if (exists) {
      throw new NoRepoControlsError(
        `vault-guard: refusing to run: ${rel} exists, so git would read objects for this repository from ` +
          `another object store. ${CLONE_FRESH} Nothing was scanned.`,
      );
    }
  }
}
