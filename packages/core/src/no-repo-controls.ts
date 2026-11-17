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
 *  - The object store is not trusted to hold what its ids claim. The HEAD
 *    commit, every tree, and every blob the scan reads are hashed (git's own
 *    sha1 or sha256, by id length) and compared with the id they were asked
 *    for; a mismatch refuses the run. The file list comes from the verified
 *    raw trees (`utils/verified-head-tree.ts`), not from `ls-tree` output.
 *
 * The git calls are `config --local --list`, `rev-parse --show-toplevel`,
 * `rev-parse --git-common-dir` and `--git-path objects`, `rev-parse --verify
 * HEAD`, `ls-tree -r -t -z HEAD` (a hint of tree ids only), and
 * `cat-file --batch` (commit and trees, then the blobs) with
 * `cat-file --batch-check`.
 */

import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';

import { BASELINE_FILENAME } from './baseline';
import type { HeadTreeEntry } from './trust-base';
import { climbsOut } from './utils/dot-dot';
import { fileSetGitEnv } from './utils/git-env';
import { readVerifiedHeadTree } from './utils/verified-head-tree';
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

  const head = git(repoRoot, ['rev-parse', '--verify', '--quiet', 'HEAD']);
  if (!head.ok || head.out.trim() === '') {
    throw new NoRepoControlsError(
      'vault-guard: --no-repo-controls judges the tree as at HEAD, and HEAD does not resolve to a ' +
        'commit here (a repository with no commit yet, or a broken HEAD). Nothing was scanned.',
    );
  }

  let entries: HeadTreeEntry[];
  try {
    // From the raw commit and trees, each hashed against its id: nothing the
    // object store says about the tree is taken on trust.
    entries = readVerifiedHeadTree(repoRoot, head.out.trim());
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
    const key = headEntryKey(repoRoot, e.path);
    if (key === null || seen.has(key)) {
      throw new NoRepoControlsError(
        `vault-guard: the HEAD tree has entries that cannot be told apart, at ${JSON.stringify(e.path)}: ` +
          'two entries read as the same path (names that are not valid UTF-8, or a name listed twice), or a ' +
          'path with an empty, "." or ".." segment or that resolves outside the repository. Scanning it would ' +
          'judge one entry in place of another, or drop it. ' +
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
 * The absolute path a HEAD entry is scanned under, or null when the entry
 * name cannot be one: an empty, `.` or `..` segment (split on every separator
 * the platform accepts, so `..\x` counts on Windows), or a name that
 * resolves outside `repoRoot` at all (a name on another drive such as `D:x`, or a rooted
 * `\x` on Windows). Such an entry is refused, never dropped: a later
 * "is it inside the scan root?" check would otherwise skip it without a word.
 * `impl` is injectable so the Windows rules are tested on any host.
 */
export function headEntryKey(repoRoot: string, entryPath: string, impl: typeof path = path): string | null {
  const segments = impl.sep === '\\' ? entryPath.split(/[\\/]/) : entryPath.split('/');
  if (segments.some(s => s === '' || s === '.' || s === '..')) return null;
  const key = impl.resolve(repoRoot, entryPath);
  const rel = impl.relative(repoRoot, key);
  if (rel === '' || climbsOut(rel, impl) || impl.isAbsolute(rel)) return null;
  return key;
}

/** The refusal for a git directory that is not the repository's own. */
function notOwnStore(what: string): NoRepoControlsError {
  return new NoRepoControlsError(
    `vault-guard: refusing to run: ${what}, so git may read this repository's objects or config from ` +
      `somewhere a fresh plain clone does not. ${CLONE_FRESH} Nothing was scanned.`,
  );
}

/** lstat, or the error code; never throws. */
function lstatOrCode(p: string): fs.Stats | string {
  try {
    return fs.lstatSync(p);
  } catch (e) {
    return (e as NodeJS.ErrnoException | undefined)?.code ?? 'error';
  }
}

function realOrSelf(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/**
 * Refuse a repository whose git directory or object store may be somewhere
 * else (review of 02a563d, B4 and its re-check). The rule is structural, not
 * a list of known redirect files alone: the git directory must be the real
 * directory `<root>/.git`, the object store the real directory
 * `<root>/.git/objects` with no link anywhere inside it, and git itself must
 * agree on both paths.
 *
 *  - `.git` must be a directory, not a `gitdir:` pointer file or a link.
 *  - `.git/commondir` must not exist: it moves config, refs and objects to
 *    another git directory (a linked worktree has one; a fresh clone does not).
 *  - `.git/objects/info/alternates` and `http-alternates` must not exist.
 *  - `.git/objects` and every directory and file under it must be real: a link
 *    to a directory (`objects`, `objects/pack`, `objects/info`, a loose
 *    `objects/ab`) or to a pack or loose object would read objects from
 *    another store.
 *  - `git rev-parse --git-common-dir` and `--git-path objects`, run with the
 *    stripped environment, must resolve to `<root>/.git` and
 *    `<root>/.git/objects`.
 *
 * Refs (`refs/`, `packed-refs`, `HEAD`) are not checked: wherever a ref is
 * read from, the commit it names must be in this store, so it can only pick
 * a commit the repository already holds, and the report names that commit.
 */
function assertOwnObjectStore(repoRoot: string): void {
  const dotGit = path.join(repoRoot, '.git');
  const st = lstatOrCode(dotGit);
  if (typeof st === 'string') {
    throw notOwnStore(`.git at the repository root cannot be examined (${st})`);
  }
  if (!st.isDirectory()) {
    throw notOwnStore(
      '.git at the repository root is a file or a link, not a directory (a worktree, a submodule, or a pointer)',
    );
  }
  const commondir = lstatOrCode(path.join(dotGit, 'commondir'));
  if (commondir !== 'ENOENT') {
    throw notOwnStore('.git/commondir exists (or cannot be examined): it points git at another git directory');
  }
  for (const name of ['alternates', 'http-alternates']) {
    const rel = `.git/objects/info/${name}`;
    const a = lstatOrCode(path.join(repoRoot, rel));
    if (a !== 'ENOENT') {
      throw notOwnStore(`${rel} exists (or cannot be examined): git would read objects from another object store`);
    }
  }
  const objects = path.join(dotGit, 'objects');
  assertNoLinkIn(objects, '.git/objects');

  const common = git(repoRoot, ['rev-parse', '--git-common-dir']);
  const objPath = git(repoRoot, ['rev-parse', '--git-path', 'objects']);
  if (!common.ok || !objPath.ok) {
    throw notOwnStore(`git could not name its git directory (${!common.ok ? common.detail : !objPath.ok ? objPath.detail : ''})`);
  }
  const resolvedCommon = realOrSelf(path.resolve(repoRoot, common.out.trim()));
  const resolvedObjects = realOrSelf(path.resolve(repoRoot, objPath.out.trim()));
  if (resolvedCommon !== realOrSelf(dotGit)) {
    throw notOwnStore("git's common git directory is not .git at the repository root");
  }
  if (resolvedObjects !== realOrSelf(objects)) {
    throw notOwnStore("git's object directory is not .git/objects at the repository root");
  }
}

/** A path for a message: the first 200 characters and the full length, so a deep nest stays one line. */
function shown(p: string): string {
  return p.length <= 200 ? p : `${p.slice(0, 200)}... (${p.length} characters)`;
}

/**
 * Walk `dir` with lstat and refuse on anything that is not a real directory
 * or a regular file, the directory itself included. A fresh clone's object
 * store holds only directories and regular files.
 */
function assertNoLinkIn(dir: string, label: string): void {
  const top = lstatOrCode(dir);
  if (typeof top === 'string') throw notOwnStore(`${label} cannot be examined (${top})`);
  if (!top.isDirectory()) throw notOwnStore(`${label} is not a real directory (a link or a file)`);
  const stack: Array<{ abs: string; rel: string }> = [{ abs: dir, rel: label }];
  while (stack.length > 0) {
    const { abs, rel } = stack.pop() as { abs: string; rel: string };
    let names: string[];
    try {
      names = fs.readdirSync(abs);
    } catch (e) {
      throw notOwnStore(`${shown(rel)} cannot be read (${(e as NodeJS.ErrnoException | undefined)?.code ?? 'error'})`);
    }
    for (const name of names) {
      const childAbs = path.join(abs, name);
      const childRel = `${rel}/${name}`;
      const c = lstatOrCode(childAbs);
      if (typeof c === 'string') throw notOwnStore(`${shown(childRel)} cannot be examined (${c})`);
      if (c.isDirectory()) stack.push({ abs: childAbs, rel: childRel });
      else if (!c.isFile()) throw notOwnStore(`${shown(childRel)} is a link or a special file, not a regular file`);
    }
  }
}
