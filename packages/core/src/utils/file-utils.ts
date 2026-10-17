import { spawnSync } from 'child_process';
import fs, { promises as fsPromises } from 'fs';
import path from 'path';
import ignore from 'ignore';

import { DiagnosticBus } from '../diagnostics';
import { GitError } from '../errors';
import { inspectWorktree, wantsWorktreeCopy, type TrackedEntry } from './content-source';
import { fileSetGitEnv } from './git-env';

/**
 * Build a filter from `config.ignore.paths` / `config.ignore.patterns` entries.
 *
 * Patterns follow gitignore syntax (handled by the `ignore` package). Paths are
 * matched against file paths relative to `root` so that patterns like
 * `packages/**\/__tests__\/**` work as expected from the repo root.
 *
 * @returns A predicate that returns `true` when a file should be **excluded**.
 */
export function buildConfigIgnoreFilter(
  patterns: string[],
  root: string,
): (filePath: string) => boolean {
  if (patterns.length === 0) return () => false;
  const ig = ignore().add(patterns);
  return (filePath: string): boolean => {
    const rel = path.relative(root, path.resolve(filePath)).split(path.sep).join('/');
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return false;
    return ig.ignores(rel);
  };
}

const GITIGNORE_CACHE_MAX = 32;

type CachedIgnoreFilter = {
  lastUsed: number;
  /** Returns true if `filePath` should be excluded by `.gitignore` rules. */
  tester: (filePath: string) => boolean;
  /** Absolute paths of `.gitignore` files whose mtimes are tracked. */
  watchPaths: string[];
  /** Expected `mtimeMs` for each path in `watchPaths` (same order). */
  mtimesMs: number[];
};

const gitignoreCache = new Map<string, CachedIgnoreFilter>();

/**
 * Drop all cached `.gitignore` matchers. Call after long-lived processes
 * detect an out-of-band change that `mtime` cannot observe, or in tests.
 */
export function clearGitignoreCache(): void {
  gitignoreCache.clear();
}

function touchCache(key: string, entry: CachedIgnoreFilter): void {
  gitignoreCache.delete(key);
  gitignoreCache.set(key, { ...entry, lastUsed: Date.now() });
  while (gitignoreCache.size > GITIGNORE_CACHE_MAX) {
    const oldest = gitignoreCache.keys().next().value;
    if (oldest === undefined) break;
    gitignoreCache.delete(oldest);
  }
}

function isStale(entry: CachedIgnoreFilter): boolean {
  for (let i = 0; i < entry.watchPaths.length; i++) {
    const p = entry.watchPaths[i];
    const expected = entry.mtimesMs[i];
    try {
      if (fs.statSync(p).mtimeMs !== expected) return true;
    } catch {
      return true;
    }
  }
  return false;
}

function findGitRoot(startDir: string): string | null {
  let dir = path.resolve(startDir);
  while (true) {
    if (fs.existsSync(path.join(dir, '.git'))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/**
 * The nearest directory at or above `startDir` that holds a `.git` entry
 * (a directory, or a file in a worktree or submodule), or null. Its presence,
 * not an answer from git, is what decides that a path is inside git.
 */
export function findGitEntryRoot(startDir: string): string | null {
  return findGitRoot(startDir);
}

function filesystemRootFor(resolvedPath: string): string {
  return path.parse(resolvedPath).root;
}

interface GitignoreChainEntry {
  readonly dir: string;
  readonly absGitignore: string;
  readonly content: string;
}

/** Prefix a single `.gitignore` line for rules defined in a subdirectory. */
function qualifyGitignoreLine(line: string, posixPrefix: string): string {
  if (!posixPrefix) return line;
  const trimmed = line.trimEnd();
  if (!trimmed || trimmed.startsWith('#')) return line;

  const neg = trimmed.startsWith('!');
  const body = neg ? trimmed.slice(1) : trimmed;
  if (!body) return line;

  let out: string;
  if (body.startsWith('/')) {
    out = `${posixPrefix}${body}`;
  } else if (body.includes('/')) {
    out = `${posixPrefix}/${body}`;
  } else {
    out = `${posixPrefix}/**/${body}`;
  }
  return neg ? `!${out}` : out;
}

function qualifyGitignoreContent(content: string, posixPrefix: string): string {
  if (!posixPrefix) return content;
  return content.split('\n').map(l => qualifyGitignoreLine(l, posixPrefix)).join('\n');
}

/**
 * Walk upward from `resolvedScan` through `stopAt` (inclusive), collect each
 * `.gitignore`, then return entries in shallow-to-deep order for merging.
 */
function collectGitignoreChain(resolvedScan: string, stopAt: string): GitignoreChainEntry[] {
  const stop = path.resolve(stopAt);
  const raw: GitignoreChainEntry[] = [];
  let dir = path.resolve(resolvedScan);

  while (true) {
    const absGitignore = path.join(dir, '.gitignore');
    if (fs.existsSync(absGitignore)) {
      try {
        raw.push({
          dir,
          absGitignore,
          content: fs.readFileSync(absGitignore, 'utf-8'),
        });
      } catch {
        /* unreadable .gitignore -- treat as absent */
      }
    }
    if (dir === stop) break;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  raw.reverse();
  return raw;
}

/**
 * Recursively discover `.gitignore` files inside `root` (inclusive of `root`
 * itself), skipping directories the walk never descends into anyway
 * ({@link shouldIgnoreDirectory}) so this pre-pass stays cheap. Scanning from
 * an ancestor of a nested `.gitignore` (e.g. `vault-guard scan .` in a repo
 * with a per-package `.gitignore`) otherwise never sees that file: the ignore
 * filter was only ever built from ancestors of the scan root, not descendants.
 */
function collectDescendantGitignores(root: string): GitignoreChainEntry[] {
  const found: GitignoreChainEntry[] = [];
  const stack: string[] = [root];

  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (shouldIgnoreDirectory(entry.name)) continue;
        stack.push(full);
      } else if (entry.isFile() && entry.name === '.gitignore') {
        try {
          found.push({ dir, absGitignore: full, content: fs.readFileSync(full, 'utf-8') });
        } catch {
          /* unreadable .gitignore -- treat as absent */
        }
      }
    }
  }

  // Shallow-to-deep, matching collectGitignoreChain's ordering, so more
  // specific nested rules are added (and can override) after broader ones.
  found.sort((a, b) => a.dir.split(path.sep).length - b.dir.split(path.sep).length);
  return found;
}

function buildIgnoreFilter(resolvedScanRoot: string): CachedIgnoreFilter {
  const gitRoot = findGitRoot(resolvedScanRoot);
  const stopAt = gitRoot ?? filesystemRootFor(resolvedScanRoot);
  const ancestorChain = collectGitignoreChain(resolvedScanRoot, stopAt);
  const seen = new Set(ancestorChain.map(c => c.absGitignore));
  const descendantChain = collectDescendantGitignores(resolvedScanRoot).filter(
    c => !seen.has(c.absGitignore),
  );
  const chain = [...ancestorChain, ...descendantChain];

  const ig = ignore();
  for (const { dir, content } of chain) {
    const relDir = path.relative(stopAt, dir).split(path.sep).join('/');
    const posixPrefix = relDir === '' || relDir === '.' ? '' : relDir;
    ig.add(qualifyGitignoreContent(content, posixPrefix));
  }

  const watchPaths = chain.map(c => c.absGitignore);
  const mtimesMs = watchPaths.map(p => {
    try {
      return fs.statSync(p).mtimeMs;
    } catch {
      return -1;
    }
  });

  const tester = (filePath: string): boolean => {
    const rel = path.relative(stopAt, path.resolve(filePath)).split(path.sep).join('/');
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      return false;
    }
    const posixPath = rel === '' ? '.' : rel;
    return ig.ignores(posixPath);
  };

  return {
    lastUsed: Date.now(),
    tester,
    watchPaths,
    mtimesMs,
  };
}

function getGitignoreTester(scanRoot: string): (filePath: string) => boolean {
  const key = path.resolve(scanRoot);
  const hit = gitignoreCache.get(key);
  if (hit && !isStale(hit)) {
    touchCache(key, hit);
    return hit.tester;
  }
  const built = buildIgnoreFilter(key);
  touchCache(key, built);
  return built.tester;
}

/**
 * Get all files in directory recursively (async version)
 */
export async function getAllFilesAsync(
  dirPath: string,
  visited = new Set<string>(),
  verbose = false,
  bus?: DiagnosticBus,
  counts?: ScanSkipCounts,
  /**
   * Where the verbose walk warnings go. The CLI collects them so that, on a
   * run that cannot complete, the INCOMPLETE line is the first thing on
   * stderr (design 2026-10-17, section 7). Defaults to `console.error`.
   */
  warn?: WalkWarn,
): Promise<string[]> {
  const files: string[] = [];

  try {
    try {
      await fsPromises.access(dirPath);
    } catch {
      if (bus) {
        bus.add({
          code: 'fs.permission_denied',
          severity: 'warning',
          ctx: { dir: dirPath },
        });
      }
      return files;
    }

    const realPath = fs.realpathSync(dirPath);
    if (visited.has(realPath)) {
      return files;
    }
    visited.add(realPath);

    const items = await fsPromises.readdir(dirPath);

    for (const item of items) {
      try {
        const fullPath = path.join(dirPath, item);
        const lstat = await fsPromises.lstat(fullPath);

        if (lstat.isSymbolicLink()) {
          continue;
        }

        if (lstat.isDirectory() && !shouldIgnoreDirectory(item)) {
          const subFiles = await getAllFilesAsync(fullPath, visited, verbose, bus, counts, warn);
          files.push(...subFiles);
        } else if (lstat.isFile()) {
          if (shouldIgnoreFile(fullPath)) {
            if (counts) counts.typeFiltered++;
          } else {
            files.push(fullPath);
          }
        }
      } catch (error) {
        if (bus) {
          bus.add({
            code: 'fs.permission_denied',
            severity: 'warning',
            ctx: { path: path.join(dirPath, item), detail: String(error) },
          });
        }
        if (verbose) walkWarn(warn, `Warning: Cannot access ${path.join(dirPath, item)}:`, error);
      }
    }
  } catch (error) {
    if (bus) {
      bus.add({
        code: 'fs.permission_denied',
        severity: 'warning',
        ctx: { dir: dirPath, detail: String(error) },
      });
    }
    if (verbose) walkWarn(warn, `Warning: Cannot read directory ${dirPath}:`, error);
  }

  return files;
}

/** A sink for one line of walk output on stderr. */
export type WalkWarn = (line: string) => void;

function walkWarn(warn: WalkWarn | undefined, message: string, error: unknown): void {
  if (warn) warn(`${message} ${String(error)}`);
  else console.error(message, error);
}

/**
 * Get all files in directory recursively (sync version for backwards compatibility)
 */
export function getAllFiles(
  dirPath: string,
  visited = new Set<string>(),
  verbose = false,
  bus?: DiagnosticBus,
): string[] {
  const files: string[] = [];

  try {
    if (!fs.existsSync(dirPath)) {
      if (bus) {
        bus.add({
          code: 'fs.permission_denied',
          severity: 'warning',
          ctx: { dir: dirPath },
        });
      }
      return files;
    }

    const realPath = fs.realpathSync(dirPath);
    if (visited.has(realPath)) {
      return files;
    }
    visited.add(realPath);

    const items = fs.readdirSync(dirPath);

    for (const item of items) {
      try {
        const fullPath = path.join(dirPath, item);
        const lstat = fs.lstatSync(fullPath);

        if (lstat.isSymbolicLink()) {
          continue;
        }

        if (lstat.isDirectory() && !shouldIgnoreDirectory(item)) {
          files.push(...getAllFiles(fullPath, visited, verbose, bus));
        } else if (lstat.isFile() && !shouldIgnoreFile(fullPath)) {
          files.push(fullPath);
        }
      } catch (error) {
        if (bus) {
          bus.add({
            code: 'fs.permission_denied',
            severity: 'warning',
            ctx: { path: path.join(dirPath, item), detail: String(error) },
          });
        }
        if (verbose) {
          console.error(`Warning: Cannot access ${path.join(dirPath, item)}:`, error);
        }
      }
    }
  } catch (error) {
    if (bus) {
      bus.add({
        code: 'fs.permission_denied',
        severity: 'warning',
        ctx: { dir: dirPath, detail: String(error) },
      });
    }
    if (verbose) {
      console.error(`Warning: Cannot read directory ${dirPath}:`, error);
    }
  }

  return files;
}

/**
 * What a plain directory scan's file set was built from, and what it found
 * along the way that the run has to state. Filled by
 * {@link getFilesToScanAsync}; one object may be shared across several
 * directory targets, and the sets accumulate.
 *
 * Every path is absolute and expressed under the target as the caller gave it
 * (not symlink-resolved), the same namespace the returned file list uses.
 */
export interface PlainFileSetInfo {
  /**
   * `git` when every directory target was inside a git work tree, `walk` when
   * any was not. Undefined until a directory target has been built.
   */
  fileSet?: 'git' | 'walk';
  /**
   * Paths tracked by the OUTER repository's own index (before any filtering).
   * Files of a submodule or an untracked nested repository are scanned but are
   * not in this set: the baseline writer accepts findings only in files the
   * repository it writes into has committed.
   */
  trackedFiles: Set<string>;
  /** Tracked paths that `.gitignore` matches. */
  trackedIgnored: Set<string>;
  /** Tracked paths kept although they sit under a nested vendored directory name. */
  trackedNestedVendored: Set<string>;
  /**
   * Tracked paths absent from the work tree: listed by `git ls-files --deleted`
   * or marked skip-worktree by a sparse checkout, AND failing `lstat` with
   * ENOENT or ENOTDIR. Counted, not fatal.
   */
  trackedMissing: string[];
  /** Vendored names skipped as a direct child of the scan root in the tracked half. */
  vendoredDirNames: Set<string>;
  /**
   * Tracked paths that could not be examined on disk for any other reason. The
   * caller must fail closed on these (exit 2), exactly as pull-request mode does.
   */
  unreadable: Array<{ file: string; reason: string }>;
  /**
   * Where each tracked file in the returned list is read from: its index blob
   * (design 2026-10-12, section 2), keyed by the path as returned. Untracked
   * files are absent and are read from disk.
   */
  blobs: Map<string, TrackedEntry>;
  /** Tracked paths whose disk copy is scanned as well as the blob (2.4). */
  worktreeAlso: Set<string>;
}

/** A fresh, empty {@link PlainFileSetInfo}. */
export function newPlainFileSetInfo(): PlainFileSetInfo {
  return {
    trackedFiles: new Set(),
    trackedIgnored: new Set(),
    trackedNestedVendored: new Set(),
    trackedMissing: [],
    vendoredDirNames: new Set(),
    unreadable: [],
    blobs: new Map(),
    worktreeAlso: new Set(),
  };
}

function noteFileSet(info: PlainFileSetInfo | undefined, kind: 'git' | 'walk'): void {
  if (!info) return;
  info.fileSet = info.fileSet === undefined || info.fileSet === kind ? kind : 'walk';
}

/**
 * Get files to scan (filters out ignored directories/files) - async version
 *
 * INSIDE A GIT WORK TREE the set comes from git: tracked files plus untracked
 * files that `.gitignore` does not exclude (see {@link getGitFilesToScan}). A
 * tracked file is scanned whatever `.gitignore` says, because `.gitignore`
 * governs what git will add and says nothing about a file already committed.
 * Whether the target is inside git is decided by the presence of a `.git`
 * entry, never by asking git: once one is found, any git failure throws
 * {@link GitError} rather than quietly falling back to the walk, which would
 * bring back exactly the gap this closes.
 *
 * OUTSIDE GIT the filesystem walk and the gitignore tester run as before.
 *
 * @param configIgnorePatterns - gitignore-style patterns from `config.ignore.paths`
 *   / `config.ignore.patterns`. Matched relative to `targetPath`.
 * @param info - filled with what the run must report about the file set. A
 *   caller that does not pass one cannot see tracked files that could not be
 *   examined, so every caller that can fail closed should pass one.
 */
export async function getFilesToScanAsync(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
  configIgnorePatterns: string[] = [],
  counts?: ScanSkipCounts,
  info?: PlainFileSetInfo,
  /** Where verbose walk warnings go; `console.error` when absent. */
  warn?: WalkWarn,
): Promise<string[]> {
  if (findGitRoot(targetPath) !== null) {
    noteFileSet(info, 'git');
    return getGitFilesToScan(targetPath, configIgnorePatterns, counts, info ?? newPlainFileSetInfo(), bus);
  }
  noteFileSet(info, 'walk');
  const allFiles = await getAllFilesAsync(targetPath, new Set(), verbose, bus, counts, warn);
  const gitignoreTester = getGitignoreTester(targetPath);
  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, targetPath);
  const out: string[] = [];
  for (const file of allFiles) {
    if (shouldIgnoreFile(file, gitignoreTester)) continue;
    if (configIgnoreTester(file)) {
      if (counts) counts.configIgnored++;
      continue;
    }
    out.push(file);
  }
  return out;
}

/**
 * Tallies of what a walk declined to look at, filled by the file-set builders.
 * Reported rather than silent: a file the run did not open is a decision made
 * on the user's behalf.
 */
export interface ScanSkipCounts {
  /** Files dropped by the extension, lockfile-name and generated-artifact filters. */
  typeFiltered: number;
  /** Files dropped by the config's own `ignore` list: a declared skip. */
  configIgnored: number;
}

/**
 * Get files to scan (filters out ignored directories/files) - sync version
 *
 * @param configIgnorePatterns - gitignore-style patterns from `config.ignore.paths`
 *   / `config.ignore.patterns`. Matched relative to `targetPath`.
 */
export function getFilesToScan(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
  configIgnorePatterns: string[] = [],
): string[] {
  const allFiles = getAllFiles(targetPath, new Set(), verbose, bus);
  const gitignoreTester = getGitignoreTester(targetPath);
  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, targetPath);
  return allFiles.filter(
    file => !shouldIgnoreFile(file, gitignoreTester) && !configIgnoreTester(file),
  );
}

/**
 * What a pull-request run declined to look at, and how much of it there was.
 *
 * Reported rather than silent for the same reason every suppression in this
 * tool is reported: something the scanner declined to look at is a decision the
 * run made on the user's behalf, and a run that makes it invisibly manufactures
 * confidence it has not earned.
 */
export interface PullRequestSkips {
  /** Directories skipped by name at the scan root. */
  dirCount: number;
  /** Those directory names, for a one-line summary. */
  dirNames: string[];
  /**
   * Files in the head tree dropped by the extension, lockfile-name and
   * generated-artifact filters.
   *
   * Counted because those filters are silent mutes of the same shape as the
   * ones this mode exists to close: a key committed as `src/leak.min.js` or
   * `src/leak.lock` is skipped on its name alone, and the run used to say
   * nothing at all about it. What gets skipped is unchanged; that something
   * was is now visible.
   */
  typeFilteredFiles: number;
  /**
   * Files dropped by the config's `ignore` list, which in this mode is the BASE
   * ref's. A declared skip, counted so a reader sees how much the written
   * decision covered.
   */
  configIgnoredFiles?: number;
  /**
   * Files in the head tree that could not be examined on disk (a directory that
   * cannot be entered, a file missing from the checkout). Each is a file the run
   * did not check, so the caller must fail closed on them. `code` is the
   * `lstat` errno code, when there was one.
   */
  unreadable?: Array<{ file: string; reason: string; code?: string }>;
  /**
   * Files kept although a directory above them, below the scan root, carries a
   * vendored name (`src/vendor/k.js`). The walk used to skip these at any
   * depth; they are scanned, and counted so the run can say so.
   */
  nestedVendored?: string[];
}

/**
 * The file set for a pull-request run: the head tree, filtered like the walk.
 *
 * Two things are deliberately different from {@link getFilesToScan}, and both
 * of them close a way a pull request could mute the scanner in the same commit
 * that carried a secret.
 *
 * FIRST, THE SET COMES FROM GIT, NOT FROM `.gitignore`. The ordinary walk asks
 * the gitignore tester whether to skip each file, which means a `.gitignore`
 * the pull request itself added decides what the pull request is scanned on. A
 * `src/.gitignore` containing the name of the file the key sits in was enough,
 * measured, to turn exit 1 into exit 0. A file already in the head tree cannot
 * be muted that way: `.gitignore` governs what git will ADD and says nothing
 * about a file already committed. The tester stays in place for the untracked
 * working-tree scans that have no flag, where it is doing an honest job.
 *
 * SECOND, THE VENDORED-DIRECTORY NAMES ARE ANCHORED TO THE SCAN ROOT. The walk
 * skips any directory called `vendor`, `venv`, `dist` and so on at any depth,
 * which a pull request can satisfy by committing its key to `src/vendor/`. Here
 * only a direct child of the scan root can be skipped by name, so a committed
 * `src/vendor/` is scanned. Anchoring is safe here precisely because the set is
 * the head tree: a nested `node_modules` is not committed, so nothing is gained
 * by pretending to skip it and no cost is paid for walking it, since there is
 * no walk.
 *
 * Everything else is the walk's own filtering, applied to the same paths:
 * binaries and lockfiles by extension and name, generated artifacts, the
 * config's own `ignore` patterns (from the BASE ref, in this mode), and
 * anything that is not a regular file on disk. Those name-and-extension drops
 * are COUNTED into {@link PullRequestSkips.typeFilteredFiles}: what they skip
 * is unchanged, but `src/leak.min.js` used to disappear without the run saying
 * so, which is the same silence this mode exists to remove.
 */
export function getPullRequestFilesToScan(
  targetPath: string,
  headTreeFiles: Iterable<string>,
  configIgnorePatterns: string[] = [],
  skipped: PullRequestSkips = { dirCount: 0, dirNames: [], typeFilteredFiles: 0 },
): string[] {
  const target = path.resolve(targetPath);
  const targetIsDirectory = (() => {
    try {
      return fs.statSync(target).isDirectory();
    } catch {
      return true;
    }
  })();

  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, target);
  const skippedNames = new Set<string>();
  let typeFiltered = 0;
  let configIgnored = 0;
  const unreadable: Array<{ file: string; reason: string; code?: string }> = [];
  const nestedVendored: string[] = [];
  const out: string[] = [];

  for (const file of headTreeFiles) {
    const abs = path.resolve(file);
    let underNestedVendored = false;

    if (!targetIsDirectory) {
      if (abs !== target) continue;
    } else {
      const rel = path.relative(target, abs);
      if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) continue;
      const segments = rel.split(path.sep);
      // Anchored: only a direct child of the scan root is skipped by name.
      if (segments.length > 1 && shouldIgnoreDirectory(segments[0])) {
        skippedNames.add(segments[0]);
        continue;
      }
      underNestedVendored = segments.slice(1, -1).some(shouldIgnoreDirectory);
    }

    // No gitignore tester: see the note above. The rest of the walk's file
    // filtering still applies, and is counted.
    if (shouldIgnoreFile(abs)) {
      typeFiltered++;
      continue;
    }
    // A config `ignore` pattern is the project's own written decision, and it
    // comes from the BASE ref in this mode (a head that changed it is reported
    // as a proposal). It is counted apart from the type filter above, which is
    // for the skips nobody wrote down.
    if (configIgnoreTester(abs)) {
      configIgnored++;
      continue;
    }

    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(abs);
    } catch (error) {
      // In the head tree but not examinable on disk: a directory above it that
      // cannot be entered, or a file missing from the checkout. A tracked file
      // nobody could look at is exactly the file nobody checked, so it is
      // reported to the caller, which exits 2 over it.
      const code = (error as NodeJS.ErrnoException | undefined)?.code;
      unreadable.push({ file: abs, reason: String(error), ...(code ? { code } : {}) });
      continue;
    }
    if (!stat.isFile()) continue;

    if (underNestedVendored) nestedVendored.push(abs);
    out.push(abs);
  }

  skipped.dirNames = [...skippedNames].sort();
  skipped.dirCount = skipped.dirNames.length;
  skipped.typeFilteredFiles = typeFiltered;
  skipped.configIgnoredFiles = configIgnored;
  skipped.unreadable = unreadable;
  skipped.nestedVendored = nestedVendored;
  return out;
}

/** Resolve symlinks; fall back to the input when that is not possible. */
function canonicalPath(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/**
 * Run git for the plain file set. Throws {@link GitError} quoting git's own
 * stderr: a `.git` was found, so the file set must come from git, and a run
 * that cannot get it has not established anything about the tree.
 */
function runFileSetGit(cwd: string, args: string[], bus?: DiagnosticBus): string {
  const argv = ['-c', 'core.quotePath=false', ...args];
  const r = spawnSync('git', argv, {
    cwd,
    env: fileSetGitEnv(),
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 512 * 1024 * 1024,
  });
  const stderr = typeof r.stderr === 'string' ? r.stderr.trim() : '';
  if (r.error === undefined && r.status === 0) {
    // git exits 0 over an untracked directory it could not open and says so
    // on stderr only. The walk reported that as a warning; so does this.
    for (const line of stderr.split('\n').map(l => l.trim()).filter(Boolean)) {
      bus?.add({
        code: /permission denied/i.test(line) ? 'fs.permission_denied' : 'git.warning',
        severity: 'warning',
        ctx: { dir: cwd, detail: line },
      });
    }
    return r.stdout;
  }
  {
    const err = r.error ?? new Error(`git exited with status ${String(r.status)}`);
    const detail = stderr.length > 0 ? stderr : String(err);
    throw new GitError(
      `vault-guard: ${cwd} is inside a git repository (a .git entry was found), so the ` +
        `file set has to come from git, and git failed: ${detail}\n` +
        'Nothing was scanned. Fix the git error above; vault-guard does not fall back ' +
        'to walking the directory, because that walk skips tracked files that ' +
        '.gitignore matches.',
      `git ${argv.join(' ')}`,
      err,
    );
  }
}

/**
 * Tracked files under `repoRoot` that `.gitignore` matches, as absolute paths
 * resolved against `repoRoot`. Pull-request mode reports how many of these it
 * scanned, as a plain scan inside git does. Throws {@link GitError} on failure.
 */
export function listTrackedIgnoredFiles(repoRoot: string): Set<string> {
  const out = runFileSetGit(repoRoot, [
    'ls-files', '-z', '--cached', '--ignored', '--exclude-per-directory=.gitignore', '--', ':(literal).',
  ]);
  return new Set(splitZ(out).map(p => path.resolve(repoRoot, p)));
}

/** NUL-separated git output into entries, without trimming. */
function splitZ(out: string): string[] {
  return out.split('\0').filter(s => s.length > 0);
}

/** The pieces the git file set is assembled from, as symlink-resolved absolute paths. */
interface GitPathLists {
  tracked: Set<string>;
  /** The subset of `tracked` in the OUTER repository's own index. */
  outerTracked: Set<string>;
  sparse: Set<string>;
  deleted: Set<string>;
  ignoredTracked: Set<string>;
  untracked: Set<string>;
  /** Where each tracked path's content is read from, keyed by the canonical path. */
  entries: Map<string, TrackedEntry>;
  /** The first `git status` column of each tracked path that has one. */
  indexColumn: Map<string, string>;
}

/**
 * List one repository's part of the file set under `dir`, and recurse into
 * every checked-out submodule and every untracked nested repository below it.
 *
 * git runs at the toplevel `rev-parse --show-toplevel` reports for `dir`, with
 * `dir` passed as a root-relative `:(literal)` pathspec so a directory named
 * `[x]` or `:x` is that directory and never a glob or pathspec magic. Both
 * sides are symlink-resolved before `path.relative`, because git reports the
 * physical toplevel.
 */
function collectGitPaths(
  dir: string,
  out: GitPathLists,
  visitedRepos: Set<string>,
  skipNestedRepo: (dirAbs: string) => boolean,
  bus: DiagnosticBus | undefined,
  outer: boolean,
): void {
  const git = (cwd: string, args: string[]): string => runFileSetGit(cwd, args, bus);
  const top = canonicalPath(git(dir, ['rev-parse', '--show-toplevel']).trim());
  if (visitedRepos.has(`${top}\0${dir}`)) return;
  visitedRepos.add(`${top}\0${dir}`);
  const rel = path.relative(top, dir).split(path.sep).join('/');
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new GitError(
      `vault-guard: ${dir} is not inside the git work tree git reported for it (${top}). ` +
        'Nothing was scanned.',
      'git rev-parse --show-toplevel',
    );
  }
  const spec = `:(literal)${rel === '' ? '.' : rel}`;
  const abs = (p: string): string => path.resolve(top, p);

  // `-s -v`: `<tag> <mode> <object> <stage>\t<path>`. The tag says whether a
  // sparse checkout left the path out (S, or s), and is lowercase for an
  // assume-unchanged entry; the mode says whether it is a gitlink; the object
  // is the blob the content is read from. A path in conflict is listed once
  // per stage (1 to 3, no stage 0): de-duplicated here, stages 2 and 3 kept.
  const repoRel: string[] = [];
  const tags = new Map<string, string>();
  for (const record of splitZ(git(top, ['ls-files', '-z', '-s', '-v', '--cached', '--', spec]))) {
    const tab = record.indexOf('\t');
    if (tab === -1) continue;
    const [tag, mode, oid, stage] = record.slice(0, tab).split(' ');
    const rel = record.slice(tab + 1);
    const file = abs(rel);
    if (mode === '160000') {
      // A submodule. The walk used to descend into a checked-out one, so the
      // same rule is applied inside it; an uninitialised one has no files.
      if (fs.existsSync(path.join(file, '.git'))) {
        collectGitPaths(file, out, visitedRepos, skipNestedRepo, bus, false);
      }
      continue;
    }
    if (!out.tracked.has(file)) repoRel.push(rel);
    out.tracked.add(file);
    // Only the outer repository's own index is "committed here". Files of a
    // submodule or a nested repository are scanned, but they are another
    // repository's history, and the baseline writer must not name them.
    if (outer) out.outerTracked.add(file);
    if (tag === 'S' || tag === 's') out.sparse.add(file);
    tags.set(rel, tag);
    const entry = out.entries.get(file) ?? { repoTop: top, mode, worktreeAlso: false, filtered: false };
    if (stage === '0') entry.oid = oid;
    else if (stage === '2') entry.ours = oid;
    else if (stage === '3') entry.theirs = oid;
    out.entries.set(file, entry);
  }

  // Where each tracked file's content comes from (design 2026-10-12, 2.4):
  // one status and one check-attr for this repository, never one per file.
  const inspection = inspectWorktree(top, spec, repoRel, fileSetGitEnv());
  for (const rel of repoRel) {
    const file = abs(rel);
    const entry = out.entries.get(file);
    if (!entry) continue;
    const attrs = inspection.attrs.get(rel) ?? { filter: false };
    const xy = inspection.status.get(rel);
    if (xy !== undefined && xy[0] !== ' ') out.indexColumn.set(file, xy[0]);
    entry.filtered = attrs.filter;
    if (attrs.encoding !== undefined) entry.encoding = attrs.encoding;
    // A conflicted path: stage 2 and 3 blobs, plus the disk copy holding the
    // conflict markers.
    entry.worktreeAlso =
      entry.oid === undefined || wantsWorktreeCopy('index', xy, tags.get(rel), attrs.filter);
  }

  for (const p of splitZ(git(top, ['ls-files', '-z', '--deleted', '--', spec]))) {
    out.deleted.add(abs(p));
  }

  for (const p of splitZ(
    git(top, [
      'ls-files', '-z', '--cached', '--ignored', '--exclude-per-directory=.gitignore', '--', spec,
    ]),
  )) {
    out.ignoredTracked.add(abs(p));
  }

  for (const p of splitZ(
    git(top, ['ls-files', '-z', '--others', '--exclude-per-directory=.gitignore', '--', spec]),
  )) {
    if (p.endsWith('/')) {
      // git lists an untracked nested repository as one `dir/` entry and stops.
      const nested = abs(p.slice(0, -1));
      if (fs.existsSync(path.join(nested, '.git')) && !skipNestedRepo(nested)) {
        collectGitPaths(nested, out, visitedRepos, skipNestedRepo, bus, false);
      }
      continue;
    }
    out.untracked.add(abs(p));
  }
}

/**
 * The plain-scan file set inside git: tracked files plus untracked files that
 * `.gitignore` does not exclude.
 *
 * THE TRACKED HALF goes through {@link getPullRequestFilesToScan} unchanged:
 * vendored names anchored to the scan root, the counted type filter, the
 * counted config `ignore` (the working tree's, as plain mode always used), and
 * `lstat`/`isFile`, so symlinks are never followed. Plain mode and
 * pull-request mode therefore build their tracked set with the same function.
 *
 * THE UNTRACKED HALF keeps the walk's own filtering: vendored names at ANY
 * depth (an untracked `packages/x/node_modules` stays out), the type filter
 * and the config `ignore`.
 *
 * `.gitignore` is the only exclude source (`--exclude-per-directory`), not
 * `--exclude-standard`: the file set must not depend on `.git/info/exclude` or
 * on a per-machine global excludes file.
 */
function getGitFilesToScan(
  targetPath: string,
  configIgnorePatterns: string[],
  counts: ScanSkipCounts | undefined,
  info: PlainFileSetInfo,
  bus?: DiagnosticBus,
): string[] {
  const givenTarget = path.resolve(targetPath);
  const canonTarget = canonicalPath(givenTarget);
  const toGiven = (canon: string): string | null => {
    const rel = path.relative(canonTarget, canon);
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return null;
    return path.join(givenTarget, rel);
  };
  const isUnderVendoredName = (canon: string, includeLast: boolean): boolean => {
    const rel = path.relative(canonTarget, canon);
    const segments = rel.split(path.sep);
    const dirs = includeLast ? segments : segments.slice(0, -1);
    return dirs.some(shouldIgnoreDirectory);
  };

  const lists: GitPathLists = {
    tracked: new Set(),
    outerTracked: new Set(),
    sparse: new Set(),
    deleted: new Set(),
    ignoredTracked: new Set(),
    untracked: new Set(),
    entries: new Map(),
    indexColumn: new Map(),
  };
  collectGitPaths(canonTarget, lists, new Set(), nested => isUnderVendoredName(nested, true), bus, true);

  // Tracked half.
  const trackedGiven: string[] = [];
  const givenToCanon = new Map<string, string>();
  for (const canon of lists.tracked) {
    const given = toGiven(canon);
    if (given === null) continue;
    trackedGiven.push(given);
    givenToCanon.set(given, canon);
    if (lists.outerTracked.has(canon)) info.trackedFiles.add(given);
  }
  for (const canon of lists.ignoredTracked) {
    const given = toGiven(canon);
    if (given !== null) info.trackedIgnored.add(given);
  }
  const prSkips: PullRequestSkips = { dirCount: 0, dirNames: [], typeFilteredFiles: 0 };
  const tracked = getPullRequestFilesToScan(givenTarget, trackedGiven, configIgnorePatterns, prSkips);
  if (counts) {
    counts.typeFiltered += prSkips.typeFilteredFiles;
    counts.configIgnored += prSkips.configIgnoredFiles ?? 0;
  }
  for (const name of prSkips.dirNames) info.vendoredDirNames.add(name);
  for (const f of prSkips.nestedVendored ?? []) info.trackedNestedVendored.add(f);
  for (const file of tracked) {
    const entry = lists.entries.get(givenToCanon.get(file) ?? file);
    if (!entry) continue;
    info.blobs.set(file, entry);
    if (entry.worktreeAlso) info.worktreeAlso.add(file);
  }
  const stagedButDeleted: string[] = [];
  for (const u of prSkips.unreadable ?? []) {
    const canon = givenToCanon.get(u.file) ?? u.file;
    const listedAbsent = lists.deleted.has(canon) || lists.sparse.has(canon);
    const absent = u.code === 'ENOENT' || u.code === 'ENOTDIR';
    // Missing only when git ALSO says the file is not in the work tree AND the
    // filesystem agrees it is not there. Anything else (a directory that cannot
    // be entered, a name git's UTF-8 output turned into a path that does not
    // exist) is a file nobody examined, and the caller exits 2 over it.
    if (listedAbsent && absent) {
      info.trackedMissing.push(u.file);
      // Staged, then deleted on disk (`AD` or `MD`): the index holds content
      // HEAD does not, which the next commit will contain, so its blob is
      // scanned. A committed file removed with plain `rm` (` D`) is only
      // counted: its index blob is the committed content, and scanning it
      // would block the very `commit -a` that removes it. A sparse entry
      // left out on disk is never read (its blob may not be local).
      const entry = lists.entries.get(canon);
      if (
        lists.deleted.has(canon) &&
        !lists.sparse.has(canon) &&
        lists.indexColumn.has(canon) &&
        entry?.oid !== undefined
      ) {
        const readable: TrackedEntry = { ...entry, worktreeAlso: false, diskAbsent: true };
        info.blobs.set(u.file, readable);
        stagedButDeleted.push(u.file);
      }
    } else info.unreadable.push({ file: u.file, reason: u.reason });
  }

  // Untracked half: the walk's filtering.
  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, givenTarget);
  const untracked: string[] = [];
  for (const canon of lists.untracked) {
    const given = toGiven(canon);
    if (given === null) continue;
    if (isUnderVendoredName(canon, false)) continue;
    if (shouldIgnoreFile(given)) {
      if (counts) counts.typeFiltered++;
      continue;
    }
    if (configIgnoreTester(given)) {
      if (counts) counts.configIgnored++;
      continue;
    }
    let st: fs.Stats;
    try {
      st = fs.lstatSync(given);
    } catch (error) {
      // Untracked and gone, or not examinable: the walk reported these as a
      // warning and moved on, and an untracked file is not part of what the
      // repository holds.
      bus?.add({
        code: 'fs.permission_denied',
        severity: 'warning',
        ctx: { path: given, detail: String(error) },
      });
      continue;
    }
    if (!st.isFile()) continue;
    untracked.push(given);
  }

  return [...tracked, ...stagedButDeleted, ...untracked];
}

function shouldIgnoreDirectory(name: string): boolean {
  const ignoreDirs = [
    'node_modules',
    '.git',
    'dist',
    'build',
    'coverage',
    '.next',
    '.turbo',
    // Vendored / generated trees: third-party or tool-managed content where
    // matches are not the user's secrets and the volume drowns real findings.
    '.yarn',
    'vendor',
    '.venv',
    'venv',
    '__pycache__',
    '.mypy_cache',
    '.pytest_cache',
    '.gradle',
    '.svelte-kit',
  ];
  return ignoreDirs.includes(name);
}

/**
 * Minified / bundled / generated single-file artifacts. These are never
 * hand-authored, routinely committed, and a major false-positive source:
 * broad key shapes (e.g. `AKIA…`) occur by chance inside large minified blobs.
 */
function isGeneratedArtifact(basename: string): boolean {
  return (
    /\.min\.(js|mjs|cjs|css)$/.test(basename) ||
    /\.bundle\.(js|mjs|cjs)$/.test(basename) ||
    basename === '.pnp.cjs' ||
    basename === '.pnp.loader.mjs'
  );
}

function shouldIgnoreFile(
  filePath: string,
  gitignoreTester?: (filePath: string) => boolean,
): boolean {
  const ext = path.extname(filePath);
  // Text that is skipped by name on purpose (it produces false positives).
  // Binary formats are not here: a binary skip needs the file's own bytes to
  // agree with its extension, which the content classifier decides per copy
  // (design 2026-10-17, section 2.4; utils/binary-type.ts).
  const ignoreExts = ['.lock', '.log', '.map'];

  if (ignoreExts.includes(ext)) {
    return true;
  }

  const basename = path.basename(filePath);
  if (basename === 'package-lock.json' || basename === 'pnpm-lock.yaml' || basename === 'yarn.lock') {
    return true;
  }

  if (isGeneratedArtifact(basename)) {
    return true;
  }

  if (gitignoreTester && gitignoreTester(filePath)) {
    return true;
  }

  return false;
}
