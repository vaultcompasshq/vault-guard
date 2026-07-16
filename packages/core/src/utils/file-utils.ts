import fs, { promises as fsPromises } from 'fs';
import path from 'path';
import ignore from 'ignore';

import { DiagnosticBus } from '../diagnostics';

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
        /* unreadable .gitignore — treat as absent */
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
          /* unreadable .gitignore — treat as absent */
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
          const subFiles = await getAllFilesAsync(fullPath, visited, verbose, bus);
          files.push(...subFiles);
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
 * Get files to scan (filters out ignored directories/files) - async version
 *
 * @param configIgnorePatterns - gitignore-style patterns from `config.ignore.paths`
 *   / `config.ignore.patterns`. Matched relative to `targetPath`.
 */
export async function getFilesToScanAsync(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
  configIgnorePatterns: string[] = [],
): Promise<string[]> {
  const allFiles = await getAllFilesAsync(targetPath, new Set(), verbose, bus);
  const gitignoreTester = getGitignoreTester(targetPath);
  const configIgnoreTester = buildConfigIgnoreFilter(configIgnorePatterns, targetPath);
  return allFiles.filter(
    file => !shouldIgnoreFile(file, gitignoreTester) && !configIgnoreTester(file),
  );
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
  const ignoreExts = [
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.ico',
    '.pdf',
    '.zip',
    '.tar',
    '.gz',
    '.lock',
    '.log',
    '.map',
  ];

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
