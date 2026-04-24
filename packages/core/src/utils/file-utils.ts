import fs, { promises as fsPromises } from 'fs';
import path from 'path';
import ignore from 'ignore';

import { DiagnosticBus } from '../diagnostics';

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

function buildIgnoreFilter(resolvedScanRoot: string): CachedIgnoreFilter {
  const gitRoot = findGitRoot(resolvedScanRoot);
  const stopAt = gitRoot ?? filesystemRootFor(resolvedScanRoot);
  const chain = collectGitignoreChain(resolvedScanRoot, stopAt);

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
 */
export async function getFilesToScanAsync(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
): Promise<string[]> {
  const allFiles = await getAllFilesAsync(targetPath, new Set(), verbose, bus);
  const gitignoreTester = getGitignoreTester(targetPath);
  return allFiles.filter(file => !shouldIgnoreFile(file, gitignoreTester));
}

/**
 * Get files to scan (filters out ignored directories/files) - sync version
 */
export function getFilesToScan(
  targetPath: string,
  verbose = false,
  bus?: DiagnosticBus,
): string[] {
  const allFiles = getAllFiles(targetPath, new Set(), verbose, bus);
  const gitignoreTester = getGitignoreTester(targetPath);
  return allFiles.filter(file => !shouldIgnoreFile(file, gitignoreTester));
}

function shouldIgnoreDirectory(name: string): boolean {
  const ignoreDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo'];
  return ignoreDirs.includes(name);
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
  ];

  if (ignoreExts.includes(ext)) {
    return true;
  }

  const basename = path.basename(filePath);
  if (basename === 'package-lock.json' || basename === 'pnpm-lock.yaml' || basename === 'yarn.lock') {
    return true;
  }

  if (gitignoreTester && gitignoreTester(filePath)) {
    return true;
  }

  return false;
}
