import fs from 'fs';
import path from 'path';
import { promises as fsPromises } from 'fs';

// Cache for .gitignore patterns to avoid re-reading files
const gitignoreCache = new Map<string, { ignore: GitignorePattern[]; negate: GitignorePattern[] }>();

/**
 * Gitignore pattern interface
 */
interface GitignorePattern {
  pattern: string;
  isNegation: boolean;
  isDirectory: boolean;
  regex: RegExp;
}

/**
 * Get all files in directory recursively (async version)
 */
export async function getAllFilesAsync(dirPath: string, visited = new Set<string>(), verbose = false): Promise<string[]> {
  const files: string[] = [];

  try {
    try {
      await fsPromises.access(dirPath);
    } catch {
      return files;
    }

    // Prevent infinite recursion from circular symlinks
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

        // Skip symlinks to prevent infinite recursion
        if (lstat.isSymbolicLink()) {
          continue;
        }

        if (lstat.isDirectory() && !shouldIgnoreDirectory(item)) {
          const subFiles = await getAllFilesAsync(fullPath, visited);
          files.push(...subFiles);
        } else if (lstat.isFile() && !shouldIgnoreFile(fullPath)) {
          files.push(fullPath);
        }
      } catch (error) {
        // Skip files/directories we can't read (permission errors, etc.)
        if (verbose) {
          console.error(`Warning: Cannot access ${path.join(dirPath, item)}:`, error);
        }
      }
    }
  } catch (error) {
    // If we can't read the directory at all, return empty array
    if (verbose) {
      console.error(`Warning: Cannot read directory ${dirPath}:`, error);
    }
  }

  return files;
}

/**
 * Get all files in directory recursively (sync version for backwards compatibility)
 */
export function getAllFiles(dirPath: string, visited = new Set<string>(), verbose = false): string[] {
  const files: string[] = [];

  try {
    if (!fs.existsSync(dirPath)) {
      return files;
    }

    // Prevent infinite recursion from circular symlinks
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

        // Skip symlinks to prevent infinite recursion
        if (lstat.isSymbolicLink()) {
          continue;
        }

        if (lstat.isDirectory() && !shouldIgnoreDirectory(item)) {
          files.push(...getAllFiles(fullPath, visited));
        } else if (lstat.isFile() && !shouldIgnoreFile(fullPath)) {
          files.push(fullPath);
        }
      } catch (error) {
        // Skip files/directories we can't read (permission errors, etc.)
        if (verbose) {
          console.error(`Warning: Cannot access ${path.join(dirPath, item)}:`, error);
        }
      }
    }
  } catch (error) {
    // If we can't read the directory at all, return empty array
    if (verbose) {
      console.error(`Warning: Cannot read directory ${dirPath}:`, error);
    }
  }

  return files;
}

/**
 * Get files to scan (filters out ignored directories/files) - async version
 */
export async function getFilesToScanAsync(targetPath: string, verbose = false): Promise<string[]> {
  const allFiles = await getAllFilesAsync(targetPath, new Set(), verbose);
  const gitignorePatterns = loadGitignorePatterns(targetPath, verbose);
  return allFiles.filter(file => !shouldIgnoreFile(file, gitignorePatterns));
}

/**
 * Get files to scan (filters out ignored directories/files) - sync version
 */
export function getFilesToScan(targetPath: string, verbose = false): string[] {
  const allFiles = getAllFiles(targetPath, new Set(), verbose);
  const gitignorePatterns = loadGitignorePatterns(targetPath, verbose);
  return allFiles.filter(file => !shouldIgnoreFile(file, gitignorePatterns));
}

function shouldIgnoreDirectory(name: string): boolean {
  const ignoreDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo'];
  return ignoreDirs.includes(name);
}

function shouldIgnoreFile(filePath: string, gitignorePatterns: GitignorePattern[] = []): boolean {
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
    '.log'
  ];

  if (ignoreExts.includes(ext)) {
    return true;
  }

  const basename = path.basename(filePath);
  if (basename === 'package-lock.json' || basename === 'pnpm-lock.yaml' || basename === 'yarn.lock') {
    return true;
  }

  // Check against .gitignore patterns with proper negation support
  if (gitignorePatterns.length > 0) {
    const relativePath = path.relative(process.cwd(), filePath);
    let isIgnored = false;

    // First pass: check if file matches any ignore pattern
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for (const { pattern, isNegation, regex } of gitignorePatterns) {
      if (!isNegation && regex.test(relativePath)) {
        isIgnored = true;
      }
    }

    // Second pass: check if file matches any negation pattern (only if already ignored)
    if (isIgnored) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      for (const { pattern, isNegation, regex } of gitignorePatterns) {
        if (isNegation && regex.test(relativePath)) {
          return false; // File is re-included by negation pattern
        }
      }
      return true; // File is ignored and no negation pattern applies
    }
  }

  return false;
}

/**
 * Load .gitignore patterns from directory and parent directories
 * Returns both ignore and negation patterns with proper regex compilation
 */
function loadGitignorePatterns(dirPath: string, verbose = false): GitignorePattern[] {
  const cacheKey = dirPath;
  const cached = gitignoreCache.get(cacheKey);
  if (cached) {
    return cached.ignore.concat(cached.negate);
  }

  const ignorePatterns: GitignorePattern[] = [];
  const negatePatterns: GitignorePattern[] = [];
  let currentDir = dirPath;

  // Walk up directory tree to collect all .gitignore patterns
  while (currentDir !== path.parse(currentDir).root) {
    const gitignorePath = path.join(currentDir, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      try {
        const content = fs.readFileSync(gitignorePath, 'utf-8');
        const lines = content.split('\n')
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'));

        for (const line of lines) {
          const pattern = compileGitignorePattern(line);
          if (pattern.isNegation) {
            negatePatterns.push(pattern);
          } else {
            ignorePatterns.push(pattern);
          }
        }
      } catch (error) {
        // Ignore .gitignore read errors
        if (verbose) {
          console.error(`Warning: Cannot read .gitignore in ${currentDir}:`, error);
        }
      }
    }

    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) {
      break;
    }
    currentDir = parentDir;
  }

  gitignoreCache.set(cacheKey, { ignore: ignorePatterns, negate: negatePatterns });
  return [...ignorePatterns, ...negatePatterns];
}

/**
 * Compile a .gitignore pattern into a regex pattern object
 */
function compileGitignorePattern(line: string): GitignorePattern {
  let pattern = line;
  const isNegation = pattern.startsWith('!');

  if (isNegation) {
    pattern = pattern.substring(1);
  }

  // Handle directory patterns (ending with /)
  const isDirectory = pattern.endsWith('/');
  if (isDirectory) {
    pattern = pattern.slice(0, -1);
  }

  // Remove leading slash for matching
  const hasLeadingSlash = pattern.startsWith('/');
  if (hasLeadingSlash) {
    pattern = pattern.substring(1);
  }

  // Handle recursive globbing (**)
  pattern = pattern
    .replace(/\*\*/g, '(.*/)?')  // ** matches any number of directories
    .replace(/\*/g, '[^/]*')     // * matches within a directory
    .replace(/\?/g, '[^/]');      // ? matches single character

  // Escape special regex characters
  pattern = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');

  // Convert to regex
  let regexPattern: string;
  if (hasLeadingSlash) {
    // Pattern starting with / matches from root
    regexPattern = `^${pattern}.*`;
  } else {
    // Pattern without / matches anywhere
    regexPattern = `(?:^|/)${pattern}(?:/|$)`;
  }

  const regex = new RegExp(regexPattern);

  return {
    pattern: line,
    isNegation,
    isDirectory,
    regex
  };
}
