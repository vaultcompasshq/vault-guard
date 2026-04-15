import fs from 'fs';
import path from 'path';

// Cache for .gitignore patterns to avoid re-reading files
const gitignoreCache = new Map<string, string[]>();

/**
 * Get all files in directory recursively
 */
export function getAllFiles(dirPath: string, visited = new Set<string>()): string[] {
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
        // Silently continue to avoid crashing on inaccessible files
      }
    }
  } catch (error) {
    // If we can't read the directory at all, return empty array
    // This handles permission errors on the directory itself
  }

  return files;
}

/**
 * Get files to scan (filters out ignored directories/files)
 */
export function getFilesToScan(targetPath: string): string[] {
  const allFiles = getAllFiles(targetPath);
  const gitignorePatterns = loadGitignorePatterns(targetPath);
  return allFiles.filter(file => !shouldIgnoreFile(file, gitignorePatterns));
}

function shouldIgnoreDirectory(name: string): boolean {
  const ignoreDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo'];
  return ignoreDirs.includes(name);
}

function shouldIgnoreFile(filePath: string, gitignorePatterns: string[] = []): boolean {
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

  // Check against .gitignore patterns
  if (gitignorePatterns.length > 0) {
    const relativePath = path.relative(process.cwd(), filePath);
    for (const pattern of gitignorePatterns) {
      if (matchesGitignorePattern(relativePath, pattern)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Load .gitignore patterns from directory and parent directories
 */
function loadGitignorePatterns(dirPath: string): string[] {
  const cacheKey = dirPath;
  if (gitignoreCache.has(cacheKey)) {
    return gitignoreCache.get(cacheKey)!;
  }

  const patterns: string[] = [];
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

        patterns.unshift(...lines);
      } catch (error) {
        // Ignore .gitignore read errors
      }
    }

    const parentDir = path.dirname(currentDir);
    if (parentDir === currentDir) {
      break;
    }
    currentDir = parentDir;
  }

  gitignoreCache.set(cacheKey, patterns);
  return patterns;
}

/**
 * Check if a file path matches a .gitignore pattern
 */
function matchesGitignorePattern(filePath: string, pattern: string): boolean {
  // Remove leading slashes for matching
  let gitignorePattern = pattern.replace(/^\//, '');

  // Handle directory patterns (ending with /)
  const isDirectoryPattern = gitignorePattern.endsWith('/');
  if (isDirectoryPattern) {
    gitignorePattern = gitignorePattern.slice(0, -1);
  }

  // Handle negation patterns (starting with !)
  if (gitignorePattern.startsWith('!')) {
    return false; // Negation not implemented for simplicity
  }

  // Convert glob pattern to regex
  let regexPattern = gitignorePattern
    .replace(/\./g, '\\.')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');

  // Match anywhere in path if pattern doesn't start with /
  if (!pattern.startsWith('/')) {
    regexPattern = `.*${regexPattern}`;
  }

  // Match end of path
  regexPattern = `${regexPattern}.*`;

  const regex = new RegExp(regexPattern);
  return regex.test(filePath);
}
