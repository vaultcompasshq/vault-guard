import fs from 'fs';
import path from 'path';

/**
 * Get all files in directory recursively
 */
export function getAllFiles(dirPath: string): string[] {
  const files: string[] = [];

  try {
    if (!fs.existsSync(dirPath)) {
      return files;
    }

    const items = fs.readdirSync(dirPath);

    for (const item of items) {
      try {
        const fullPath = path.join(dirPath, item);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory() && !shouldIgnoreDirectory(item)) {
          files.push(...getAllFiles(fullPath));
        } else if (stat.isFile() && !shouldIgnoreFile(fullPath)) {
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
  return getAllFiles(targetPath).filter(file => !shouldIgnoreFile(file));
}

function shouldIgnoreDirectory(name: string): boolean {
  const ignoreDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '.next', '.turbo'];
  return ignoreDirs.includes(name);
}

function shouldIgnoreFile(filePath: string): boolean {
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

  return false;
}
