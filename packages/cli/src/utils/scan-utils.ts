import path from 'path';
import fs from 'fs';
import { SecretScanner, getFilesToScan, getFilesToScanAsync, SecretMatch } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const BINARY_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip',
  '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.bin'
];

export interface ScanResult {
  file: string;
  matches: SecretMatch[];
}

export interface ScanOptions {
  verbose?: boolean;
  maxSize?: number;
  skipBinary?: boolean;
  progress?: boolean;
}

/**
 * Check if a file is binary based on extension
 */
export function isBinaryFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.includes(ext);
}

/**
 * Scan files with proper filtering and error handling (async version)
 * This is the shared scanning logic used by both scan and check commands
 */
export async function scanFilesAsync(
  targetPaths: string[],
  scanner: SecretScanner,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const {
    verbose = false,
    maxSize = MAX_FILE_SIZE,
    skipBinary = true,
    progress = false
  } = options;

  const results: ScanResult[] = [];

  for (const targetPath of targetPaths) {
    try {
      await fs.promises.access(targetPath);
    } catch {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Path not found: ${targetPath}`));
      }
      continue;
    }

    const stat = await fs.promises.stat(targetPath);
    let filesToScan: string[];

    if (stat.isFile()) {
      filesToScan = [targetPath];
    } else if (stat.isDirectory()) {
      // Use async getFilesToScan to get proper .gitignore filtering
      filesToScan = await getFilesToScanAsync(targetPath);
    } else {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Invalid path: ${targetPath}`));
      }
      continue;
    }

    // Scan each file with proper safeguards
    for (let i = 0; i < filesToScan.length; i++) {
      const file = filesToScan[i];

      try {
        // Skip binary files
        if (skipBinary && isBinaryFile(file)) {
          continue;
        }

        // Check file size
        const fileStat = await fs.promises.stat(file);
        if (fileStat.size > maxSize) {
          if (verbose) {
            console.warn(
              chalk.yellow(`⚠️  Skipping large file:`),
              chalk.white(path.relative(process.cwd(), file)),
              chalk.gray(`(${(fileStat.size / 1024 / 1024).toFixed(2)}MB)`)
            );
          }
          continue;
        }

        // Scan the file
        const matches = scanner.scan(file);
        if (matches.length > 0) {
          results.push({ file, matches });
        }

        // Show progress for large scans
        if (progress && filesToScan.length > 10 && i % 10 === 0) {
          process.stderr.write(`\r${chalk.gray(`Scanning... ${Math.round((i / filesToScan.length) * 100)}%`)}`);
        }
      } catch (error) {
        if (verbose) {
          console.error(
            chalk.red('❌ Error scanning file:'),
            chalk.white(path.relative(process.cwd(), file))
          );
          console.error(chalk.gray(String(error)));
        }
        // Continue scanning other files
      }
    }

    // Clear progress line if used
    if (progress && filesToScan.length > 10) {
      process.stderr.write('\r');
    }
  }

  return results;
}

/**
 * Scan files with proper filtering and error handling (sync version for backwards compatibility)
 * This is the shared scanning logic used by both scan and check commands
 */
export function scanFiles(
  targetPaths: string[],
  scanner: SecretScanner,
  options: ScanOptions = {}
): ScanResult[] {
  const {
    verbose = false,
    maxSize = MAX_FILE_SIZE,
    skipBinary = true
  } = options;

  const results: ScanResult[] = [];

  for (const targetPath of targetPaths) {
    if (!fs.existsSync(targetPath)) {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Path not found: ${targetPath}`));
      }
      continue;
    }

    const stat = fs.statSync(targetPath);
    let filesToScan: string[];

    if (stat.isFile()) {
      filesToScan = [targetPath];
    } else if (stat.isDirectory()) {
      // Use getFilesToScan to get proper .gitignore filtering
      filesToScan = getFilesToScan(targetPath);
    } else {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Invalid path: ${targetPath}`));
      }
      continue;
    }

    // Scan each file with proper safeguards
    for (const file of filesToScan) {
      try {
        // Skip binary files
        if (skipBinary && isBinaryFile(file)) {
          continue;
        }

        // Check file size
        const fileStat = fs.statSync(file);
        if (fileStat.size > maxSize) {
          if (verbose) {
            console.warn(
              chalk.yellow(`⚠️  Skipping large file:`),
              chalk.white(path.relative(process.cwd(), file)),
              chalk.gray(`(${(fileStat.size / 1024 / 1024).toFixed(2)}MB)`)
            );
          }
          continue;
        }

        // Scan the file
        const matches = scanner.scan(file);
        if (matches.length > 0) {
          results.push({ file, matches });
        }
      } catch (error) {
        if (verbose) {
          console.error(
            chalk.red('❌ Error scanning file:'),
            chalk.white(path.relative(process.cwd(), file))
          );
          console.error(chalk.gray(String(error)));
        }
        // Continue scanning other files
      }
    }
  }

  return results;
}

/**
 * Display scan results with proper formatting
 */
export function displayScanResults(results: ScanResult[]): void {
  if (results.length === 0) {
    console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
    return;
  }

  const totalSecrets = results.reduce((sum, r) => sum + r.matches.length, 0);
  console.log(chalk.red.bold('🚨 BLOCKED:'), chalk.white(`Found ${totalSecrets} secret${totalSecrets > 1 ? 's' : ''}\n`));

  for (const { file, matches } of results) {
    const relativePath = path.relative(process.cwd(), file);
    console.log(chalk.white.bold(`\n${relativePath}:`));

    for (const match of matches) {
      const severityColor = getSeverityColor(match.severity);
      const emoji = getSeverityEmoji(match.severity);

      console.log(
        `  ${emoji} ${chalk.white(`Line ${match.line}:`)} ${severityColor(match.type)} (${chalk.gray(match.severity)})`
      );
      console.log(chalk.gray(`    ${match.value}`));
    }
  }

  console.log('');
  console.log(chalk.red.bold('\n❌ BLOCKED:'), chalk.white('Commit blocked - remove secrets before pushing\n'));
}

function getSeverityColor(severity: string): (text: string) => string {
  switch (severity) {
    case 'critical':
      return chalk.red.bold;
    case 'high':
      return chalk.yellow;
    case 'medium':
      return chalk.blue;
    case 'low':
      return chalk.gray;
    default:
      return chalk.white;
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity) {
    case 'critical':
      return '🔴';
    case 'high':
      return '⚠️';
    case 'medium':
      return 'ℹ️';
    case 'low':
      return '✅';
    default:
      return '•';
  }
}
