import path from 'path';
import fs from 'fs';
import {
  SecretScanner,
  getFilesToScan,
  getFilesToScanAsync,
  formatJson as formatJsonResults,
  formatSarif as formatSarifResults,
  type JsonOutput,
  type FileScanResult,
  type Diagnostic,
  type DiagnosticBus,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export type { JsonOutput };
export interface ScanFormatOptions {
  diagnostics?: Diagnostic[];
}

export function formatJson(results: ScanResult[], opts: ScanFormatOptions = {}): string {
  return formatJsonResults(results, { cwd: process.cwd(), diagnostics: opts.diagnostics });
}
export function formatSarif(results: ScanResult[], opts: ScanFormatOptions = {}): string {
  return formatSarifResults(results, { cwd: process.cwd(), diagnostics: opts.diagnostics });
}

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const BINARY_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip',
  '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.bin'
];

export type ScanResult = FileScanResult;

export interface ScanOptions {
  verbose?: boolean;
  maxSize?: number;
  skipBinary?: boolean;
  progress?: boolean;
  concurrency?: number; // Number of files to scan in parallel
  bus?: DiagnosticBus;
}

/**
 * Scan an explicit list of files (e.g. paths from \`git diff --cached\`).
 * Skips missing paths and non-files silently.
 */
export async function scanFileListAsync(
  files: string[],
  scanner: SecretScanner,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const {
    verbose = false,
    maxSize = MAX_FILE_SIZE,
    skipBinary = true,
    progress = false,
    concurrency = 10,
  } = options;

  const results: ScanResult[] = [];

  const scanFile = async (file: string): Promise<void> => {
    try {
      if (!fs.existsSync(file)) return;
      const st = await fs.promises.stat(file);
      if (!st.isFile()) return;

      if (skipBinary && isBinaryFile(file)) return;

      if (st.size > maxSize) {
        if (options.bus) {
          options.bus.add({
            code: 'file.too_large',
            severity: 'warning',
            ctx: { file: path.relative(process.cwd(), file), bytes: st.size },
          });
        }
        if (verbose) {
          console.warn(
            chalk.yellow(`⚠️  Skipping large file:`),
            chalk.white(path.relative(process.cwd(), file)),
            chalk.gray(`(${(st.size / 1024 / 1024).toFixed(2)}MB)`),
          );
        }
        return;
      }

      const matches = scanner.scan(file);
      if (matches.length > 0) {
        results.push({ file, matches });
      }
    } catch (error) {
      if (options.bus) {
        options.bus.add({
          code: 'file.read_error',
          severity: 'error',
          ctx: { file: path.relative(process.cwd(), file), detail: String(error) },
        });
      }
      if (verbose) {
        console.error(chalk.red('❌ Error scanning file:'), chalk.white(path.relative(process.cwd(), file)));
        console.error(chalk.gray(String(error)));
      }
    }
  };

  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    await Promise.all(batch.map(scanFile));

    if (progress && files.length > 10) {
      const percent = Math.round(((i + batch.length) / files.length) * 100);
      process.stderr.write(`\r${chalk.gray(`Scanning... ${percent}%`)}`);
    }
  }

  if (progress && files.length > 10) {
    process.stderr.write('\r');
  }

  return results;
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
    progress = false,
    concurrency = 10 // Scan 10 files at a time by default
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
      filesToScan = await getFilesToScanAsync(targetPath, verbose, options.bus);
    } else {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Invalid path: ${targetPath}`));
      }
      continue;
    }

    // Scan each file with proper safeguards (parallel with concurrency limit)
    const scanFile = async (file: string): Promise<void> => {
      try {
        // Skip binary files
        if (skipBinary && isBinaryFile(file)) {
          return;
        }

        // Check file size
        const fileStat = await fs.promises.stat(file);
        if (fileStat.size > maxSize) {
          if (options.bus) {
            options.bus.add({
              code: 'file.too_large',
              severity: 'warning',
              ctx: { file: path.relative(process.cwd(), file), bytes: fileStat.size },
            });
          }
          if (verbose) {
            console.warn(
              chalk.yellow(`⚠️  Skipping large file:`),
              chalk.white(path.relative(process.cwd(), file)),
              chalk.gray(`(${(fileStat.size / 1024 / 1024).toFixed(2)}MB)`)
            );
          }
          return;
        }

        // Scan the file
        const matches = scanner.scan(file);
        if (matches.length > 0) {
          results.push({ file, matches });
        }
      } catch (error) {
        if (options.bus) {
          options.bus.add({
            code: 'file.read_error',
            severity: 'error',
            ctx: { file: path.relative(process.cwd(), file), detail: String(error) },
          });
        }
        if (verbose) {
          console.error(
            chalk.red('❌ Error scanning file:'),
            chalk.white(path.relative(process.cwd(), file))
          );
          console.error(chalk.gray(String(error)));
        }
        // Continue scanning other files
      }
    };

    // Process files in batches for parallel scanning
    for (let i = 0; i < filesToScan.length; i += concurrency) {
      const batch = filesToScan.slice(i, i + concurrency);
      await Promise.all(batch.map(scanFile));

      // Show progress for large scans
      if (progress && filesToScan.length > 10) {
        const percent = Math.round(((i + batch.length) / filesToScan.length) * 100);
        process.stderr.write(`\r${chalk.gray(`Scanning... ${percent}%`)}`);
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
      filesToScan = getFilesToScan(targetPath, verbose, options.bus);
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
          if (options.bus) {
            options.bus.add({
              code: 'file.too_large',
              severity: 'warning',
              ctx: { file: path.relative(process.cwd(), file), bytes: fileStat.size },
            });
          }
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
        if (options.bus) {
          options.bus.add({
            code: 'file.read_error',
            severity: 'error',
            ctx: { file: path.relative(process.cwd(), file), detail: String(error) },
          });
        }
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
 * Display scan results with proper formatting.
 *
 * Output format: `<path>:<line>:<col>  <severity>  <type>  <redacted>`
 *
 * Why this layout:
 *   - Most modern terminals (iTerm2, Windows Terminal, VS Code, JetBrains)
 *     auto-link `path:line:col` so users can cmd/ctrl-click directly to the
 *     source — no copy-paste, no greppable secret value needed.
 *   - Paths are cwd-relative for the same reason JSON/SARIF are: avoids
 *     leaking the developer's home dir / username when output is shared.
 *   - The redacted match value (`sk-a…(37c)`) is shown last and intentionally
 *     low-information.
 */
export function displayScanResults(results: ScanResult[]): void {
  if (results.length === 0) {
    console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
    return;
  }

  const totalSecrets = results.reduce((sum, r) => sum + r.matches.length, 0);
  console.log(chalk.red.bold('🚨 BLOCKED:'), chalk.white(`Found ${totalSecrets} secret${totalSecrets > 1 ? 's' : ''}\n`));

  for (const { file, matches } of results) {
    const relativePath = relativeForDisplay(file);

    for (const match of matches) {
      const severityColor = getSeverityColor(match.severity);
      const emoji = getSeverityEmoji(match.severity);
      const location = `${relativePath}:${match.line}:${match.column + 1}`;

      console.log(
        `  ${emoji} ${chalk.cyan(location)}  ${severityColor(match.severity)}  ${chalk.white(match.type)}  ${chalk.gray(match.value)}`
      );
    }
  }

  console.log('');
  console.log(chalk.red.bold('❌ BLOCKED:'), chalk.white('Commit blocked — remove secrets before pushing\n'));
}

/** cwd-relative when inside cwd, absolute otherwise. Matches scan-output behaviour. */
function relativeForDisplay(file: string): string {
  if (!path.isAbsolute(file)) return file;
  const rel = path.relative(process.cwd(), file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return file;
  return rel || '.';
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
