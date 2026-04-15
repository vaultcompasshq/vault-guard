import path from 'path';
import fs from 'fs';
import { SecretScanner, getFilesToScan } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

function isBinaryFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  const binaryExts = ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.bin'];
  return binaryExts.includes(ext);
}

export async function scanCommand(targetPath: string): Promise<void> {
  const scanner = new SecretScanner();
  const results: Array<{ file: string; matches: any[] }> = [];

  console.log(chalk.blue('🔍 Scanning'), chalk.cyan(targetPath));

  try {
    // Check if path exists
    if (!fs.existsSync(targetPath)) {
      console.error(chalk.red('❌ Error:'), chalk.white(`Path does not exist: ${targetPath}`));
      console.log(chalk.gray('💡 Hint: Check the path and try again'));
      process.exit(1);
      return;
    }

    // Check if path is file or directory
    const stat = fs.statSync(targetPath);
    let filesToScan: string[];

    if (stat.isFile()) {
      // Scan single file
      filesToScan = [targetPath];
      console.log(chalk.gray(`Scanning single file\n`));
    } else if (stat.isDirectory()) {
      // Scan directory
      filesToScan = getFilesToScan(targetPath);
      console.log(chalk.gray(`Found ${filesToScan.length} files to scan\n`));
    } else {
      console.error(chalk.red('❌ Error:'), chalk.white(`Invalid path: ${targetPath}`));
      process.exit(1);
      return;
    }

    // Scan each file
    for (const file of filesToScan) {
      try {
        // Skip binary files
        if (isBinaryFile(file)) {
          continue;
        }

        // Check file size
        const fileStat = fs.statSync(file);
        if (fileStat.size > MAX_FILE_SIZE) {
          console.warn(chalk.yellow(`⚠️  Skipping large file: ${path.relative(process.cwd(), file)} (${(fileStat.size / 1024 / 1024).toFixed(2)}MB)`));
          continue;
        }

        const matches = scanner.scan(file);
        if (matches.length > 0) {
          results.push({ file, matches });
        }
      } catch (error) {
        // Log error but continue scanning other files
        console.error(chalk.red('❌ Error scanning file:'), chalk.white(path.relative(process.cwd(), file)));
        console.error(chalk.gray(String(error)));
      }
    }

  // Display results
  if (results.length === 0) {
    console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
  } else {
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
    process.exit(1);
  }
  } catch (error) {
    console.error(chalk.red('❌ Fatal error:'), chalk.white(String(error)));
    process.exit(1);
  }
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
