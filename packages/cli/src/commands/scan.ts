import {
  SecretScanner,
  loadConfig,
  getGitStagedFilePaths,
  isInsideGitWorkTree,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import {
  scanFilesAsync,
  scanFileListAsync,
  displayScanResults,
  formatJson,
  formatSarif,
} from '../utils/scan-utils';

export type OutputFormat = 'text' | 'json' | 'sarif';

export async function scanCommand(
  targetPath: string,
  format: OutputFormat = 'text',
  staged = false,
): Promise<number> {
  const cwd = process.cwd();
  const config = loadConfig(cwd);
  const scanner = new SecretScanner(config);

  if (format === 'text' && !staged) {
    console.log(chalk.blue('🔍 Scanning'), chalk.cyan(targetPath));
  }

  try {
    let results;

    if (staged) {
      if (!isInsideGitWorkTree(cwd)) {
        console.error(chalk.red('❌ Error:'), chalk.white('Not a git repository (or outside a work tree).'));
        return 1;
      }
      const stagedFiles = getGitStagedFilePaths(cwd);
      if (format === 'text') {
        console.log(chalk.blue('🔍 Scanning'), chalk.cyan('git staged files'));
        if (stagedFiles.length === 0) {
          console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('Nothing staged — nothing to scan\n'));
          return 0;
        }
        console.log(chalk.gray(`   ${stagedFiles.length} file(s) in the index\n`));
      }
      results = await scanFileListAsync(stagedFiles, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
      });
    } else {
      results = await scanFilesAsync([targetPath], scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
      });
    }

    if (format === 'json') {
      process.stdout.write(formatJson(results) + '\n');
      return results.length === 0 ? 0 : 1;
    }

    if (format === 'sarif') {
      process.stdout.write(formatSarif(results) + '\n');
      return results.length === 0 ? 0 : 1;
    }

    // Default: text output
    if (results.length === 0) {
      console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
      return 0;
    }

    displayScanResults(results);
    return 1;
  } catch (error) {
    console.error(chalk.red('❌ Fatal error:'), chalk.white(String(error)));
    return 1;
  }
}
