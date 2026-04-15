import { SecretScanner } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import { scanFilesAsync, displayScanResults } from '../utils/scan-utils';

export async function scanCommand(targetPath: string): Promise<number> {
  const scanner = new SecretScanner();

  console.log(chalk.blue('🔍 Scanning'), chalk.cyan(targetPath));

  try {
    // Use async scanning logic for better performance
    const results = await scanFilesAsync([targetPath], scanner, {
      verbose: true,
      skipBinary: true,
      progress: true // Show progress for large scans
    });

    // Display results using shared formatter
    if (results.length === 0) {
      console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
      return 0; // Success exit code
    } else {
      displayScanResults(results);
      return 1; // Error exit code (secrets found)
    }
  } catch (error) {
    console.error(chalk.red('❌ Fatal error:'), chalk.white(String(error)));
    return 1; // Error exit code
  }
}
