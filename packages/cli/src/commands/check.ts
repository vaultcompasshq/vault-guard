import { SecretScanner } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import path from 'path';
import { scanFilesAsync } from '../utils/scan-utils';

export async function checkCommand(files: string[]): Promise<number> {
  const scanner = new SecretScanner();
  const filesToCheck = files.length > 0 ? files : ['.'];

  console.log(chalk.blue('✅ Quick check\n'));

  // Use async scanning logic with same safeguards as scan command
  const results = await scanFilesAsync(filesToCheck, scanner, {
    verbose: false,
    skipBinary: true,
    progress: false
  });

  if (results.length === 0) {
    console.log(chalk.green.bold('✅ Clean:'), chalk.white('No secrets found\n'));
    return 0; // Success exit code
  } else {
    const totalSecrets = results.reduce((sum, r) => sum + r.matches.length, 0);
    console.log(chalk.red.bold('🔴 BLOCKED:'), chalk.white(`Found ${totalSecrets} secret${totalSecrets > 1 ? 's' : ''}\n`));

    // Display simplified results
    for (const { file, matches } of results) {
      const relativePath = relativePathCwd(file);
      console.log(chalk.red('🔴'), chalk.white(`${relativePath}: ${matches.length} secret${matches.length > 1 ? 's' : ''}`));
    }

    console.log('');
    return 1; // Error exit code (secrets found)
  }
}

function relativePathCwd(filePath: string): string {
  return path.relative(process.cwd(), filePath);
}
