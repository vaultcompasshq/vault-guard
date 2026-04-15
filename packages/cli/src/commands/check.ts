import path from 'path';
import { SecretScanner, getAllFiles } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function checkCommand(files: string[]): Promise<void> {
  const scanner = new SecretScanner();
  const filesToCheck = files.length > 0 ? files : ['.'];

  console.log(chalk.blue('✅ Quick check\n'));

  let totalSecretsFound = 0;

  for (const file of filesToCheck) {
    if (!require('fs').existsSync(file)) {
      console.error(chalk.red('❌ Error:'), chalk.white(`File not found: ${file}\n`));
      continue;
    }

    if (require('fs').statSync(file).isDirectory()) {
      // Scan directory
      const allFiles = getAllFiles(file);
      let secretsFound = 0;

      for (const f of allFiles) {
        const matches = scanner.scan(f);
        if (matches.length > 0) {
          secretsFound += matches.length;
          totalSecretsFound += matches.length;
          const relativePath = path.relative(process.cwd(), f);
          console.log(chalk.red('🔴'), chalk.white(`${relativePath}: ${matches.length} secret${matches.length > 1 ? 's' : ''}`));
        }
      }

      if (secretsFound === 0) {
        console.log(chalk.green('✅'), chalk.white(`${file}: Clean`));
      }
    } else {
      // Scan single file
      const matches = scanner.scan(file);
      if (matches.length > 0) {
        totalSecretsFound += matches.length;
        console.log(chalk.red('🔴'), chalk.white(`${file}: ${matches.length} secret${matches.length > 1 ? 's' : ''}`));
      } else {
        console.log(chalk.green('✅'), chalk.white(`${file}: Clean`));
      }
    }
  }

  console.log('');

  // Exit with error code if secrets found
  if (totalSecretsFound > 0) {
    process.exit(1);
  }
}
