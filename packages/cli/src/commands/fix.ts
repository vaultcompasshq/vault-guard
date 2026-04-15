import fs from 'fs';
import path from 'path';
import { SecretScanner } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function fixCommand(files: string[]): Promise<void> {
  console.log(chalk.blue.bold('🔧 Auto-fixing issues\n'));

  if (files.length === 0) {
    console.log(chalk.yellow('⚠️  No files specified'));
    console.log(chalk.gray('Usage: vault-guard fix <files...>\n'));
    return;
  }

  const scanner = new SecretScanner();
  let fixedCount = 0;
  let errorCount = 0;

  for (const file of files) {
    if (!fs.existsSync(file)) {
      console.error(chalk.red('❌ Error:'), chalk.white(`File not found: ${file}\n`));
      errorCount++;
      continue;
    }

    const matches = scanner.scan(file);
    if (matches.length === 0) {
      console.log(chalk.green('✅'), chalk.white(`${file}: No secrets to fix`));
      continue;
    }

    console.log(chalk.yellow('⚠️'), chalk.white(`${file}: ${matches.length} secret${matches.length > 1 ? 's' : ''} found`));
    console.log(chalk.gray('💡 Hint: Remove secrets manually to fix\n'));
  }

  console.log(chalk.bold('Summary:'));
  console.log(chalk.green(`  ✅ Fixed: ${fixedCount} files`));
  if (errorCount > 0) {
    console.log(chalk.red(`  ❌ Errors: ${errorCount} files`));
  }
  console.log('');
}
