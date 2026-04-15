import fs from 'fs';
import path from 'path';
import { SecretScanner } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function fixCommand(files: string[]): Promise<void> {
  console.log(chalk.blue.bold('🔧 Secret Fix Guide\n'));
  console.log(chalk.gray('Note: This command identifies secrets but cannot auto-fix them.'));
  console.log(chalk.gray('You must manually remove secrets from your code.\n'));

  if (files.length === 0) {
    console.log(chalk.yellow('⚠️  No files specified'));
    console.log(chalk.gray('Usage: vault-guard fix <files...>\n'));
    return;
  }

  const scanner = new SecretScanner();
  let filesWithSecrets = 0;

  for (const file of files) {
    if (!fs.existsSync(file)) {
      console.error(chalk.red('❌ Error:'), chalk.white(`File not found: ${file}\n`));
      continue;
    }

    const matches = scanner.scan(file);
    if (matches.length === 0) {
      console.log(chalk.green('✅'), chalk.white(`${file}: No secrets found`));
      continue;
    }

    filesWithSecrets++;
    console.log(chalk.yellow('⚠️'), chalk.white(`${file}: ${matches.length} secret${matches.length > 1 ? 's' : ''} found`));
    console.log(chalk.gray('   Actions needed:'));

    for (const match of matches) {
      const relativePath = path.relative(process.cwd(), file);
      console.log(chalk.gray(`     • Line ${match.line}: Remove ${match.type} secret`));
    }
    console.log('');
  }

  if (filesWithSecrets === 0) {
    console.log(chalk.green.bold('✅ All files clean!\n'));
  } else {
    console.log(chalk.bold('Summary:'));
    console.log(chalk.yellow(`  ⚠️  Files with secrets: ${filesWithSecrets}`));
    console.log(chalk.gray('  💡 Remove secrets manually, then run: vault-guard check\n'));

    // Exit with error code if secrets found
    process.exit(1);
  }
}
