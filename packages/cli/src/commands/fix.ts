import fs from 'fs';
import path from 'path';
import { SecretScanner } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function fixCommand(files: string[]): Promise<number> {
  console.log(chalk.blue.bold('🔧 Secret Remediation Guide\n'));
  console.log(chalk.gray('This command shows you exactly what needs to be fixed.'));
  console.log(chalk.gray('Manual remediation is required for security reasons.\n'));

  if (files.length === 0) {
    console.log(chalk.yellow('⚠️  No files specified'));
    console.log(chalk.gray('Usage: vault-guard fix <files...>\n'));
    return 0; // Success (nothing to do)
  }

  const scanner = new SecretScanner();
  let filesWithSecrets = 0;
  let totalSecrets = 0;

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
    totalSecrets += matches.length;

    const relativePath = path.relative(process.cwd(), file);
    console.log(chalk.yellow('⚠️'), chalk.white(`${relativePath}: ${matches.length} secret${matches.length > 1 ? 's' : ''} found`));
    console.log(chalk.gray('   Remediation steps:'));

    for (const match of matches) {
      console.log('');
      console.log(chalk.gray(`   1. Open file: ${relativePath}`));
      console.log(chalk.gray(`   2. Go to line: ${match.line}`));
      console.log(chalk.gray(`   3. Remove: ${chalk.white(match.type)} secret`));
      console.log(chalk.gray(`   4. Replace with: ${getReplacementSuggestion(match.type)}`));

      // Show context (masked)
      console.log(chalk.gray(`   Found: ${match.value}`));
    }
    console.log('');
  }

  if (filesWithSecrets === 0) {
    console.log(chalk.green.bold('✅ All files clean!\n'));
    return 0; // Success exit code
  } else {
    console.log(chalk.bold('Summary:'));
    console.log(chalk.yellow(`  ⚠️  Files with secrets: ${filesWithSecrets}`));
    console.log(chalk.red(`  ❌ Total secrets: ${totalSecrets}`));
    console.log('');
    console.log(chalk.gray('Next steps:'));
    console.log(chalk.gray('  1. Fix the secrets listed above'));
    console.log(chalk.gray('  2. Run: vault-guard check to verify'));
    console.log(chalk.gray('  3. Commit your changes\n'));

    return 1; // Error exit code (secrets found)
  }
}

function getReplacementSuggestion(secretType: string): string {
  const suggestions: Record<string, string> = {
    'anthropic': 'Environment variable (ANTHROPIC_API_KEY)',
    'openai': 'Environment variable (OPENAI_API_KEY)',
    'stripe': 'Environment variable (STRIPE_SECRET_KEY)',
    'aws-access': 'AWS IAM role or environment variable',
    'aws-secret': 'AWS IAM role or environment variable',
    'github-token': 'GitHub Actions secret or environment variable',
    'jwt-token': 'Environment variable or authentication service',
    'api-key-generic': 'Environment variable or secrets manager',
    'secret-generic': 'Environment variable or secrets manager',
    'password-in-code': 'Environment variable or secrets manager'
  };

  return suggestions[secretType] || 'Environment variable or secure vault';
}
