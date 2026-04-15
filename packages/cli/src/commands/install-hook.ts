import { PreCommitHook } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function installHookCommand(): Promise<void> {
  console.log(chalk.blue('🪝 Installing pre-commit hook\n'));

  const hook = new PreCommitHook();
  const result = hook.install();

  if (result.success) {
    console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white(result.message));
    console.log(chalk.gray('\nThe hook will automatically scan for secrets before each commit\n'));
  } else {
    console.error(chalk.red('❌ Error:'), chalk.white(result.message));
    if (result.message.includes('git repository')) {
      console.log(chalk.gray('💡 Hint: Run'), chalk.cyan('git init'), chalk.gray('first\n'));
    } else {
      console.log(chalk.gray('💡 Hint: Check file permissions\n'));
    }
  }
}
