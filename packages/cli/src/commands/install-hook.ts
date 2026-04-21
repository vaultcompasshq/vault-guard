import { PreCommitHook, type HookManager } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function installHookCommand(manager: HookManager = 'native'): Promise<void> {
  console.log(chalk.blue('🪝 Installing pre-commit hook\n'));
  console.log(chalk.gray(`   Manager: ${manager}\n`));

  const hook = new PreCommitHook();
  const result = hook.install({ manager });

  if (result.success) {
    console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white(result.message));
    if (result.hookPath) {
      console.log(chalk.gray(`   Path: ${result.hookPath}`));
    }
    console.log(
      chalk.gray(
        '\nThe hook runs `vault-guard scan --staged` before each commit (staged files only).\n',
      ),
    );
  } else {
    console.error(chalk.red('❌ Error:'), chalk.white(result.message));
    if (result.message.includes('git repository')) {
      console.log(chalk.gray('💡 Hint: Run'), chalk.cyan('git init'), chalk.gray('first\n'));
    } else {
      console.log(chalk.gray('💡 Hint: Check file permissions or merge the snippet shown above.\n'));
    }
  }
}
