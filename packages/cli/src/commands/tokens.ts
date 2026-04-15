import { TokenCounter } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export async function tokensCommand(): Promise<void> {
  console.log(chalk.magenta.bold('💰 Token Usage\n'));

  const counter = new TokenCounter();
  const report = counter.generateReport(process.cwd());

  console.log(chalk.white.bold('Total Tokens:'), chalk.magenta.bold(report.totalTokens.toLocaleString()));
  console.log(chalk.white.bold('Estimated Cost:'), chalk.magenta.bold(`$${report.estimatedCost.toFixed(2)}`));

  console.log(chalk.white.bold('\nBreakdown by file type:'));
  for (const [ext, tokens] of Object.entries(report.breakdown)) {
    const percentage = ((tokens / report.totalTokens) * 100).toFixed(1);
    console.log(`  ${chalk.cyan(ext)}: ${chalk.magenta(tokens.toLocaleString())} tokens (${chalk.gray(percentage + '%')})`);
  }

  console.log(chalk.gray('\n💡 Tip: Use with AI coding tools to track token usage'));
}
