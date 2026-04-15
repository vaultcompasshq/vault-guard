import { Command } from 'commander';
import { scanCommand } from './commands/scan';
import { installHookCommand } from './commands/install-hook';
import { tokensCommand } from './commands/tokens';
import { monitorCommand } from './commands/monitor';
import { fixCommand } from './commands/fix';
import { checkCommand } from './commands/check';

export function buildCli(): Command {
  const program = new Command();

  program
    .name('vault-guard')
    .description('Security and optimization layer for AI-native coding')
    .version('1.0.0');

  // Scan command
  program
    .command('scan')
    .description('Scan files for secrets')
    .argument('[path]', 'Path to scan', '.')
    .action(async (path: string) => {
      const exitCode = await scanCommand(path);
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  // Install-hook command
  program
    .command('install-hook')
    .description('Install pre-commit hook')
    .action(async () => {
      await installHookCommand();
    });

  // Tokens command
  program
    .command('tokens')
    .description('Show token usage')
    .action(async () => {
      await tokensCommand();
    });

  // Monitor command
  program
    .command('monitor')
    .description('Start status monitor')
    .action(async () => {
      await monitorCommand();
    });

  // Fix command
  program
    .command('fix')
    .description('Show remediation steps for secrets')
    .argument('[files...]', 'Files to check')
    .action(async (files: string[]) => {
      const exitCode = await fixCommand(files);
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  // Check command
  program
    .command('check')
    .description('Quick check')
    .argument('[files...]', 'Files to check')
    .action(async (files: string[]) => {
      const exitCode = await checkCommand(files);
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  return program;
}
