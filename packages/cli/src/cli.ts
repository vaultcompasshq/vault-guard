import * as fs from 'fs';
import * as path from 'path';
import { Command } from 'commander';
import { scanCommand, OutputFormat } from './commands/scan';
import { installHookCommand } from './commands/install-hook';
import { tokensCommand } from './commands/tokens';
import { fixCommand } from './commands/fix';
import { checkCommand } from './commands/check';
import { statuslineCommand } from './commands/statusline';
import { suggestModelCommand } from './commands/suggest-model';
import { proxyCommand } from './commands/proxy';

function readCliVersion(): string {
  const pkgPath = path.join(__dirname, '..', 'package.json');
  const raw = fs.readFileSync(pkgPath, 'utf-8');
  return (JSON.parse(raw) as { version: string }).version;
}

export function buildCli(): Command {
  const program = new Command();

  program
    .name('vault-guard')
    .description('Security and optimization layer for AI-native coding')
    .version(readCliVersion());

  // Scan command
  program
    .command('scan')
    .description('Scan files for secrets')
    .argument('[path]', 'Path to scan', '.')
    .option('-f, --format <format>', 'Output format: text | json | sarif', 'text')
    .option('--staged', 'Scan git staged files only (uses index vs HEAD)', false)
    .action(async (path: string, options: { format: string; staged?: boolean }) => {
      const format = (options.format as OutputFormat) ?? 'text';
      const exitCode = await scanCommand(path, format, Boolean(options.staged));
      if (exitCode !== 0) {
        process.exit(exitCode);
      }
    });

  // Install-hook command
  program
    .command('install-hook')
    .description('Install pre-commit hook (runs vault-guard scan --staged)')
    .option(
      '-m, --manager <manager>',
      'Hook integration: native | husky | lefthook | precommit',
      'native',
    )
    .action(async (options: { manager: string }) => {
      const m = (options.manager ?? 'native').toLowerCase() as
        | 'native'
        | 'husky'
        | 'lefthook'
        | 'precommit';
      if (!['native', 'husky', 'lefthook', 'precommit'].includes(m)) {
        console.error(`Unknown manager: ${options.manager}`);
        process.exit(1);
      }
      await installHookCommand(m);
    });

  // Tokens command
  program
    .command('tokens')
    .description('Show token usage')
    .action(async () => {
      await tokensCommand();
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

  program
    .command('statusline')
    .description('Emit status fields for editor statuslines (JSON)')
    .option('--json', 'Print machine-readable JSON (default)', true)
    .option('--human', 'Print human-readable summary instead of JSON')
    .action((options: { json?: boolean; human?: boolean }) => {
      const asJson = options.human ? false : options.json !== false;
      statuslineCommand(asJson);
    });

  program
    .command('suggest-model')
    .description('Heuristic model hint from local telemetry (opt-in)')
    .option('--json', 'Print JSON', false)
    .option('--cwd <dir>', 'Optional cwd context label')
    .option('--language <lang>', 'Optional language label (e.g. tsx)')
    .action((options: { json?: boolean; cwd?: string; language?: string }) => {
      suggestModelCommand({
        json: Boolean(options.json),
        cwd: options.cwd,
        language: options.language,
      });
    });

  program
    .command('proxy')
    .description('Opt-in local Anthropic HTTP forwarder with usage logging (MVP)')
    .requiredOption(
      '--listen <host:port>',
      'Bind address, e.g. 127.0.0.1:8765',
    )
    .option(
      '--allow-env-fallback',
      'Permit fallback to ANTHROPIC_API_KEY when caller omits x-api-key. ' +
        'Off by default — see SECURITY.md before enabling.',
      false,
    )
    .option(
      '--allow-public',
      'Permit binding a non-loopback address. Off by default — exposing this ' +
        'proxy on the network combined with --allow-env-fallback is a credit-card ' +
        'draining footgun.',
      false,
    )
    .action(
      async (options: {
        listen: string;
        allowEnvFallback?: boolean;
        allowPublic?: boolean;
      }) => {
        try {
          const handle = await proxyCommand({
            listen: options.listen,
            allowEnvFallback: Boolean(options.allowEnvFallback),
            allowPublic: Boolean(options.allowPublic),
          });

          let signalled = false;
          const onSignal = (signal: NodeJS.Signals): void => {
            if (signalled) return;
            signalled = true;
            void handle
              .shutdown(signal)
              .catch(() => {
                /* shutdown is best-effort */
              })
              .finally(() => process.exit(0));
          };
          process.on('SIGINT', onSignal);
          process.on('SIGTERM', onSignal);

          await new Promise(() => {
            /* keep process alive until a signal triggers shutdown */
          });
        } catch (e) {
          console.error(String(e));
          process.exit(1);
        }
      },
    );

  return program;
}
