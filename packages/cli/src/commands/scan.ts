import {
  SecretScanner,
  loadConfig,
  ConfigError,
  GitError,
  mapPatternRejectionReasonToDiagnosticCode,
  getGitStagedFilePaths,
  isInsideGitWorkTree,
  DiagnosticBus,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import {
  scanFilesAsync,
  scanFileListAsync,
  displayScanResults,
  formatJson,
  formatSarif,
} from '../utils/scan-utils';
import type { Diagnostic } from '@vaultcompass/vault-guard-core';

interface ExtraPatternDiagnosticCtx {
  patternId: string;
  reason: string;
  detail: string;
}

export type OutputFormat = 'text' | 'json' | 'sarif';

export async function scanCommand(
  targetPath: string,
  format: OutputFormat = 'text',
  staged = false,
): Promise<number> {
  const cwd = process.cwd();

  let config;
  try {
    config = loadConfig(cwd);
  } catch (e) {
    if (e instanceof ConfigError) {
      console.error(chalk.red('❌ Config error:'), chalk.white(e.message));
      console.error(
        chalk.gray(
          '   Fix the JSON in the file above (or remove it) and re-run. ' +
            'Vault Guard refuses to scan with a broken config because silent ' +
            'fallback to defaults would mask the rules you intended.\n',
        ),
      );
      return 1;
    }
    throw e;
  }

  const scanner = new SecretScanner(config);

  const bus = new DiagnosticBus();
  const diagnostics: Diagnostic[] = [];
  const extraPatternDiagnostics: ExtraPatternDiagnosticCtx[] = [];

  // Surface rejected `extra_patterns` (ReDoS guard, length cap, invalid syntax).
  for (const rej of scanner.extraPatternRejections) {
    const ctx: ExtraPatternDiagnosticCtx = {
      patternId: rej.id,
      reason: rej.reason,
      detail: rej.detail,
    };
    extraPatternDiagnostics.push(ctx);
    diagnostics.push({
      code: mapPatternRejectionReasonToDiagnosticCode(rej.reason),
      severity: 'warning',
      ctx: { ...ctx },
    });
  }

  if (extraPatternDiagnostics.length > 0 && format === 'text') {
    for (const ctx of extraPatternDiagnostics) {
      console.error(
        chalk.yellow('⚠️  extra_pattern rejected:'),
        chalk.white(`${ctx.patternId} (${ctx.reason}) — ${ctx.detail}`),
      );
    }
    console.error(
      chalk.gray(
        '   Set "extra_patterns_unsafe": true in .vault-guard.json only if ' +
          'you have audited every pattern.\n',
      ),
    );
  }

  if (format === 'text' && !staged) {
    console.log(chalk.blue('🔍 Scanning'), chalk.cyan(targetPath));
  }

  try {
    let results;

    if (staged) {
      if (!isInsideGitWorkTree(cwd)) {
        console.error(chalk.red('❌ Error:'), chalk.white('Not a git repository (or outside a work tree).'));
        return 1;
      }

      let stagedFiles: string[];
      try {
        stagedFiles = getGitStagedFilePaths(cwd);
      } catch (e) {
        if (e instanceof GitError) {
          console.error(chalk.red('❌ Git error:'), chalk.white(e.message));
          console.error(
            chalk.gray(
              '   vault-guard cannot determine which files are staged.\n' +
                '   Refusing to produce a ✅ result that may be incorrect.\n',
            ),
          );
          return 2;
        }
        throw e;
      }

      if (format === 'text') {
        console.log(chalk.blue('🔍 Scanning'), chalk.cyan('git staged files'));
        if (stagedFiles.length === 0) {
          console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('Nothing staged — nothing to scan\n'));
          return 0;
        }
        console.log(chalk.gray(`   ${stagedFiles.length} file(s) in the index\n`));
      }
      results = await scanFileListAsync(stagedFiles, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
        bus,
      });
    } else {
      results = await scanFilesAsync([targetPath], scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
        bus,
      });
    }

    // Merge bus diagnostics
    diagnostics.push(...bus.drain());

    if (format === 'json') {
      process.stdout.write(formatJson(results, { diagnostics }) + '\n');
      return results.length === 0 ? 0 : 1;
    }

    if (format === 'sarif') {
      process.stdout.write(formatSarif(results, { diagnostics }) + '\n');
      return results.length === 0 ? 0 : 1;
    }

    // Text mode: print one-line diagnostic summary when any non-fatal issues occurred
    if (diagnostics.length > 0) {
      console.error(
        chalk.yellow(`⚠️  ${diagnostics.length} warning(s) — run with --json for details`),
      );
    }

    if (results.length === 0) {
      console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
      return 0;
    }

    displayScanResults(results);
    return 1;
  } catch (error) {
    console.error(chalk.red('❌ Fatal error:'), chalk.white(String(error)));
    return 1;
  }
}
