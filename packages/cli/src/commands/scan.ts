import {
  SecretScanner,
  loadConfig,
  ConfigError,
  GitError,
  mapPatternRejectionReasonToDiagnosticCode,
  getGitStagedFilePaths,
  isInsideGitWorkTree,
  DiagnosticBus,
  loadBaseline,
  filterResultsByBaseline,
  resolveFailOn,
  countBlockingMatches,
  FAIL_ON_VALUES,
  type FailOnThreshold,
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
  targetPath: string | string[],
  format: OutputFormat = 'text',
  staged = false,
  failOnFlag?: string,
): Promise<number> {
  const cwd = process.cwd();
  const targetPaths = Array.isArray(targetPath) ? targetPath : [targetPath];
  const targetLabel = targetPaths.length === 1 ? targetPaths[0] : `${targetPaths.length} paths`;

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

  // Resolve the gate threshold before scanning so an invalid value fails fast
  // rather than after a long scan.
  const failOnResolved = resolveFailOn(failOnFlag, config.fail_on);
  if (!failOnResolved.ok) {
    console.error(
      chalk.red('❌ Invalid fail-on value:'),
      chalk.white(failOnResolved.invalid),
    );
    console.error(chalk.gray(`   Expected one of: ${FAIL_ON_VALUES.join(' | ')}\n`));
    return 1;
  }
  const failOn: FailOnThreshold = failOnResolved.threshold;

  const scanner = new SecretScanner(config);

  // Merge config ignore paths and patterns into a single list for file filtering.
  const configIgnorePatterns: string[] = [
    ...(config.ignore?.paths ?? []),
    ...(config.ignore?.patterns ?? []),
  ];

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
    console.log(chalk.blue('🔍 Scanning'), chalk.cyan(targetLabel));
  }

  const stats = { filesScanned: 0, bytesScanned: 0 };
  const t0 = Date.now();

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
        stats,
        configIgnorePatterns,
        fromGitIndex: true,
        cwd,
      });
    } else {
      results = await scanFilesAsync(targetPaths, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
        bus,
        stats,
        configIgnorePatterns,
      });
    }

    // Merge bus diagnostics
    diagnostics.push(...bus.drain());

    const baselineLoad = loadBaseline(cwd);
    if (baselineLoad.parseError) {
      diagnostics.push({
        code: 'baseline.invalid',
        severity: 'warning',
        ctx: { path: baselineLoad.sourcePath ?? '', detail: baselineLoad.parseError },
      });
      if (format === 'text') {
        console.error(
          chalk.yellow('⚠️  Baseline file invalid:'),
          chalk.white(baselineLoad.parseError),
          chalk.gray(baselineLoad.sourcePath ? `(${baselineLoad.sourcePath})` : ''),
        );
      }
    }

    const { results: afterBaseline, suppressed: baselineSuppressed } = filterResultsByBaseline(
      process.cwd(),
      results,
      baselineLoad.fingerprints,
    );
    results = afterBaseline;

    const durationMs = Date.now() - t0;
    const totalMatches = results.reduce((n, r) => n + r.matches.length, 0);
    const blocking = countBlockingMatches(results, failOn);
    const run = {
      duration_ms: durationMs,
      files_scanned: stats.filesScanned,
      bytes_scanned: stats.bytesScanned,
      patterns_active: scanner.getActivePatternCount(),
      diagnostics_count: diagnostics.length,
      fail_on: failOn,
      blocking_matches: blocking,
      ...(baselineSuppressed > 0 ? { baseline_suppressed: baselineSuppressed } : {}),
    };

    if (format === 'json') {
      process.stdout.write(formatJson(results, { diagnostics, run }) + '\n');
      return blocking === 0 ? 0 : 1;
    }

    if (format === 'sarif') {
      process.stdout.write(formatSarif(results, { diagnostics, run }) + '\n');
      return blocking === 0 ? 0 : 1;
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

    displayScanResults(results, blocking);

    if (blocking === 0) {
      // Findings exist but all sit below the gate. Say so explicitly — a silent
      // exit 0 after printing findings reads like a bug.
      console.log(
        chalk.white(
          `${totalMatches} finding(s), none at or above severity "${failOn}" — not failing the gate.`,
        ),
      );
      console.log(
        chalk.gray(`   Tighten with --fail-on low or "fail_on": "low" in .vault-guard.json\n`),
      );
      return 0;
    }

    return 1;
  } catch (error) {
    console.error(chalk.red('❌ Fatal error:'), chalk.white(String(error)));
    return 1;
  }
}
