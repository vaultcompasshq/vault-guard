import {
  SecretScanner,
  loadConfig,
  ConfigError,
  GitError,
  mapPatternRejectionReasonToDiagnosticCode,
  getGitStagedFilePaths,
  getGitWorkTreeRoot,
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
  resolveScanRoot,
  type UnreadableFile,
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

  // Base for every path this run renders, serializes, ignore-matches and
  // fingerprints, and the directory its config is loaded from.
  //
  // A directory scan is anchored at the cwd, which is also the directory it
  // walked. A `--staged` run is anchored at the REPOSITORY ROOT: its file
  // list comes from the index and spans the whole worktree, so when the hook
  // runs from a subdirectory some staged files sit above the cwd. Anchored
  // at the cwd those fall out of `path.relative` and come back absolute --
  // publishing the developer's home directory and username into JSON and
  // into SARIF uris that still claim `uriBaseId: "%SRCROOT%"` -- and both
  // `ignore` matching and baseline fingerprints silently become functions of
  // wherever the caller happened to be standing.
  //
  // Resolved HERE, before loadConfig, because the config has to come from
  // the same place its `ignore` patterns will be matched against. Loading
  // `sub/.vault-guard.json` and then matching its `ignore.paths` against the
  // root makes `fixtures/**` mean `<root>/fixtures/` to the matcher and
  // `sub/fixtures/` to whoever wrote it, which exempts staged files nobody
  // exempted.
  let outputBase = cwd;
  if (staged) {
    try {
      outputBase = getGitWorkTreeRoot(cwd);
    } catch {
      // Deliberately not diagnosed here, and not swallowed either: the
      // staged branch below runs isInsideGitWorkTree and then
      // getGitStagedFilePaths, which produce the right message and a
      // non-zero exit for exactly these failures. Only a SUCCESSFUL lookup
      // is memoised, so that call genuinely re-runs and genuinely throws.
      outputBase = cwd;
    }
  }

  let config;
  try {
    config = loadConfig(outputBase);
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
  // True when neither the flag nor the config chose a threshold. Drives the
  // 1.4.0 upgrade notice below: users who picked a value have already decided.
  const gateIsImplicitDefault = failOnFlag === undefined && config.fail_on === undefined;

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
  // Files the scanner reached but could not read. On the staged path this is
  // fatal (see below); on a directory scan it is reported but not fatal.
  const unreadable: UnreadableFile[] = [];
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
        // outputBase was resolved above, before the config load. If that
        // lookup failed it was left as `cwd` and NOT reported; this call
        // repeats it internally and is where the failure surfaces.
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
        unreadable,
        configIgnorePatterns,
        fromGitIndex: true,
        cwd: outputBase,
      });
    } else {
      results = await scanFilesAsync(targetPaths, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
        bus,
        stats,
        unreadable,
        configIgnorePatterns,
      });
    }

    // Merge bus diagnostics
    diagnostics.push(...bus.drain());

    const baselineLoad = loadBaseline(outputBase);
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
      outputBase,
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
      ...(unreadable.length > 0 ? { unscannable_files: unreadable.length } : {}),
    };

    // A staged file vault-guard could not read is a file it did not check,
    // and the staged list is exactly what is about to be committed -- so the
    // run cannot claim to have cleared the commit. This is the one place the
    // fail-closed promise is load-bearing, and it is enforced here rather
    // than left to a "N warning(s)" line the caller has to notice.
    //
    // A directory scan deliberately does NOT do this: its file set is
    // discovered rather than declared, and unreadable entries in it are
    // ordinary (root-owned caches, sockets, other users' files). Failing
    // there would make the command unrunnable for reasons the user cannot
    // fix, and a gate people stop running protects nothing.
    const stagedScanIncomplete = staged && unreadable.length > 0;
    // Exit 2 is already this CLI's "cannot vouch for the result" code -- the
    // GitError branch above uses it for the same reason. Exit 1 means
    // "scanned fine, found something", which this run did not establish.
    const INCOMPLETE_SCAN_EXIT = 2;

    // Upgrade notice for the 1.4.0 default change. Before 1.4.0 any finding
    // failed the scan; now the implicit default is `medium`. When that
    // difference is what decides this run's outcome (findings exist, none
    // block, and the user never chose a threshold), say so once on stderr —
    // stderr so JSON/SARIF stdout stays parseable, and only for the implicit
    // default so setting `fail_on` anywhere silences it for good.
    if (gateIsImplicitDefault && totalMatches > 0 && blocking === 0) {
      console.error(
        chalk.yellow(
          `note: earlier vault-guard versions failed on any finding; since 1.4.0 the default gate is "medium".`,
        ),
      );
      console.error(
        chalk.gray(
          `      This run would have failed before. Set "fail_on" in .vault-guard.json ("low" restores the old\n` +
            `      behaviour, "medium" keeps this one) to silence this note.`,
        ),
      );
    }

    if (format === 'json') {
      // The document is still emitted: CI wants the artifact even when the
      // run failed, and `run.unscannable_files` plus the error-severity
      // `file.read_error` diagnostics inside it say why.
      process.stdout.write(formatJson(results, { diagnostics, run, cwd: outputBase }) + '\n');
      if (stagedScanIncomplete) return INCOMPLETE_SCAN_EXIT;
      return blocking === 0 ? 0 : 1;
    }

    if (format === 'sarif') {
      // `--staged` reads paths from the git index, so the repository root is
      // the right base there -- not the cwd, which a hook invoked from a
      // subdirectory would otherwise make the base for files above it.
      const scanRoot = staged ? outputBase : resolveScanRoot(targetPaths, cwd);
      process.stdout.write(
        formatSarif(results, { diagnostics, run, scanRoot, cwd: outputBase }) + '\n',
      );
      if (stagedScanIncomplete) return INCOMPLETE_SCAN_EXIT;
      return blocking === 0 ? 0 : 1;
    }

    // Text mode: print one-line diagnostic summary when any non-fatal issues occurred
    if (diagnostics.length > 0) {
      console.error(
        chalk.yellow(`⚠️  ${diagnostics.length} warning(s) — run with --json for details`),
      );
    }

    if (stagedScanIncomplete) {
      console.error(
        chalk.red.bold('❌ INCOMPLETE:'),
        chalk.white(
          `${unreadable.length} staged file(s) could not be read and were not scanned\n`,
        ),
      );
      for (const { file, reason } of unreadable) {
        console.error(`  ${chalk.cyan(file)}`);
        console.error(`    ${chalk.gray(reason)}`);
      }
      // Anything that DID scan is still worth showing; the reader needs both
      // "here is what I found" and "here is what I never looked at".
      if (results.length > 0) {
        console.error('');
        displayScanResults(results, blocking, outputBase);
      }
      console.error(
        chalk.gray(
          '\n   vault-guard could not examine every staged file.\n' +
            '   Refusing to produce a ✅ result that may be incorrect.\n',
        ),
      );
      return INCOMPLETE_SCAN_EXIT;
    }

    if (results.length === 0) {
      console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
      return 0;
    }

    displayScanResults(results, blocking, outputBase);

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
