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
  loadTrustedControls,
  TrustBaseError,
  type FailOnThreshold,
  type PullRequestSkips,
  type TrustBaseReport,
  type TrustedControls,
  type VaultGuardConfig,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import fs from 'fs';
import { isAbsolute, relative, resolve as pathResolve } from 'path';
import {
  scanFilesAsync,
  scanFileListAsync,
  displayScanResults,
  formatJson,
  formatSarif,
  resolveScanRoot,
  formatExcludeEntry,
  excludeEntryNote,
  type RunSkipCounts,
  type UnreadableFile,
} from '../utils/scan-utils';
import type { Diagnostic } from '@vaultcompass/vault-guard-core';

interface ExtraPatternDiagnosticCtx {
  patternId: string;
  reason: string;
  detail: string;
}

export type OutputFormat = 'text' | 'json' | 'sarif';

/**
 * Exit 2 is "vault-guard cannot vouch for this result". The staged path already
 * uses it for a file it could not read and for a git failure; pull-request mode
 * uses it for a base ref it could not read control inputs from; a whole-tree /
 * target scan (plain or --trust-base) uses it for a walk that examined zero
 * files. In every case nothing about the tree was established, so exit 1
 * ("scanned fine, found something") would be a claim the run did not earn.
 */
const COULD_NOT_RUN_EXIT = 2;
// Exit 1 is reserved for "scanned, and findings at or above the gate exist".
// Everything that is not a verdict on the tree (bad config, bad flag, not a git
// repo, an unexpected crash) is COULD_NOT_RUN_EXIT, because callers such as
// conductor read 1 as "secrets found".

/**
 * Symlinks resolved, falling back to the input when they cannot be. The
 * worktree root git reports is physical (`/private/var/...` on macOS, where
 * `/var` is a link), so a target compared against it unresolved reads as
 * outside a repository it is plainly inside.
 */
function canonicalPath(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/**
 * The INCOMPLETE block, on stderr, for every output format: what could not be
 * vouched for, why, and the exact `ignore.paths` entry that would declare it.
 * `between` runs after the file list and before the closing lines (text mode
 * uses it to show what DID scan).
 *
 * Two different causes land in `unreadable` and must not be conflated: a read
 * failure means the file was never examined, a budget overrun means it WAS
 * scanned but slowly enough that the result is not trusted, and a too-large file
 * was refused before it was read.
 */
function reportIncomplete(
  unreadable: UnreadableFile[],
  staged: boolean,
  trustBase: TrustBaseReport | undefined,
  between?: () => void,
): void {
  const unread = unreadable.filter(u => u.kind !== 'scan_budget' && u.kind !== 'too_large');
  const overBudget = unreadable.filter(u => u.kind === 'scan_budget');
  const tooLarge = unreadable.filter(u => u.kind === 'too_large');
  const parts: string[] = [];
  const what = staged ? 'staged file(s)' : 'file(s) or target(s)';
  if (unread.length > 0) {
    parts.push(`${unread.length} ${what} could not be read and were not scanned`);
  }
  if (overBudget.length > 0) {
    parts.push(
      `${overBudget.length} ${what} exceeded the per-file scan budget, so their result is not trusted`,
    );
  }
  if (tooLarge.length > 0) {
    parts.push(`${tooLarge.length} ${what} over the 32 MiB scan limit were not scanned`);
  }
  console.error(chalk.red.bold('❌ INCOMPLETE:'), chalk.white(`${parts.join('; ')}\n`));
  const ignoreWhere = trustBase
    ? `"ignore.paths" in .vault-guard.json on the base ref "${trustBase.ref}" (a change made in this pull request is only a proposal)`
    : '"ignore.paths" in .vault-guard.json';
  for (const { file, reason, exclude } of unreadable) {
    console.error(`  ${chalk.cyan(file)}`);
    console.error(`    ${chalk.gray(reason)}`);
    if (exclude) {
      console.error(
        `    ${chalk.gray(`to exclude it on purpose, add ${formatExcludeEntry(exclude)} to ${ignoreWhere}`)}`,
      );
      const note = excludeEntryNote(exclude);
      if (note) console.error(`    ${chalk.gray(`(${note})`)}`);
    } else {
      console.error(`    ${chalk.gray('check the path, or stop passing it to vault-guard')}`);
    }
  }
  between?.();
  console.error(
    chalk.gray(
      `\n   vault-guard cannot vouch for every ${staged ? 'staged file' : 'file it was asked to scan'}.\n` +
        '   Refusing to produce a ✅ result that may be incorrect (exit 2).\n' +
        '   Fix the cause, or exclude the file deliberately: an excluded file is counted\n' +
        '   and reported as "Excluded by config ignore", never hidden.\n',
    ),
  );
}

export async function scanCommand(
  targetPath: string | string[],
  format: OutputFormat = 'text',
  staged = false,
  failOnFlag?: string,
  /**
   * Pull-request mode. Control inputs come from this ref and the head tree is
   * the thing scanned. Never set by a pre-commit hook: a hook runs inside the
   * trust boundary, where the working tree is the developer's own.
   */
  trustBaseRef?: string,
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

  // Pull-request mode is resolved FIRST, before anything is printed and before
  // a single file is opened. A base ref that cannot be read is could-not-run,
  // and a run that had already announced "🔍 Scanning ." before discovering
  // that would be describing work it never did.
  let controls: TrustedControls | undefined;
  if (trustBaseRef !== undefined) {
    try {
      controls = loadTrustedControls(outputBase, trustBaseRef);
    } catch (e) {
      if (e instanceof TrustBaseError || e instanceof ConfigError) {
        console.error(chalk.red('❌ Cannot establish the trust base:'), chalk.white(e.message));
        return COULD_NOT_RUN_EXIT;
      }
      throw e;
    }
  }

  // The trust base is resolved from the run's anchor, which for a directory
  // scan is the process cwd -- the same place the config is loaded from. A
  // target somewhere else entirely therefore has NO tracked files in common
  // with the repository the base ref lives in, and the intersection that makes
  // pull-request mode safe becomes an intersection with nothing: the run
  // scanned zero files and printed "no secrets found". Found by running the
  // built CLI against another checkout by absolute path, which is exactly how
  // someone would try this by hand.
  //
  // Refused rather than repaired by re-anchoring, because re-anchoring would
  // move the config search, the output paths and the baseline fingerprints
  // along with it, and quietly changing which config a scan obeys is the class
  // of behaviour this whole flag exists to remove.
  if (controls && !staged) {
    for (const target of targetPaths) {
      const abs = canonicalPath(pathResolve(cwd, target));
      const rel = relative(controls.repoRoot, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) {
        console.error(
          chalk.red('❌ Cannot establish the trust base:'),
          chalk.white(
            `the scan target ${target} is outside the repository that "${trustBaseRef}" ` +
              `lives in (${controls.repoRoot}), so pull-request mode would have no ` +
              'tracked files to scan and would report a clean result over nothing. ' +
              'Run vault-guard from inside the repository you are judging. ' +
              'Nothing was scanned.',
          ),
        );
        return COULD_NOT_RUN_EXIT;
      }
    }
  }

  const trustBase: TrustBaseReport | undefined =
    controls === undefined
      ? undefined
      : {
          ref: controls.ref,
          proposals: controls.proposals,
          configChanged: controls.configChanged,
          baselineChanged: controls.baselineChanged,
          configShapeChange: controls.configShapeChange,
          baselineShapeChange: controls.baselineShapeChange,
        };

  let config: VaultGuardConfig;
  try {
    config = controls ? controls.config : loadConfig(outputBase);
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
      return COULD_NOT_RUN_EXIT;
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
    return COULD_NOT_RUN_EXIT;
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
        chalk.white(`${ctx.patternId} (${ctx.reason}) -- ${ctx.detail}`),
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
  // Total findings hidden by inline `vault-guard: ignore-line` /
  // `ignore-next-line` directives across every file. Reported even at zero so
  // the run always states whether the scanner was silenced inline.
  const inlineSuppressed = { count: 0, criticalVendorAnchored: 0 };
  // What the file set declined to look at. Only filled on a pull-request
  // DIRECTORY scan, which is the only path that builds a file set this way:
  // `--staged` takes its list from the index and consults neither the vendored
  // names nor the type filters, so both counts are structurally zero there and
  // printing them would invent a reassurance.
  const prSkips: PullRequestSkips = {
    dirCount: 0,
    dirNames: [],
    typeFilteredFiles: 0,
    configIgnoredFiles: 0,
  };
  // What the run skipped without opening: the walk's type filter, the config's
  // own `ignore` list (a declared skip) and binary extensions. On a
  // pull-request directory scan the first two are counted into `prSkips`.
  const skips: RunSkipCounts = { typeFiltered: 0, configIgnored: 0, binary: 0 };
  // Files the run reached but could not vouch for: unreadable, over the scan
  // budget, or a named target that is not there. Fatal (exit 2) on every path.
  const unreadable: UnreadableFile[] = [];
  const t0 = Date.now();

  try {
    let results;

    if (staged) {
      if (!isInsideGitWorkTree(cwd)) {
        console.error(chalk.red('❌ Error:'), chalk.white('Not a git repository (or outside a work tree).'));
        return COULD_NOT_RUN_EXIT;
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
          console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('Nothing staged -- nothing to scan\n'));
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
        skips,
        configIgnorePatterns,
        fromGitIndex: true,
        cwd: outputBase,
        // Explicit: staged paths are judged relative to the repository root.
        pathRoot: outputBase,
        inlineSuppressed,
      });
    } else {
      results = await scanFilesAsync(targetPaths, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: format === 'text',
        bus,
        stats,
        unreadable,
        skips,
        configIgnorePatterns,
        inlineSuppressed,
        ...(controls
          ? { pullRequest: { headTreeFiles: controls.headTreeFiles, skipped: prSkips } }
          : {}),
      });
    }

    // A whole-tree / target scan (plain or --trust-base) that examined ZERO
    // files established nothing about the tree, and "No secrets found" over
    // nothing is a worse signal than no gate at all: it is a green check a
    // reviewer reads as "this was looked at". Found in the wild as a check
    // script whose scan root resolved relative to its own (relocated) path
    // rather than the repository -- it scanned zero files and sat green in a
    // required check for two days before anyone noticed. action.yml's
    // `pwd -P` SCAN_ROOT handling addresses the wrong-root case one layer
    // out; this CLI check is a backstop for the ZERO-FILE subset of it. A
    // wrong root that still holds a stray scannable file examines one file
    // and scans green, so running at the repository root remains the real
    // fix; this only refuses the empty case.
    //
    // `--staged` is deliberately EXCLUDED. Its file list is declared by the
    // caller (the git index) rather than discovered by a walk, so an empty
    // index is the caller explicitly asking "what's staged" and getting a
    // true "nothing" -- an IMPOSED empty scope, not a DISCOVERED one, and it
    // must stay a clean pass. That case already returns 0 above (text mode)
    // or falls through this same function to a 0 (json/sarif), and both are
    // pinned by empty-scan-fail-closed.test.ts's "explicit empty scope"
    // block.
    //
    // Counting `stats.filesScanned` rather than `results.length` matters:
    // `results` holds only files WITH findings, so a clean scan of 500 files
    // has `results.length === 0` and must stay exit 0. `filesScanned` counts
    // every file actually opened and scanned, findings or not.
    // Skipped when something was recorded as unscannable: the INCOMPLETE path
    // below then runs, naming the file and the remedy in every format, which
    // says more than "resolved to no files".
    if (!staged && stats.filesScanned === 0 && unreadable.length === 0) {
      console.error(
        chalk.red('❌ Cannot establish a result:'),
        chalk.white(
          'vault-guard: nothing was scanned. The scan target resolved to no ' +
            'files; in CI this is a could-not-run, not a clean pass. Check ' +
            'that the action runs at the repository root.',
        ),
      );
      return COULD_NOT_RUN_EXIT;
    }

    // Merge bus diagnostics
    diagnostics.push(...bus.drain());

    // In pull-request mode the baseline is the base ref's, already read and
    // parsed with the config. A baseline the head rewrote is a proposal, not a
    // suppression list: pre-computing the fingerprint of the finding you are
    // adding is the cheapest of all the ways to mute this scanner.
    const baselineLoad = controls
      ? {
          sourcePath: controls.baselinePath ?? undefined,
          fingerprints: controls.baseline,
          parseError: controls.baselineParseError ?? undefined,
        }
      : loadBaseline(outputBase);
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
    // Pull-request mode counts the ignore list while building its file set;
    // every other path counts it in `skips`.
    const configIgnored =
      controls && !staged ? (prSkips.configIgnoredFiles ?? 0) : skips.configIgnored;
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
      // Always present (even at zero): a muted scanner must say so.
      inline_suppressed: inlineSuppressed.count,
      inline_suppressed_critical_vendor: inlineSuppressed.criticalVendorAnchored,
      ...(controls && !staged
        ? {
            vendored_dirs_skipped: prSkips.dirCount,
            type_filtered_files: prSkips.typeFilteredFiles,
          }
        : {}),
      // A plain directory walk has the same type filter; it was silent there.
      ...(!controls && !staged ? { type_filtered_files: skips.typeFiltered } : {}),
      // Both are stated every run, even at zero: a skip by extension or by the
      // project's own ignore list is a decision the run must say it made.
      binary_files_skipped: skips.binary,
      config_ignored_files: configIgnored,
      ...(unreadable.length > 0
        ? {
            unscannable_files: unreadable.length,
            // Which files, why, and the exact exclude that would declare each.
            unscannable: unreadable.map(u => ({
              file: u.file,
              kind: u.kind ?? 'read_error',
              ...(u.exclude ? { exclude: u.exclude } : {}),
            })),
          }
        : {}),
    };

    // A file vault-guard could not read, or whose scan blew the budget, or a
    // named target that is not there, is a file it did not check, so the run
    // cannot claim to have cleared the tree, the commit or the pull request.
    // This is enforced here rather than left to a "N warning(s)" line the
    // caller has to notice, on EVERY path: staged, directory and pull-request.
    //
    // Directory and pull-request runs used to carry on and exit 0 here, on the
    // theory that unreadable entries in a walked tree are ordinary (root-owned
    // caches, sockets). That is true of a developer's own scratch directory and
    // false of the thing a CI gate is judging: a file that is tracked in the
    // repository and cannot be read is exactly the file nobody checked. The way
    // out is deliberate rather than silent: fix the file, or list it under
    // `ignore.paths` in the config, which is then counted and reported.
    const scanIncomplete = unreadable.length > 0;
    // Exit 2 is already this CLI's "cannot vouch for the result" code -- the
    // GitError branch above uses it for the same reason. Exit 1 means
    // "scanned fine, found something", which this run did not establish.
    const INCOMPLETE_SCAN_EXIT = 2;

    // Upgrade notice for the 1.4.0 default change. Before 1.4.0 any finding
    // failed the scan; now the implicit default is `medium`. When that
    // difference is what decides this run's outcome (findings exist, none
    // block, and the user never chose a threshold), say so once on stderr  -- 
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
      process.stdout.write(
        formatJson(results, { diagnostics, run, cwd: outputBase, trustBase }) + '\n',
      );
      if (scanIncomplete) {
        // stdout carries the document; the reason and the remedy go to stderr,
        // so the Action and any wrapper that shows stderr can say why.
        reportIncomplete(unreadable, staged, trustBase);
        return INCOMPLETE_SCAN_EXIT;
      }
      return blocking === 0 ? 0 : 1;
    }

    if (format === 'sarif') {
      // `--staged` reads paths from the git index, so the repository root is
      // the right base there -- not the cwd, which a hook invoked from a
      // subdirectory would otherwise make the base for files above it.
      const scanRoot = staged ? outputBase : resolveScanRoot(targetPaths, cwd);
      process.stdout.write(
        formatSarif(results, { diagnostics, run, scanRoot, cwd: outputBase, trustBase }) + '\n',
      );
      if (scanIncomplete) {
        reportIncomplete(unreadable, staged, trustBase);
        return INCOMPLETE_SCAN_EXIT;
      }
      return blocking === 0 ? 0 : 1;
    }

    // Text mode: print one-line diagnostic summary when any non-fatal issues occurred
    if (diagnostics.length > 0) {
      console.error(
        chalk.yellow(`⚠️  ${diagnostics.length} warning(s) -- run with --json for details`),
      );
    }

    // Pull-request mode states what it read and what it refused to apply,
    // every run, including the run where the answer is "nothing". A reviewer
    // reading a green tick needs to know that the tick was produced against
    // the base ref's rules rather than against whatever the pull request said
    // the rules were.
    if (trustBase) {
      console.log(
        chalk.gray(`Control inputs: base ref "${trustBase.ref}" (pull-request mode)`),
      );
      if (trustBase.proposals.length === 0) {
        console.log(chalk.gray('Proposed, not applied: none'));
      } else {
        for (const proposal of trustBase.proposals) {
          console.log(chalk.yellow(`Proposed, not applied: ${proposal}`));
        }
      }
      // Not on the staged path: its file list comes from the index and never
      // consults either filter, so both numbers are structurally zero there
      // and printing "0 skipped" would be a reassurance the run did not earn.
      if (!staged) {
        const names = prSkips.dirNames.length > 0 ? ` (${prSkips.dirNames.join(', ')})` : '';
        const vendoredLine = `Vendored directories skipped: ${prSkips.dirCount}${names}`;
        // Yellow when non-zero: a root-level vendored name still mutes by
        // design, so a non-zero count is a thing a reviewer has to weigh, in
        // the same colour as a proposal rather than the grey of a tally.
        console.log(prSkips.dirCount > 0 ? chalk.yellow(vendoredLine) : chalk.gray(vendoredLine));
        console.log(
          chalk.gray(`Files skipped by type or name: ${prSkips.typeFilteredFiles}`),
        );
      }
    }

    // Suppression visibility: state both suppression counts every run, even at
    // zero. A suppression is the user's decision and must be visible -- a
    // scanner that can be silenced without saying so manufactures false
    // confidence.
    const inlineWord = inlineSuppressed.count === 1 ? 'directive' : 'directives';
    // The critical vendor-anchored subset is appended only when it is non-zero.
    // Stating "0 of them" on every clean run would add a clause to a line
    // people read at a glance without adding information; the JSON carries it
    // unconditionally for anything that parses rather than reads.
    const criticalClause =
      inlineSuppressed.criticalVendorAnchored > 0
        ? `, ${inlineSuppressed.criticalVendorAnchored} of them on a critical vendor-anchored finding`
        : '';
    console.log(
      chalk.gray(
        `Suppressed: ${baselineSuppressed} by baseline, ` +
          `${inlineSuppressed.count} by inline ignore ${inlineWord}${criticalClause}`,
      ),
    );

    // What the run declined to open. In text mode a line appears only when it
    // is non-zero, because the plain-mode summary is pinned byte for byte (see
    // the before-state test) and a clean run reads at a glance; JSON and SARIF
    // state every count, including zero, for anything that parses rather than
    // reads. A plain directory walk has the same type filter pull-request mode
    // reports above.
    if (!trustBase && !staged && skips.typeFiltered > 0) {
      console.log(chalk.gray(`Files skipped by type or name: ${skips.typeFiltered}`));
    }
    if (configIgnored > 0) {
      console.log(
        chalk.gray(`Excluded by config ignore: ${configIgnored} (declared in the config "ignore" list)`),
      );
    }
    if (skips.binary > 0) {
      console.log(chalk.gray(`Binary files skipped: ${skips.binary}`));
    }

    if (scanIncomplete) {
      reportIncomplete(unreadable, staged, trustBase, () => {
        // Anything that DID scan is still worth showing; the reader needs both
        // "here is what I found" and "here is what I never looked at".
        if (results.length > 0) {
          console.error('');
          displayScanResults(results, blocking, outputBase);
        }
      });
      return INCOMPLETE_SCAN_EXIT;
    }

    if (results.length === 0) {
      console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
      return 0;
    }

    displayScanResults(results, blocking, outputBase);

    if (blocking === 0) {
      // Findings exist but all sit below the gate. Say so explicitly -- a silent
      // exit 0 after printing findings reads like a bug.
      console.log(
        chalk.white(
          `${totalMatches} finding(s), none at or above severity "${failOn}" -- not failing the gate.`,
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
    return COULD_NOT_RUN_EXIT;
  }
}
