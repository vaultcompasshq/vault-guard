import {
  SecretScanner,
  loadConfig,
  ConfigError,
  GitError,
  mapPatternRejectionReasonToDiagnosticCode,
  getGitStagedEntries,
  getGitWorkTreeRoot,
  GitContentSource,
  cleanGitEnv,
  copyKey,
  dropHeaderOnlyTwins,
  type TrackedEntry,
  isInsideGitWorkTree,
  DiagnosticBus,
  loadBaseline,
  BaselineRefusedError,
  applyBaseline,
  findGitEntryRoot,
  resolveFailOn,
  countBlockingMatches,
  FAIL_ON_VALUES,
  loadTrustedControls,
  TrustBaseError,
  repositoryLabel,
  ATTRIBUTES_PROPOSAL_LINE,
  ATTRIBUTES_NOTE_LINE,
  newPlainFileSetInfo,
  listTrackedIgnoredFiles,
  BINARY_FAMILIES,
  type FailOnThreshold,
  type PullRequestSkips,
  type TrustBaseReport,
  type TrustedControls,
  type VaultGuardConfig,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import fs from 'fs';
import { basename, dirname, isAbsolute, join as pathJoin, relative, resolve as pathResolve } from 'path';
import {
  scanFilesAsync,
  scanFileListAsync,
  displayScanResults,
  formatJson,
  formatSarif,
  resolveScanRoot,
  formatExcludeEntry,
  excludeEntryNote,
  newContentReport,
  newRunSkipCounts,
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
 * The root baseline entries and content fingerprints are keyed against: the
 * git work tree root when the anchor is inside git (a `.git` entry decides,
 * and a git failure then throws GitError, which is exit 2), the anchor
 * otherwise.
 */
export function resolveContentRoot(anchor: string, staged = false): string {
  if (findGitEntryRoot(anchor) === null) return canonicalPath(anchor);
  // A plain or pull-request run uses a clean git environment: a hook's
  // GIT_DIR or GIT_WORK_TREE must not move the root a path is judged against.
  // `--staged` keeps the inherited one, as for every staged git call
  // (design 2026-10-12, 2.7 and 6).
  return staged ? getGitWorkTreeRoot(anchor) : getGitWorkTreeRoot(anchor, cleanGitEnv());
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
/** A path for a stderr line: JSON-escaped when it holds a control character. */
function printablePath(p: string): string {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f]/.test(p) ? JSON.stringify(p) : p;
}

/** A path of more than 60 characters shortened in the middle to 60, with `...`. */
export function shortenMiddle(p: string, max = 60): string {
  if (p.length <= max) return p;
  const keep = max - 3;
  const front = Math.ceil(keep / 2);
  return `${p.slice(0, front)}...${p.slice(p.length - (keep - front))}`;
}

/**
 * The INCOMPLETE block's first line (design 2026-10-17, section 7): the label,
 * then the first unscannable file in sorted order, then the counts, so a
 * wrapper that quotes the first stderr line and caps it at 160 characters
 * keeps the name and only ever loses counts.
 */
export function reportIncomplete(
  unreadableIn: UnreadableFile[],
  staged: boolean,
  trustBase: TrustBaseReport | undefined,
  between?: () => void,
): void {
  // Sorted, so the first file named is the same on every run (entries are
  // pushed in completion order from concurrent batches).
  const unreadable = [...unreadableIn].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
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
  const first = unreadable.length > 0 ? `First: ${shortenMiddle(printablePath(unreadable[0].file))}. ` : '';
  console.error(chalk.red.bold('❌ INCOMPLETE:'), chalk.white(`${first}${parts.join('; ')}\n`));
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
      // The directory is resolved, the last component is not: a tracked
      // symlink named as a target is judged by where it sits, never by where
      // it points (design 2026-10-12, 2.1).
      // A link to a directory is still resolved, as before.
      const given = pathResolve(cwd, target);
      const namedFileLink = ((): boolean => {
        try {
          if (!fs.lstatSync(given).isSymbolicLink()) return false;
        } catch {
          return false;
        }
        try {
          return !fs.statSync(given).isDirectory();
        } catch {
          return true;
        }
      })();
      const abs = namedFileLink ? pathJoin(canonicalPath(dirname(given)), basename(given)) : canonicalPath(given);
      const rel = relative(controls.repoRoot, abs);
      if (rel.startsWith('..') || isAbsolute(rel)) {
        console.error(
          chalk.red('❌ Cannot establish the trust base:'),
          chalk.white(
            `the scan target ${target} is outside ${repositoryLabel(controls.repoRoot)}, ` +
              `the checkout that the base ref "${trustBaseRef}" was read from, so pull-request mode would have no ` +
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
          attributesChanged: controls.attributesChanged,
          attributesPaths: controls.attributesPaths,
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

  // The working-tree baseline is loaded here, beside the config, so a linked
  // baseline fails the run before anything is scanned or announced (design
  // 2026-10-12, 4.2). Pull-request mode already read the base ref's.
  let plainBaseline: ReturnType<typeof loadBaseline> | undefined;
  if (!controls) {
    try {
      plainBaseline = loadBaseline(outputBase);
    } catch (e) {
      if (e instanceof BaselineRefusedError) {
        console.error(chalk.red('❌'), chalk.white(e.message));
        return COULD_NOT_RUN_EXIT;
      }
      throw e;
    }
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

  // Advisory stderr lines of the run, collected rather than printed, so that
  // on a run that cannot complete the INCOMPLETE line is the first thing on
  // stderr (design 2026-10-17, section 7). On a complete run they are printed
  // as soon as the scan is known to be complete, in their old order.
  const deferred: string[] = [];
  const defer = (line: string): void => {
    deferred.push(line);
  };
  const flushDeferred = (): void => {
    for (const line of deferred.splice(0)) console.error(line);
  };

  if (extraPatternDiagnostics.length > 0 && format === 'text') {
    for (const ctx of extraPatternDiagnostics) {
      defer(
        `${chalk.yellow('⚠️  extra_pattern rejected:')} ${chalk.white(`${ctx.patternId} (${ctx.reason}) -- ${ctx.detail}`)}`,
      );
    }
    defer(
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
  const skips = newRunSkipCounts();
  // Progress is for a person watching a terminal. In a pipe or a CI log it is
  // noise, and its carriage return would join the next stderr line to it.
  const showProgress = format === 'text' && process.stderr.isTTY === true;
  // Files the run reached but could not vouch for: unreadable, over the scan
  // budget, or a named target that is not there. Fatal (exit 2) on every path.
  const unreadable: UnreadableFile[] = [];
  // Where a plain directory scan's file set came from, and what it has to say
  // about it (section 2 of the 2026-10-11 design).
  const plainFileSet = newPlainFileSetInfo();
  // Every file actually opened, so the tracked counts are of files SCANNED,
  // not merely listed.
  const scannedFiles = new Set<string>();
  // Where content was read from (design 2026-10-12, section 2).
  const contentReport = newContentReport();
  let stagedContent: GitContentSource | undefined;
  const t0 = Date.now();

  try {
    let results;

    if (staged) {
      if (!isInsideGitWorkTree(cwd)) {
        console.error(chalk.red('❌ Error:'), chalk.white('Not a git repository (or outside a work tree).'));
        flushDeferred();
        return COULD_NOT_RUN_EXIT;
      }

      let stagedFiles: string[];
      try {
        // outputBase was resolved above, before the config load. If that
        // lookup failed it was left as `cwd` and NOT reported; this call
        // repeats it internally and is where the failure surfaces.
        const staged = getGitStagedEntries(cwd);
        stagedFiles = staged.map(e => e.path);
        // The blobs are read by the object ids this listing named, with the
        // inherited environment (a hook's index, a GIT_DIR-only repository).
        const root = getGitWorkTreeRoot(cwd);
        const entries = new Map<string, TrackedEntry>();
        for (const e of staged) {
          entries.set(e.path, { repoTop: root, mode: e.mode, oid: e.oid, worktreeAlso: false, filtered: false });
        }
        stagedContent = new GitContentSource('index', process.env, entries);
      } catch (e) {
        if (e instanceof GitError) {
          console.error(chalk.red('❌ Git error:'), chalk.white(e.message));
          console.error(
            chalk.gray(
              '   vault-guard cannot determine which files are staged.\n' +
                '   Refusing to produce a ✅ result that may be incorrect.\n',
            ),
          );
          flushDeferred();
          return 2;
        }
        throw e;
      }

      if (format === 'text') {
        console.log(chalk.blue('🔍 Scanning'), chalk.cyan('git staged files'));
        if (stagedFiles.length === 0) {
          console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('Nothing staged -- nothing to scan\n'));
          flushDeferred();
          return 0;
        }
        console.log(chalk.gray(`   ${stagedFiles.length} file(s) in the index\n`));
      }
      try {
      results = await scanFileListAsync(stagedFiles, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: showProgress,
        warn: defer,
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
        content: contentReport,
        ...(stagedContent ? { contentSource: stagedContent } : {}),
      });
      } finally {
        // Wait, bounded, for the reader's git to exit, so none outlives the
        // scan. Never rejects, so an earlier error and the exit code stand.
        await stagedContent?.closeAndWait();
      }
    } else {
      results = await scanFilesAsync(targetPaths, scanner, {
        verbose: format === 'text',
        skipBinary: true,
        progress: showProgress,
        warn: defer,
        bus,
        stats,
        unreadable,
        skips,
        configIgnorePatterns,
        inlineSuppressed,
        scannedFiles,
        content: contentReport,
        ...(controls
          ? {
              pullRequest: {
                headTreeFiles: controls.headTreeFiles,
                headBlobs: controls.headBlobs,
                repoRoot: controls.repoRoot,
                skipped: prSkips,
              },
            }
          : { plainFileSet }),
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
      flushDeferred();
      return COULD_NOT_RUN_EXIT;
    }

    // Merge bus diagnostics
    diagnostics.push(...bus.drain());

    // Computed before any advisory stderr is written (design 2026-10-17, 7).
    // A file vault-guard could not read, or whose scan blew the budget, or a
    // named target that is not there, is a file it did not check; see below.
    const scanIncomplete = unreadable.length > 0;

    // In pull-request mode the baseline is the base ref's, already read and
    // parsed with the config. A baseline the head rewrote is a proposal, not a
    // suppression list: pre-computing the fingerprint of the finding you are
    // adding is the cheapest of all the ways to mute this scanner.
    const baselineLoad = controls
      ? {
          sourcePath: controls.baselinePath ?? undefined,
          fingerprints: controls.baseline,
          entries: controls.baselineEntries,
          parseError: controls.baselineParseError ?? undefined,
        }
      : (plainBaseline ?? { fingerprints: new Set<string>() });
    if (baselineLoad.parseError) {
      diagnostics.push({
        code: 'baseline.invalid',
        severity: 'warning',
        ctx: { path: baselineLoad.sourcePath ?? '', detail: baselineLoad.parseError },
      });
      if (format === 'text') {
        defer(
          `${chalk.yellow('⚠️  Baseline file invalid:')} ${chalk.white(baselineLoad.parseError)} ` +
            chalk.gray(baselineLoad.sourcePath ? `(${baselineLoad.sourcePath})` : ''),
        );
      }
    }
    // A complete run prints what it collected here, where those lines used to
    // appear relative to the rest of stderr. An incomplete one prints them
    // after the INCOMPLETE block.
    if (!scanIncomplete) flushDeferred();

    // Baseline entries and content fingerprints are keyed relative to the
    // repository root inside git, so a baseline written at the root matches a
    // run from anywhere in the tree.
    const contentRoot = controls
      ? controls.repoRoot
      : resolveContentRoot(outputBase, staged);
    const { results: afterBaseline, suppressed: baselineSuppressed } = applyBaseline(
      results,
      baselineLoad,
      {
        anchor: outputBase,
        contentRoot,
        isValueBearing: id => scanner.isValueBearing(id),
        // A header-only entry's file digest is taken over the bytes the
        // finding came from, kept by the scan: the blob for a blob match, the
        // disk copy for a worktree match. Nothing is re-read after the scan.
        readBytes: (f: string, source, stage) => {
          const kept = contentReport.kept.get(copyKey(f, source, stage));
          if (kept !== undefined) return kept;
          if (source === undefined || source === 'file' || source === 'worktree') return fs.readFileSync(f);
          throw new Error(`no bytes kept for ${f}`);
        },
      },
    );
    // 2.5, step 3: a disk-copy header-only match whose unsuppressed blob twin
    // is reported is the same finding, reported once.
    results = dropHeaderOnlyTwins(afterBaseline);
    // Kept bytes are released once the baseline has been applied.
    contentReport.kept.clear();
    const baselineEntriesLoaded = baselineLoad.entries?.length ?? 0;

    const durationMs = Date.now() - t0;
    // Pull-request mode counts the ignore list while building its file set;
    // every other path counts it in `skips`.
    const configIgnored =
      controls && !staged ? (prSkips.configIgnoredFiles ?? 0) : skips.configIgnored;
    const totalMatches = results.reduce((n, r) => n + r.matches.length, 0);
    const blocking = countBlockingMatches(results, failOn);

    // Where the file set came from, and the tracked files it scanned that the
    // walk used to skip, each counted only if it was actually scanned.
    const fileSetKind: 'git' | 'walk' | 'head-tree' | 'index' = staged
      ? 'index'
      : controls
        ? 'head-tree'
        : (plainFileSet.fileSet ?? 'walk');
    const countScanned = (files: Iterable<string>): number => {
      let n = 0;
      for (const f of files) if (scannedFiles.has(f)) n++;
      return n;
    };
    let trackedIgnoredScanned = 0;
    let trackedNestedVendoredScanned = 0;
    if (fileSetKind === 'head-tree' && controls) {
      trackedIgnoredScanned = countScanned(listTrackedIgnoredFiles(controls.repoRoot));
      trackedNestedVendoredScanned = countScanned(prSkips.nestedVendored ?? []);
    } else if (fileSetKind === 'git') {
      trackedIgnoredScanned = countScanned(plainFileSet.trackedIgnored);
      trackedNestedVendoredScanned = countScanned(plainFileSet.trackedNestedVendored);
    }
    const plainVendoredNames = [...plainFileSet.vendoredDirNames].sort();
    const mismatches = [...skips.typeMismatch].sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
    const trackedCounts =
      fileSetKind === 'git' || fileSetKind === 'head-tree'
        ? {
            tracked_ignored_files_scanned: trackedIgnoredScanned,
            tracked_nested_vendored_scanned: trackedNestedVendoredScanned,
          }
        : {};

    const run = {
      duration_ms: durationMs,
      files_scanned: stats.filesScanned,
      bytes_scanned: stats.bytesScanned,
      patterns_active: scanner.getActivePatternCount(),
      diagnostics_count: diagnostics.length,
      fail_on: failOn,
      blocking_matches: blocking,
      ...(baselineSuppressed > 0 ? { baseline_suppressed: baselineSuppressed } : {}),
      baseline_entries: baselineEntriesLoaded,
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
      // Inside git a root-level vendored name still mutes by design, as in
      // pull-request mode, so the count is stated the same way.
      ...(fileSetKind === 'git' ? { vendored_dirs_skipped: plainVendoredNames.length } : {}),
      // Both are stated every run, even at zero: a skip by extension or by the
      // project's own ignore list is a decision the run must say it made.
      binary_files_skipped: skips.binary,
      // Design 2026-10-17, section 5: every one always present, zero included.
      binary_files_skipped_by_family: { ...skips.binaryByFamily },
      binary_worktree_copies_skipped: skips.binaryWorktreeCopies,
      binary_type_mismatch_scanned: mismatches.length,
      binary_type_mismatch: mismatches,
      scan_budget_retimed: skips.retimed,
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
      file_set: fileSetKind,
      ...trackedCounts,
      ...(fileSetKind === 'git' ? { tracked_files_missing: plainFileSet.trackedMissing.length } : {}),
      content_source:
        contentReport.blobFiles > 0 || fileSetKind !== 'walk' ? ('git' as const) : ('disk' as const),
      worktree_copies_scanned: contentReport.worktreeCopies.size,
      worktree_undecodable: contentReport.undecodable,
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
    // (`scanIncomplete` is computed above, before any advisory stderr.)
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
    // Never on a run that exits 2 (design 2026-10-17, section 8): the note
    // describes a verdict, and such a run has none. Wrappers quote the first
    // stderr line as the reason, and this note became that reason.
    if (!scanIncomplete && gateIsImplicitDefault && totalMatches > 0 && blocking === 0) {
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

    // The directory every printed path is relative to: the repository root for
    // `--staged`, otherwise the scan target when it sits outside the cwd, else
    // the cwd. JSON, SARIF and text all use it, so one finding is spelled one
    // way in every format.
    const displayRoot = staged ? outputBase : resolveScanRoot(targetPaths, cwd);

    if (format === 'json') {
      // The document is still emitted: CI wants the artifact even when the
      // run failed, and `run.unscannable_files` plus the error-severity
      // `file.read_error` diagnostics inside it say why.
      // `scanRoot` only decides how `results[].file` is DISPLAYED (relative to
      // the scan target when that sits outside the cwd); fingerprints are
      // computed from `cwd` and the original path, as before.
      process.stdout.write(
        formatJson(results, { diagnostics, run, scanRoot: displayRoot, cwd: outputBase, contentRoot, trustBase }) +
          '\n',
      );
      if (scanIncomplete) {
        // stdout carries the document; the reason and the remedy go to stderr,
        // so the Action and any wrapper that shows stderr can say why.
        reportIncomplete(unreadable, staged, trustBase);
        flushDeferred();
        return INCOMPLETE_SCAN_EXIT;
      }
      return blocking === 0 ? 0 : 1;
    }

    if (format === 'sarif') {
      // `--staged` reads paths from the git index, so the repository root is
      // the right base there -- not the cwd, which a hook invoked from a
      // subdirectory would otherwise make the base for files above it.
      process.stdout.write(
        formatSarif(results, { diagnostics, run, scanRoot: displayRoot, cwd: outputBase, contentRoot, trustBase }) +
          '\n',
      );
      if (scanIncomplete) {
        reportIncomplete(unreadable, staged, trustBase);
        flushDeferred();
        return INCOMPLETE_SCAN_EXIT;
      }
      return blocking === 0 ? 0 : 1;
    }

    // Text mode: print one-line diagnostic summary when any non-fatal issues
    // occurred. On an incomplete run it follows the INCOMPLETE block instead.
    const warningSummary = (): void => {
      if (diagnostics.length > 0) {
        console.error(
          chalk.yellow(`⚠️  ${diagnostics.length} warning(s) -- run with --json for details`),
        );
      }
    };
    if (!scanIncomplete) warningSummary();

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
        let attributesNoted = false;
        for (const proposal of trustBase.proposals) {
          console.log(chalk.yellow(`Proposed, not applied: ${proposal}`));
          if (!attributesNoted && proposal.startsWith(ATTRIBUTES_PROPOSAL_LINE)) {
            attributesNoted = true;
            console.log(chalk.gray(`   ${ATTRIBUTES_NOTE_LINE}`));
          }
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
    // The plain file set inside git: what it scanned that the walk used to
    // skip, the root-level vendored names that still mute by design, and
    // tracked files that are not in the work tree. Each only when non-zero.
    if (fileSetKind === 'git' && plainVendoredNames.length > 0) {
      console.log(
        chalk.yellow(
          `Vendored directories skipped: ${plainVendoredNames.length} (${plainVendoredNames.join(', ')})`,
        ),
      );
    }
    if (trackedIgnoredScanned > 0) {
      console.log(
        chalk.gray(`Tracked files that .gitignore would hide, scanned: ${trackedIgnoredScanned}`),
      );
    }
    if (trackedNestedVendoredScanned > 0) {
      console.log(
        chalk.gray(
          `Tracked files under nested vendored directories, scanned: ${trackedNestedVendoredScanned}`,
        ),
      );
    }
    if (fileSetKind === 'git' && plainFileSet.trackedMissing.length > 0) {
      console.log(
        chalk.yellow(
          `Tracked files missing from the working tree: ${plainFileSet.trackedMissing.length}` +
            ' (deleted locally or left out by a sparse checkout, not scanned)',
        ),
      );
    }
    if (contentReport.worktreeCopies.size > 0) {
      console.log(
        chalk.gray(
          `Tracked files whose working-tree copy differs, both scanned: ${contentReport.worktreeCopies.size}`,
        ),
      );
    }
    if (contentReport.undecodable.length > 0) {
      const named = contentReport.undecodable
        .slice(0, 3)
        .map(u => `${u.file}: ${u.encoding}`)
        .join(', ');
      const more = contentReport.undecodable.length > 3 ? ', ...' : '';
      console.log(
        chalk.yellow(
          `Working-tree copies in an encoding vault-guard cannot decode, scanned as UTF-8: ` +
            `${contentReport.undecodable.length} (${named}${more})`,
        ),
      );
    }
    if (!trustBase && !staged && skips.typeFiltered > 0) {
      console.log(chalk.gray(`Files skipped by type or name: ${skips.typeFiltered}`));
    }
    if (configIgnored > 0) {
      console.log(
        chalk.gray(`Excluded by config ignore: ${configIgnored} (declared in the config "ignore" list)`),
      );
    }
    // Binary skips by content agreement (design 2026-10-17, section 5), each
    // line only when non-zero, so a clean run with no binary files prints
    // byte for byte what it printed before.
    if (skips.binary > 0) {
      const families = BINARY_FAMILIES.filter(f => skips.binaryByFamily[f] > 0)
        .map(f => `${f} ${skips.binaryByFamily[f]}`)
        .join(', ');
      console.log(chalk.gray(`Binary files skipped: ${skips.binary} (content matched the extension: ${families})`));
    }
    if (skips.binaryWorktreeCopies > 0) {
      console.log(chalk.gray(`Working-tree copies skipped as binary, blob scanned: ${skips.binaryWorktreeCopies}`));
    }
    if (mismatches.length > 0) {
      const named = mismatches.slice(0, 3).map(m => printablePath(m.file)).join(', ');
      const more = mismatches.length > 3 ? ` and ${mismatches.length - 3} more` : '';
      console.log(
        chalk.yellow(`Files named as binary but holding text, scanned as text: ${mismatches.length} (${named}${more})`),
      );
    }
    if (skips.retimed > 0) {
      console.log(chalk.gray(`Files re-timed after a slow first scan, then trusted: ${skips.retimed}`));
    }

    if (scanIncomplete) {
      reportIncomplete(unreadable, staged, trustBase, () => {
        // Anything that DID scan is still worth showing; the reader needs both
        // "here is what I found" and "here is what I never looked at".
        if (results.length > 0) {
          console.error('');
          displayScanResults(results, blocking, displayRoot);
        }
      });
      // Everything else this run had to say on stderr follows the block.
      flushDeferred();
      warningSummary();
      return INCOMPLETE_SCAN_EXIT;
    }

    if (results.length === 0) {
      console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
      return 0;
    }

    displayScanResults(results, blocking, displayRoot);

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
    if (error instanceof GitError) {
      // Inside a git work tree the file set comes from git; a git failure there
      // is could-not-run, never a quiet fall back to the walk.
      console.error(chalk.red('❌ Git error:'), chalk.white(error.message));
      flushDeferred();
      return COULD_NOT_RUN_EXIT;
    }
    console.error(chalk.red('❌ Fatal error:'), chalk.white(String(error)));
    flushDeferred();
    return COULD_NOT_RUN_EXIT;
  }
}
