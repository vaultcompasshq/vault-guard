import path from 'path';
import fs from 'fs';
import { execFileSync } from 'child_process';
import {
  SecretScanner,
  getFilesToScan,
  getFilesToScanAsync,
  buildConfigIgnoreFilter,
  scanTextFileSync,
  MAX_SCAN_FILE_BYTES,
  FileTooLargeError,
  readGitIndexFile,
  applyPathAwareSeverity,
  formatJson as formatJsonResults,
  formatSarif as formatSarifResults,
  getPullRequestFilesToScan,
  type JsonOutput,
  type JsonRunMetadata,
  type TrustBaseReport,
  type PullRequestSkips,
  type ScanSkipCounts,
  type FileScanResult,
  type Diagnostic,
  type DiagnosticBus,
  type IgnoreDirectiveHits,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';

export type { JsonOutput, JsonRunMetadata };
export interface ScanFormatOptions {
  diagnostics?: Diagnostic[];
  run?: JsonRunMetadata;
  /**
   * Directory the scan actually walked. SARIF uris are relativized against it
   * so an out-of-tree target does not publish absolute local paths. Ignored by
   * `formatJson`, whose `file` paths stay cwd-relative.
   */
  scanRoot?: string;
  /**
   * Base for `formatJson`'s `file` paths and for match fingerprints, and the
   * anchor SARIF resolves `scanRoot` against. Defaults to `process.cwd()`,
   * which is right for a directory scan.
   *
   * A `--staged` run must pass the repository root instead. Its file list
   * comes from the index and therefore spans the whole worktree, including
   * files ABOVE the cwd when the hook runs from a subdirectory. Those fall
   * out of `path.relative(cwd, ...)` and would otherwise be serialized as
   * absolute machine paths, and fingerprinted against a base that changes
   * with whatever directory the caller happened to be standing in.
   */
  cwd?: string;
  /** Pull-request mode's report, when the run was given `--trust-base`. */
  trustBase?: TrustBaseReport;
}

export function formatJson(results: ScanResult[], opts: ScanFormatOptions = {}): string {
  return formatJsonResults(results, {
    cwd: opts.cwd ?? process.cwd(),
    diagnostics: opts.diagnostics,
    run: opts.run,
    trustBase: opts.trustBase,
  });
}
export function formatSarif(results: ScanResult[], opts: ScanFormatOptions = {}): string {
  return formatSarifResults(results, {
    cwd: opts.cwd ?? process.cwd(),
    scanRoot: opts.scanRoot,
    diagnostics: opts.diagnostics,
    run: opts.run,
    trustBase: opts.trustBase,
  });
}

/**
 * The directory a SARIF run should treat as `%SRCROOT%`.
 *
 * Only a single target gets its own root. With several targets there is no one
 * directory that contains them all except a common ancestor, and that ancestor
 * is often `/` or the user's home, which would turn every uri into a
 * "relative" path that still spells out the machine's layout. Falling back to
 * the cwd in that case keeps the pre-existing behaviour, where anything
 * outside the cwd simply stays absolute.
 */
export function resolveScanRoot(targetPaths: string[], cwd = process.cwd()): string {
  // The `scan` CLI command's positional is non-variadic, so it never passes
  // more than one path here; this branch exists for programmatic callers of
  // this function that scan several targets at once.
  if (targetPaths.length !== 1) return cwd;
  const abs = path.resolve(cwd, targetPaths[0]);

  // The target becomes the root ONLY when it is genuinely outside cwd. An
  // in-tree absolute target (or one equal to cwd) must not narrow %SRCROOT%
  // to a subdirectory: GitHub Code Scanning resolves %SRCROOT% from its own
  // knowledge of the checkout, which is cwd, so a uri relative to a narrower
  // root would end up naming a different file.
  const rel = path.relative(cwd, abs);
  if (rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel))) return cwd;

  try {
    return fs.statSync(abs).isDirectory() ? abs : path.dirname(abs);
  } catch {
    // Unreadable or missing target: the scan will report nothing for it, so the
    // base does not matter. Its parent is still the closest honest answer.
    return path.dirname(abs);
  }
}

/**
 * The directory that test / documentation / locale path context is judged
 * relative to, for one scan target. NOT the same question as
 * {@link resolveScanRoot}, which picks SARIF's `%SRCROOT%` and returns the cwd
 * whenever the target is inside it. That is wrong for context: an ancestor cwd
 * (a workspace with the repo checked out at `website/`, HOME, or `/` in a
 * container) would put every directory between it and the repo back into the
 * judged path.
 *
 * The root is the git work tree containing the target; failing that, the
 * target directory itself (its parent for a file target). Directories above it
 * never count.
 */
export function resolveContextRoot(target: string, cwd = process.cwd()): string {
  const abs = path.resolve(cwd, target);
  let dir: string;
  try {
    dir = fs.statSync(abs).isDirectory() ? abs : path.dirname(abs);
  } catch {
    dir = path.dirname(abs);
  }
  try {
    const top = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      cwd: dir,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (top) return top;
  } catch {
    // Not a git work tree (or git is missing): fall through to the directory.
  }
  return dir;
}

/**
 * The most one file may weigh and still be scanned (32 MiB, the core constant,
 * which is also what `--staged` allows a blob). Files up to it are read and
 * scanned whole; above it a file is unscannable, never partly scanned.
 */
const MAX_FILE_SIZE = MAX_SCAN_FILE_BYTES;

/**
 * Record a file above the size limit as unscannable. Like an unreadable file it
 * makes the run exit 2, and it carries the exclude entry that would declare it.
 */
function recordTooLarge(
  displayFile: string,
  bytes: number,
  maxBytes: number,
  options: ScanOptions,
  exclude?: string,
): void {
  const reason = `${(bytes / 1024 / 1024).toFixed(1)} MiB: over ${Math.round(maxBytes / 1024 / 1024)} MiB, not scanned`;
  options.unreadable?.push({
    kind: 'too_large',
    file: displayFile,
    reason,
    ...(exclude ? { exclude } : {}),
  });
  options.bus?.add({
    code: 'file.read_error',
    severity: 'error',
    ctx: { file: displayFile, detail: reason },
  });
}

/**
 * Per-file scan budget (ms). This is a **post-hoc** detector, NOT a wall-clock
 * bound, and the distinction is load-bearing:
 *
 * Node's regex engine is **synchronous** and cannot be interrupted from
 * JavaScript. There is no point at which this code can abandon, preempt, or
 * time-bound a scan that is already running. The budget is therefore checked
 * AFTER `scanner.scan` / `scanContent` has returned, by comparing elapsed time.
 * A catastrophic pattern still runs to completion and still blocks the process
 * for however long it takes; measured, an 11.3s file scan reports over budget
 * only once those 11.3 seconds have already elapsed.
 *
 * What the budget buys is refusing to TRUST that result: an over-budget file is
 * recorded as unscannable, so the staged path fails closed rather than
 * publishing a "clean" verdict on a file whose scan behaved pathologically.
 * The built-in regex bounds are what actually bound time; this catches the case
 * where a future pattern edit or a user `extra_pattern` reintroduces a runaway
 * shape. Generous on purpose: a normal file scans in single-digit milliseconds.
 */
const DEFAULT_SCAN_BUDGET_MS = 5000;

const BINARY_EXTENSIONS = [
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip',
  '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.bin'
];

export type ScanResult = FileScanResult;

/**
 * Fold one file's inline ignore-directive suppressions into the run total and,
 * when any occurred, emit a `suppression.inline` diagnostic naming the
 * suppressed line numbers. A suppression is the user's own decision, and a
 * scanner that can be silenced without saying so manufactures false
 * confidence, so this is emitted rather than discarded.
 */
function recordInlineSuppression(
  hits: IgnoreDirectiveHits,
  displayFile: string,
  options: ScanOptions,
): void {
  if (hits.count === 0) return;
  if (options.inlineSuppressed) {
    options.inlineSuppressed.count += hits.count;
    options.inlineSuppressed.criticalVendorAnchored += hits.criticalVendorAnchored ?? 0;
  }
  options.bus?.add({
    code: 'suppression.inline',
    severity: 'warning',
    ctx: {
      file: displayFile,
      lines: [...new Set(hits.lines)].sort((a, b) => a - b),
      count: hits.count,
    },
  });
}

/**
 * Record a file whose scan blew the per-file budget (detected post-hoc, after
 * the synchronous scan returned; see DEFAULT_SCAN_BUDGET_MS). It is folded
 * into the same `unreadable` list an unreadable file uses, so `scanCommand`'s
 * existing fail-closed logic (staged -> exit 2) needs no change, and a distinct
 * `file.scan_timeout` diagnostic states why the file is not trusted. The `kind`
 * discriminator keeps the two apart in output: this file WAS read and scanned,
 * so calling it unreadable would be a lie.
 */
function recordBudgetExceeded(
  displayFile: string,
  elapsedMs: number,
  budgetMs: number,
  options: ScanOptions,
  exclude?: string,
): void {
  options.unreadable?.push({
    kind: 'scan_budget',
    file: displayFile,
    reason: `scan exceeded the ${budgetMs}ms budget (took ${Math.round(elapsedMs)}ms)`,
    ...(exclude ? { exclude } : {}),
  });
  options.bus?.add({
    code: 'file.scan_timeout',
    severity: 'error',
    ctx: { file: displayFile, elapsed_ms: Math.round(elapsedMs), budget_ms: budgetMs },
  });
}

/** Filled by scan runners when provided (files opened for secret scanning, bytes read). */
export interface ScanTelemetryStats {
  filesScanned: number;
  bytesScanned: number;
}

/**
 * One file whose result the run cannot vouch for. Two distinct causes share
 * this list because they have the same consequence (the staged path must fail
 * closed), but they are NOT the same event and output must not conflate them:
 *
 *   - `read_error`: the file was never examined; the read itself failed.
 *   - `scan_budget`: the file WAS read and scanned, but the scan took longer
 *     than the budget, so the result is not trusted. Calling this "could not be
 *     read" would be false.
 */
export interface UnreadableFile {
  /** Which of the two causes produced this entry. Defaults to a read failure. */
  kind?: 'read_error' | 'scan_budget' | 'too_large';
  /** cwd-relative where possible, for display and structured output. */
  file: string;
  /** Why the file's result cannot be trusted. */
  reason: string;
  /**
   * The `ignore.paths` entry that would exclude exactly this file, relative to
   * the root `ignore` patterns are matched against. Absent when the entry is
   * not a file the config could name (a missing target).
   */
  exclude?: string;
}

/**
 * Tallies of what the run declined to open, beyond the pull-request-only
 * counts: the walk's type filter, the config's own `ignore` list, and files the
 * extension rule skips at scan time.
 */
export interface RunSkipCounts extends ScanSkipCounts {
  /** Files skipped by {@link isBinaryFile} when the scanner reached them. */
  binary: number;
}

/**
 * The gitignore-style entry that excludes exactly `file`: its path relative to
 * `root`, anchored with a leading slash so it cannot match a same-named file
 * elsewhere, with the characters gitignore treats as syntax escaped.
 * Undefined when `file` is not under `root`.
 */
export function excludePatternFor(file: string, root: string): string | undefined {
  const rel = path.relative(path.resolve(root), path.resolve(file));
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return undefined;
  // Escaped: backslash, star and brackets, which gitignore reads as syntax, and
  // a trailing space, which it strips. NOT escaped: `?`, which already matches
  // itself (an escaped one matches nothing here), and `#` and `!`, which only
  // mean something at the start of a pattern and this one starts with a slash.
  const posix = rel
    .split(path.sep)
    .join('/')
    .replace(/([\\*[\]])/g, '\\$1')
    .replace(/ $/, '\\ ');
  return `/${posix}`;
}

/**
 * One plain sentence for an entry that contains a question mark, which the
 * gitignore matcher reads as "any single character" and cannot match literally,
 * so the entry may also exclude a similarly named file. Empty otherwise.
 */
export function excludeEntryNote(pattern: string): string {
  return pattern.includes('?')
    ? 'the question mark matches any single character in this entry, so it may also exclude a similarly named file'
    : '';
}

/** The entry as it is printed for pasting into the config: a JSON string. */
export function formatExcludeEntry(pattern: string): string {
  return JSON.stringify(pattern);
}

export interface ScanOptions {
  verbose?: boolean;
  maxSize?: number;
  skipBinary?: boolean;
  progress?: boolean;
  concurrency?: number;
  bus?: DiagnosticBus;
  stats?: ScanTelemetryStats;
  /**
   * Filled with one entry per file that was reached but could not be read,
   * so its contents were never examined.
   *
   * This is deliberately separate from the `file.read_error` diagnostic that
   * describes the same event. A diagnostic is advisory and gets summarised as
   * "N warning(s)"; this list is what the caller uses to decide whether the
   * run may claim success at all. `scanCommand` treats a non-empty list as
   * fatal (exit 2) on every path: staged, directory and pull-request.
   */
  unreadable?: UnreadableFile[];
  /**
   * Per-file scan budget in milliseconds, checked **post-hoc** (the scan is
   * synchronous and cannot be preempted; see {@link DEFAULT_SCAN_BUDGET_MS}).
   * A file whose scan is found to have exceeded it is recorded in
   * {@link ScanOptions.unreadable} (so the staged path fails closed) and
   * reported via a `file.scan_timeout` error diagnostic; a directory scan keeps
   * going. Defaults to {@link DEFAULT_SCAN_BUDGET_MS}.
   */
  scanBudgetMs?: number;
  /** Filled with what the run skipped without opening, so it can be reported. */
  skips?: RunSkipCounts;
  /**
   * Combined gitignore-style patterns from `config.ignore.paths` and
   * `config.ignore.patterns`. Applied to every file before scanning so that
   * `.vault-guard.json` `ignore` entries are honoured uniformly across
   * directory scans and staged-file scans.
   */
  configIgnorePatterns?: string[];
  /**
   * When true, read each path from the git index (`git show :path`) so
   * `--staged` matches what will actually be committed -- including `AD`
   * (added in index, deleted in worktree) and partially staged files.
   */
  fromGitIndex?: boolean;
  /** Repo root for `fromGitIndex` (defaults to `process.cwd()`). */
  cwd?: string;
  /**
   * Directory test / documentation / locale path context is judged relative
   * to. Defaults to `cwd` for a file list and to {@link resolveScanRoot} for a
   * directory scan, so directories ABOVE the scanned tree (a runner workspace
   * named `docs`, a temp dir named `loadtest`) can never count as context.
   */
  pathRoot?: string;
  /**
   * Accumulates the total number of findings suppressed by inline
   * `vault-guard: ignore-line` / `ignore-next-line` directives across every
   * file scanned. Each such file also emits a `suppression.inline` diagnostic
   * (via {@link ScanOptions.bus}) naming its suppressed line numbers. Left
   * untouched when absent, so callers that do not report suppressions pay
   * nothing.
   */
  inlineSuppressed?: { count: number; criticalVendorAnchored: number };
  /**
   * Pull-request mode's file set. When present, a directory target's file list
   * is the tracked files intersected with the walk's own filtering, rather than
   * a filesystem walk filtered by the gitignore tester -- so a `.gitignore` the
   * pull request added cannot remove a tracked file from the scan, and the
   * vendored-directory names are anchored to the scan root.
   *
   * A file target named explicitly on the command line is unaffected: the user
   * asked for that file by name, and there is nothing for a head-side ignore
   * rule to hide behind.
   */
  pullRequest?: {
    /** Absolute paths of the head tree's regular files, from `git ls-tree`. */
    headTreeFiles: string[];
    /** Filled with what the run declined to look at, and why. */
    skipped: PullRequestSkips;
  };
}

/**
 * Scan an explicit list of files (e.g. paths from \`git diff --cached\`).
 * Without `fromGitIndex`, skips missing worktree paths. With `fromGitIndex`,
 * reads staged blobs so deleted worktree files are still scanned.
 */
export async function scanFileListAsync(
  files: string[],
  scanner: SecretScanner,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const {
    verbose = false,
    maxSize = MAX_FILE_SIZE,
    skipBinary = true,
    progress = false,
    concurrency = 10,
    configIgnorePatterns = [],
    fromGitIndex = false,
    cwd = process.cwd(),
    scanBudgetMs = DEFAULT_SCAN_BUDGET_MS,
  } = options;
  // Context (test / docs / locale) is judged relative to this, never on the
  // absolute path: the checkout's own location is not evidence about a file.
  // With no root given it is each file's own git work tree (memoised per
  // directory), NOT the process cwd: a cwd above the repository would put every
  // directory between the two back into the judged path.
  const rootByDir = new Map<string, string>();
  const pathRootFor = (file: string): string => {
    if (options.pathRoot !== undefined) return options.pathRoot;
    const dir = path.dirname(path.resolve(cwd, file));
    let root = rootByDir.get(dir);
    if (root === undefined) {
      root = resolveContextRoot(dir, cwd);
      rootByDir.set(dir, root);
    }
    return root;
  };

  // Apply config ignore patterns to the explicit file list (e.g. staged files).
  // buildConfigIgnoreFilter matches relative to cwd so patterns like
  // `packages/**/__tests__/**` work identically for staged and directory scans.
  const configIgnoreTester =
    configIgnorePatterns.length > 0
      ? buildConfigIgnoreFilter(configIgnorePatterns, cwd)
      : null;
  const filteredFiles = configIgnoreTester
    ? files.filter(f => {
        if (!configIgnoreTester(f)) return true;
        if (options.skips) options.skips.configIgnored++;
        return false;
      })
    : files;

  const results: ScanResult[] = [];

  const scanFile = async (file: string): Promise<void> => {
    const pathRoot = pathRootFor(file);
    const exclude = excludePatternFor(file, cwd);
    try {
      if (fromGitIndex) {
        const rel = path.relative(cwd, file).split(path.sep).join('/');
        if (skipBinary && isBinaryFile(file)) {
          if (options.skips) options.skips.binary++;
          return;
        }

        // Pass the ABSOLUTE path. `git show :<path>` resolves against the
        // worktree root, not the process cwd, and `rel` is cwd-relative --
        // handing it over is what broke every staged scan launched from a
        // subdirectory. `rel` stays for display only.
        const content = readGitIndexFile(cwd, file);
        // No content sniffing: only the extension rule above skips a blob, the
        // same rule directory mode uses. A NUL byte is scanned as text like any
        // other content. Skipping on NUL let a key sit beside one and pass
        // silently; refusing on NUL broke ordinary commits of fonts and
        // lockfiles.

        // The size limit is on the RAW blob (readGitIndexFile throws
        // FileTooLargeError over MAX_SCAN_FILE_BYTES, and the catch below
        // records it as too large),
        // not on the decoded text: a UTF-16 blob under the limit decodes to a
        // different length and must not be refused for that.
        const byteLen = Buffer.byteLength(content, 'utf-8');

        if (options.stats) {
          options.stats.filesScanned += 1;
          options.stats.bytesScanned += byteLen;
        }

        const hits: IgnoreDirectiveHits = { count: 0, lines: [] };
        const tScan = Date.now();
        const matches = applyPathAwareSeverity(
          scanner.scanContent(content, { filePath: file, ignoreHits: hits, pathRoot }),
          file,
          pathRoot,
        );
        const elapsed = Date.now() - tScan;
        recordInlineSuppression(hits, rel, options);
        if (matches.length > 0) {
          results.push({ file, matches });
        }
        if (elapsed > scanBudgetMs) recordBudgetExceeded(rel, elapsed, scanBudgetMs, options, exclude);
        return;
      }

      if (!fs.existsSync(file)) return;
      const st = await fs.promises.stat(file);
      if (!st.isFile()) return;

      if (skipBinary && isBinaryFile(file)) {
        if (options.skips) options.skips.binary++;
        return;
      }

      if (st.size > maxSize) {
        recordTooLarge(path.relative(cwd, file), st.size, maxSize, options, exclude);
        return;
      }

      if (options.stats) {
        options.stats.filesScanned += 1;
        options.stats.bytesScanned += st.size;
      }

      const tScan = Date.now();
      const matches = scanner.scan(file, { pathRoot });
      const elapsed = Date.now() - tScan;
      if (matches.length > 0) {
        results.push({ file, matches });
      }
      if (elapsed > scanBudgetMs) {
        recordBudgetExceeded(path.relative(cwd, file), elapsed, scanBudgetMs, options, exclude);
      }
    } catch (error) {
      // A staged blob over the limit: the same record, wording and exclude as a
      // file over the limit on disk.
      if (error instanceof FileTooLargeError) {
        recordTooLarge(path.relative(cwd, file), error.bytes, error.maxBytes, options, exclude);
        return;
      }
      options.unreadable?.push({
        kind: 'read_error',
        file: path.relative(cwd, file),
        reason: String(error),
        ...(exclude ? { exclude } : {}),
      });
      if (options.bus) {
        options.bus.add({
          code: 'file.read_error',
          severity: 'error',
          ctx: { file: path.relative(cwd, file), detail: String(error) },
        });
      }
      if (verbose) {
        console.error(chalk.red('❌ Error scanning file:'), chalk.white(path.relative(cwd, file)));
        console.error(chalk.gray(String(error)));
      }
    }
  };

  for (let i = 0; i < filteredFiles.length; i += concurrency) {
    const batch = filteredFiles.slice(i, i + concurrency);
    await Promise.all(batch.map(scanFile));

    if (progress && filteredFiles.length > 10) {
      const percent = Math.round(((i + batch.length) / filteredFiles.length) * 100);
      process.stderr.write(`\r${chalk.gray(`Scanning... ${percent}%`)}`);
    }
  }

  if (progress && filteredFiles.length > 10) {
    process.stderr.write('\r');
  }

  return results;
}

/**
 * Check if a file is binary based on extension
 */
export function isBinaryFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return BINARY_EXTENSIONS.includes(ext);
}

/**
 * Scan files with proper filtering and error handling (async version)
 * This is the shared scanning logic used by both scan and check commands
 */
export async function scanFilesAsync(
  targetPaths: string[],
  scanner: SecretScanner,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const {
    verbose = false,
    maxSize = MAX_FILE_SIZE,
    skipBinary = true,
    progress = false,
    concurrency = 10, // Scan 10 files at a time by default
    scanBudgetMs = DEFAULT_SCAN_BUDGET_MS,
  } = options;

  const results: ScanResult[] = [];

  for (const targetPath of targetPaths) {
    const pathRoot = options.pathRoot ?? resolveContextRoot(targetPath);
    // A target that is not there is a target the run did not check. It used
    // to be skipped, so `check a.ts missing.ts` printed "No secrets found" and
    // exited 0 on the strength of one file out of two.
    const recordUnusableTarget = (reason: string): void => {
      options.unreadable?.push({ kind: 'read_error', file: targetPath, reason });
      options.bus?.add({
        code: 'file.read_error',
        severity: 'error',
        ctx: { file: targetPath, detail: reason },
      });
    };
    try {
      await fs.promises.access(targetPath);
    } catch {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Path not found: ${targetPath}`));
      }
      recordUnusableTarget('path not found, so nothing under it was scanned');
      continue;
    }

    const stat = await fs.promises.stat(targetPath);
    let filesToScan: string[];

    if (stat.isFile()) {
      filesToScan = [targetPath];
    } else if (stat.isDirectory()) {
      filesToScan = options.pullRequest
        ? getPullRequestFilesToScan(
            targetPath,
            options.pullRequest.headTreeFiles,
            options.configIgnorePatterns ?? [],
            options.pullRequest.skipped,
          )
        : await getFilesToScanAsync(
            targetPath,
            verbose,
            options.bus,
            options.configIgnorePatterns ?? [],
            options.skips,
          );
    } else {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Invalid path: ${targetPath}`));
      }
      recordUnusableTarget('not a regular file or directory, so nothing was scanned');
      continue;
    }
    // Tracked files the pull-request file set could not examine on disk are
    // files the run did not check: record them so the run exits 2. Only for a
    // directory target: that is the only one getPullRequestFilesToScan just
    // filled the list for, so a file target after a directory must not record
    // the directory's entries a second time.
    const prUnreadable = stat.isDirectory() ? (options.pullRequest?.skipped.unreadable ?? []) : [];
    for (const u of prUnreadable) {
      const exclude = excludePatternFor(u.file, targetPath);
      const display = path.relative(process.cwd(), u.file);
      options.unreadable?.push({
        kind: 'read_error',
        file: display,
        reason: u.reason,
        ...(exclude ? { exclude } : {}),
      });
      options.bus?.add({
        code: 'file.read_error',
        severity: 'error',
        ctx: { file: display, detail: u.reason },
      });
    }
    // Ignore patterns are matched against the directory being walked, so that
    // is the root an exclude entry has to be written against. A file named on
    // the command line is never filtered by them: stop naming it instead.
    const excludeRoot = stat.isDirectory() ? targetPath : undefined;

    // Scan each file with proper safeguards (parallel with concurrency limit)
    const scanFile = async (file: string): Promise<void> => {
      try {
        // Skip binary files
        if (skipBinary && isBinaryFile(file)) {
          if (options.skips) options.skips.binary++;
          return;
        }

        // Check file size
        const fileStat = await fs.promises.stat(file);
        if (fileStat.size > maxSize) {
          recordTooLarge(
            path.relative(process.cwd(), file),
            fileStat.size,
            maxSize,
            options,
            excludeRoot ? excludePatternFor(file, excludeRoot) : undefined,
          );
          return;
        }

        if (options.stats) {
          options.stats.filesScanned += 1;
          options.stats.bytesScanned += fileStat.size;
        }

        const tScan = Date.now();
        const hits: IgnoreDirectiveHits = { count: 0, lines: [] };
        const matches = scanner.scan(file, { ignoreHits: hits, pathRoot });
        recordInlineSuppression(hits, path.relative(process.cwd(), file), options);
        const elapsed = Date.now() - tScan;
        if (matches.length > 0) {
          results.push({ file, matches });
        }
        if (elapsed > scanBudgetMs) {
          recordBudgetExceeded(
            path.relative(process.cwd(), file),
            elapsed,
            scanBudgetMs,
            options,
            excludeRoot ? excludePatternFor(file, excludeRoot) : undefined,
          );
        }
      } catch (error) {
        const exclude = excludeRoot ? excludePatternFor(file, excludeRoot) : undefined;
        options.unreadable?.push({
          kind: 'read_error',
          file: path.relative(process.cwd(), file),
          reason: String(error),
          ...(exclude ? { exclude } : {}),
        });
        if (options.bus) {
          options.bus.add({
            code: 'file.read_error',
            severity: 'error',
            ctx: { file: path.relative(process.cwd(), file), detail: String(error) },
          });
        }
        if (verbose) {
          console.error(
            chalk.red('❌ Error scanning file:'),
            chalk.white(path.relative(process.cwd(), file))
          );
          console.error(chalk.gray(String(error)));
        }
        // Continue scanning other files
      }
    };

    // Process files in batches for parallel scanning
    for (let i = 0; i < filesToScan.length; i += concurrency) {
      const batch = filesToScan.slice(i, i + concurrency);
      await Promise.all(batch.map(scanFile));

      // Show progress for large scans
      if (progress && filesToScan.length > 10) {
        const percent = Math.round(((i + batch.length) / filesToScan.length) * 100);
        process.stderr.write(`\r${chalk.gray(`Scanning... ${percent}%`)}`);
      }
    }

    // Clear progress line if used
    if (progress && filesToScan.length > 10) {
      process.stderr.write('\r');
    }
  }

  return results;
}

/**
 * Scan files with proper filtering and error handling (sync version for backwards compatibility)
 * This is the shared scanning logic used by both scan and check commands
 */
export function scanFiles(
  targetPaths: string[],
  scanner: SecretScanner,
  options: ScanOptions = {}
): ScanResult[] {
  const {
    verbose = false,
    maxSize = MAX_FILE_SIZE,
    skipBinary = true
  } = options;

  const results: ScanResult[] = [];

  for (const targetPath of targetPaths) {
    const pathRoot = options.pathRoot ?? resolveContextRoot(targetPath);
    if (!fs.existsSync(targetPath)) {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Path not found: ${targetPath}`));
      }
      continue;
    }

    const stat = fs.statSync(targetPath);
    let filesToScan: string[];

    if (stat.isFile()) {
      filesToScan = [targetPath];
    } else if (stat.isDirectory()) {
      filesToScan = getFilesToScan(
        targetPath,
        verbose,
        options.bus,
        options.configIgnorePatterns ?? [],
      );
    } else {
      if (verbose) {
        console.error(chalk.red('❌ Error:'), chalk.white(`Invalid path: ${targetPath}`));
      }
      continue;
    }

    // Scan each file with proper safeguards
    for (const file of filesToScan) {
      try {
        // Skip binary files
        if (skipBinary && isBinaryFile(file)) {
          continue;
        }

        // Check file size
        const fileStat = fs.statSync(file);
        // Above the limit scanTextFileSync throws, and the catch below records
        // the file as unscannable.
        if (options.stats) {
          options.stats.filesScanned += 1;
          options.stats.bytesScanned += fileStat.size;
        }

        const matches = scanTextFileSync(scanner, file, {
          maxFileBytes: maxSize,
          bus: options.bus,
          pathRoot,
        });
        if (matches.length > 0) {
          results.push({ file, matches });
        }
      } catch (error) {
        options.unreadable?.push({
          kind: 'read_error',
          file: path.relative(process.cwd(), file),
          reason: String(error),
        });
        if (options.bus) {
          options.bus.add({
            code: 'file.read_error',
            severity: 'error',
            ctx: { file: path.relative(process.cwd(), file), detail: String(error) },
          });
        }
        if (verbose) {
          console.error(
            chalk.red('❌ Error scanning file:'),
            chalk.white(path.relative(process.cwd(), file))
          );
          console.error(chalk.gray(String(error)));
        }
        // Continue scanning other files
      }
    }
  }

  return results;
}

/**
 * Display scan results with proper formatting.
 *
 * Output format: `<path>:<line>:<col>  <severity>  <type>  <redacted>`
 *
 * Why this layout:
 *   - Most modern terminals (iTerm2, Windows Terminal, VS Code, JetBrains)
 *     auto-link `path:line:col` so users can cmd/ctrl-click directly to the
 *     source -- no copy-paste, no greppable secret value needed.
 *   - Paths are relative to `base` for the same reason JSON/SARIF are: avoids
 *     leaking the developer's home dir / username when output is shared.
 *   - The redacted match value (`sk-a…(37c)`) is shown last and intentionally
 *     low-information.
 *
 * `base` defaults to `process.cwd()`. A `--staged` run passes the repository
 * root, because its findings can sit above the directory the hook ran from
 * and would otherwise print as absolute machine paths.
 */
export function displayScanResults(
  results: ScanResult[],
  blocking?: number,
  base: string = process.cwd(),
): void {
  if (results.length === 0) {
    console.log(chalk.green.bold('✅ SUCCESS:'), chalk.white('No secrets found\n'));
    return;
  }

  const totalSecrets = results.reduce((sum, r) => sum + r.matches.length, 0);
  // `blocking` is how many findings sit at or above the `--fail-on` threshold.
  // When none do we still list everything, but the headline must not say
  // "BLOCKED" over a run that is about to exit 0.
  const willBlock = blocking === undefined || blocking > 0;

  if (willBlock) {
    console.log(chalk.red.bold('🚨 BLOCKED:'), chalk.white(`Found ${totalSecrets} secret${totalSecrets > 1 ? 's' : ''}\n`));
  } else {
    console.log(
      chalk.yellow.bold('⚠️  REPORT:'),
      chalk.white(`Found ${totalSecrets} finding${totalSecrets > 1 ? 's' : ''} below the fail threshold\n`),
    );
  }

  for (const { file, matches } of results) {
    const relativePath = relativeForDisplay(file, base);

    for (const match of matches) {
      const severityColor = getSeverityColor(match.severity);
      const emoji = getSeverityEmoji(match.severity);
      const location = `${relativePath}:${match.line}:${match.column + 1}`;

      console.log(
        `  ${emoji} ${chalk.cyan(location)}  ${severityColor(match.severity)}  ${chalk.white(match.type)}  ${chalk.gray(match.value)}`
      );
    }
  }

  console.log('');
  if (willBlock) {
    console.log(chalk.red.bold('❌ BLOCKED:'), chalk.white('Commit blocked -- remove secrets before pushing\n'));
  }
}

/** Relative to `base` when inside it, absolute otherwise. Matches scan-output behaviour. */
function relativeForDisplay(file: string, base: string): string {
  if (!path.isAbsolute(file)) return file;
  const rel = path.relative(base, file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return file;
  return rel || '.';
}

function getSeverityColor(severity: string): (text: string) => string {
  switch (severity) {
    case 'critical':
      return chalk.red.bold;
    case 'high':
      return chalk.yellow;
    case 'medium':
      return chalk.blue;
    case 'low':
      return chalk.gray;
    default:
      return chalk.white;
  }
}

function getSeverityEmoji(severity: string): string {
  switch (severity) {
    case 'critical':
      return '🔴';
    case 'high':
      return '⚠️';
    case 'medium':
      return 'ℹ️';
    // Not a checkmark: every line here is a finding, and a green tick beside
    // one reads as "this file is clean".
    case 'low':
      return '🔵';
    default:
      return '•';
  }
}
