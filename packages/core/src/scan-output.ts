import path from 'path';
import { createHash } from 'crypto';
import type { ContentDemotion, DemotionReason, SecretMatch } from './types';
import type { Diagnostic } from './diagnostics';
import {
  fingerprintForMatch,
  contentFingerprintForMatch,
  contentFingerprint,
  contentRelPath,
  rootPositionalFingerprint,
} from './match-fingerprint';
import { GROUP_LISTED, GROUP_MIN } from './utils/data-shape';

/** One file's scan outcome -- shared by CLI, MCP, and SARIF/JSON formatters. */
export interface FileScanResult {
  file: string;
  matches: SecretMatch[];
  /**
   * Set when this tracked file's disk copy was scanned as well as its blob:
   * the blob side it was compared with (`index` or `head`). Text output
   * labels each finding's copy only then, so a clean tree prints exactly what
   * it printed before.
   */
  bothCopies?: 'index' | 'head';
}

/** Optional machine-readable scan run metadata (JSON + SARIF driver properties). */
export interface JsonRunMetadata {
  duration_ms: number;
  /** Files opened and scanned for secrets (excludes skipped binaries). */
  files_scanned: number;
  /** Total bytes of the files counted in {@link files_scanned}; each is read whole. */
  bytes_scanned: number;
  /** Active regex rules after config (built-ins minus "off", plus accepted extra_patterns). */
  patterns_active: number;
  diagnostics_count?: number;
  /** Matches removed because they appeared in `.vault-guard.baseline.json`. */
  baseline_suppressed?: number;
  /**
   * Findings suppressed by an inline `vault-guard: ignore-line` /
   * `ignore-next-line` directive. Emitted even at zero so a run always states
   * whether the scanner was silenced inline -- a suppression is the user's
   * decision and must be visible.
   */
  inline_suppressed?: number;
  /**
   * The subset of {@link inline_suppressed} that hid a critical finding from a
   * vendor- or context-anchored rule. Emitted even at zero, for the same reason
   * the total is: a directive over a generic fixture assignment and a directive
   * on the same line as a provider-issued key are not the same event, and one
   * total lets the second hide inside the first.
   */
  inline_suppressed_critical_vendor?: number;
  /**
   * Directories skipped by name at the scan root on a pull-request run. Only
   * a direct child of the scan root can be skipped in that mode, so this
   * number is small and worth stating; a committed `src/vendor/` is scanned.
   */
  vendored_dirs_skipped?: number;
  /**
   * Files in the head tree dropped by the extension, lockfile-name and
   * generated-artifact filters on a pull-request run. Those filters skip on a
   * name alone, so a key committed as `src/leak.min.js` or `src/leak.lock`
   * never reached the scanner and the run said nothing about it. What they
   * skip is unchanged; this is the number that makes the silence visible.
   */
  type_filtered_files?: number;
  /**
   * Files skipped as binary because their extension names a binary format AND
   * their own first bytes carry that format's signature and are not text
   * (design 2026-10-17, section 2). A name alone never skips a file. Emitted
   * even at zero.
   */
  binary_files_skipped?: number;
  /** {@link binary_files_skipped} per family, every family present; sums to it. */
  binary_files_skipped_by_family?: Record<string, number>;
  /** Working-tree copies confirmed binary whose file was otherwise scanned (the LFS case). */
  binary_worktree_copies_skipped?: number;
  /** Files with a binary extension whose bytes are text, scanned as text. */
  binary_type_mismatch_scanned?: number;
  /** Which files make up {@link binary_type_mismatch_scanned}, sorted by file. */
  binary_type_mismatch?: Array<{ file: string; family: string }>;
  /** Files whose first scan went over the CPU budget, re-timed once, then trusted. */
  scan_budget_retimed?: number;
  /**
   * Files dropped by the project's own `ignore` list in the config. A declared
   * skip: the written decision of the project (the BASE ref's on a
   * pull-request run), counted so a reader sees how much it covers. Emitted
   * even at zero.
   */
  config_ignored_files?: number;
  /** Effective gate threshold for this run (`--fail-on` / `fail_on` / default). */
  fail_on?: string;
  /**
   * Matches at or above {@link fail_on}. This, not the total match count, is
   * what drives the process exit code; integrators gating a build should read
   * this field rather than `summary.secrets`.
   */
  blocking_matches?: number;
  /**
   * Files the run should have scanned and did not vouch for: unreadable, over
   * the 32 MiB scan limit, over the per-file scan budget, a tracked file
   * missing on disk, or a named target that does not exist. Omitted when zero.
   *
   * A non-zero value means the run is INCOMPLETE: `blocking_matches` counts
   * only what the scanner actually looked at, so a clean gate result sits on
   * top of files nobody checked. The run exits 2 on every path (staged,
   * directory, pull-request), with the output still emitted. The way out is to
   * fix the file or to exclude it through the config's `ignore` list, which is
   * then counted in {@link config_ignored_files}. In SARIF the same run has
   * `invocations[0].executionSuccessful: false`.
   */
  unscannable_files?: number;
  /**
   * Which files make up {@link unscannable_files}: the path, the cause
   * (`read_error`, `scan_budget` or `too_large`) and, when a config entry could
   * name the file, the exact `ignore.paths` entry that would declare it.
   */
  unscannable?: Array<{ file: string; kind: string; exclude?: string }>;
  /**
   * Where the file set came from: `git` (a plain directory scan inside a git
   * work tree: tracked files plus untracked files that are not ignored),
   * `walk` (outside git: a filesystem walk filtered by `.gitignore`),
   * `head-tree` (pull-request mode) or `index` (`--staged`).
   */
  file_set?: 'git' | 'walk' | 'head-tree' | 'index';
  /**
   * Tracked files that `.gitignore` matches and that were scanned anyway,
   * because `.gitignore` says nothing about a file already committed. Present
   * on `git` and `head-tree` runs.
   */
  tracked_ignored_files_scanned?: number;
  /**
   * Tracked files under a vendored directory name (`vendor`, `build`, `dist`
   * and the like) below the scan root, scanned because only a direct child of
   * the scan root is skipped by name. Present on `git` and `head-tree` runs.
   */
  tracked_nested_vendored_scanned?: number;
  /**
   * Tracked files absent from the working tree: deleted locally, or left out by
   * a sparse checkout. Counted, not fatal. Present on `git` runs.
   */
  tracked_files_missing?: number;
  /** Entries in the baseline's `entries` list that were loaded (0 when none). */
  baseline_entries?: number;
  /**
   * `git` when tracked content was read from git blobs (a plain scan inside
   * git, `--trust-base`, `--staged`, a named tracked file), `disk` otherwise.
   */
  content_source?: 'git' | 'disk';
  /** Tracked files whose disk copy differed from the blob and was scanned as well. */
  worktree_copies_scanned?: number;
  /**
   * Disk copies whose declared `working-tree-encoding` vault-guard cannot
   * decode; each was scanned as UTF-8. The blob was always scanned.
   */
  worktree_undecodable?: Array<{ file: string; encoding: string }>;
  /**
   * Reported matches carrying a demotion record (design 2026-10-17 data
   * files, section 8.2). Filled in by the formatters from the results, so
   * every surface states the same number, zero included.
   */
  demoted_matches?: number;
  /** {@link demoted_matches} by reason, both keys always present. */
  demoted_by_reason?: Record<DemotionReason, number>;
  /** Groups formed (presentation only; every member is still a match). */
  match_groups?: number;
  /** Matches that are members of a group. */
  grouped_matches?: number;
}

/** One grouped finding (design 2026-10-17 data files, section 5.3). */
export interface MatchGroup {
  group_id: string;
  rule: string;
  basis: 'column' | 'long-line';
  delimiter?: string;
  /** 0-based field index, like a match's `column`. */
  column?: number;
  source?: string;
  stage?: 2 | 3;
  members: number;
  distinct_values: number;
  severity: SecretMatch['severity'];
  demoted: boolean;
  /** The first {@link GROUP_LISTED} member locations, in file order. */
  first: Array<{ line: number; column: number }>;
  members_digest: string;
}

/** {@link formGroups}'s answer, parallel to the results it was given. */
export interface FormedGroups {
  /** The groups of each file entry. */
  byFile: MatchGroup[][];
  /** For each file entry, the group of each match (same index), or undefined. */
  memberOf: Array<Array<MatchGroup | undefined>>;
}

/** The slot as one string, for the group key and id. */
function slotKey(m: SecretMatch): string | undefined {
  const s = m.groupSlot;
  if (s === undefined) return undefined;
  return s.basis === 'column' ? `column:${s.delimiter}:${s.column}` : 'long-line';
}

/**
 * Group the post-baseline results (design 2026-10-17 data files, section
 * 5.2). Within one file entry, matches with the same rule, effective
 * severity, demotion status, copy (`source`, `stage`) and slot form a group
 * when there are at least {@link GROUP_MIN} of them. A pure function of its
 * input, so every surface forms the same groups; it removes nothing.
 * `contentRoot` is the root the content fingerprint is keyed on, so a group
 * id never reads the displayed path.
 */
export function formGroups(results: FileScanResult[], opts: { contentRoot?: string } = {}): FormedGroups {
  const root = opts.contentRoot ?? process.cwd();
  const byFile: MatchGroup[][] = [];
  const memberOf: Array<Array<MatchGroup | undefined>> = [];
  for (const r of results) {
    const buckets = new Map<string, number[]>();
    r.matches.forEach((m, i) => {
      const slot = slotKey(m);
      if (slot === undefined) return;
      const k = [m.type, m.severity, m.demotion ? 'true' : 'false', slot, m.source ?? '', String(m.stage ?? '')].join('\0');
      const list = buckets.get(k) ?? [];
      list.push(i);
      buckets.set(k, list);
    });
    const groups: MatchGroup[] = [];
    const of: Array<MatchGroup | undefined> = r.matches.map(() => undefined);
    let rel: string | undefined;
    for (const idx of buckets.values()) {
      if (idx.length < GROUP_MIN) continue;
      rel ??= contentRelPath(r.file, root);
      const ms = idx.map(i => r.matches[i]).sort((a, b) => a.line - b.line || a.column - b.column);
      const m0 = ms[0];
      const slot = m0.groupSlot;
      if (slot === undefined) continue;
      const demoted = m0.demotion !== undefined;
      const group_id = createHash('sha256')
        .update(
          ['vg-group-v1', rel, m0.type, m0.severity, demoted ? 'true' : 'false', slotKey(m0), m0.source ?? '', String(m0.stage ?? '')].join('\0'),
          'utf8',
        )
        .digest('hex');
      const keys = ms
        .map(m =>
          // The member's baseline key: its content fingerprint when it carries a
          // value digest, its root-relative positional fingerprint otherwise.
          m.valueDigest !== undefined
            ? contentFingerprint(rel as string, m.type, m.valueDigest)
            : rootPositionalFingerprint(root, r.file, m),
        )
        .sort();
      const digests = new Set<string>();
      let undigested = 0;
      for (const m of ms) {
        if (m.valueDigest === undefined) undigested++;
        else digests.add(m.valueDigest);
      }
      const g: MatchGroup = {
        group_id,
        rule: m0.type,
        basis: slot.basis,
        ...(slot.basis === 'column' ? { delimiter: slot.delimiter, column: slot.column } : {}),
        ...(m0.source !== undefined ? { source: m0.source } : {}),
        ...(m0.stage !== undefined ? { stage: m0.stage } : {}),
        members: ms.length,
        distinct_values: digests.size + undigested,
        severity: m0.severity,
        demoted,
        first: ms.slice(0, GROUP_LISTED).map(m => ({ line: m.line, column: m.column })),
        members_digest: createHash('sha256').update(keys.join('\0'), 'utf8').digest('hex'),
      };
      groups.push(g);
      for (const i of idx) of[i] = g;
    }
    // In file order of each group's first member.
    groups.sort((a, b) => a.first[0].line - b.first[0].line || a.first[0].column - b.first[0].column);
    byFile.push(groups);
    memberOf.push(of);
  }
  return { byFile, memberOf };
}

/** The four `run` counts of section 8.2, from the results and their groups. */
export function contentRunCounts(
  results: FileScanResult[],
  groups: FormedGroups,
): Required<Pick<JsonRunMetadata, 'demoted_matches' | 'demoted_by_reason' | 'match_groups' | 'grouped_matches'>> {
  const byReason: Record<DemotionReason, number> = { 'data-uri-binary-payload': 0, 'base64-binary-run': 0 };
  let demoted = 0;
  for (const r of results) {
    for (const m of r.matches) {
      if (m.demotion === undefined) continue;
      demoted++;
      byReason[m.demotion.reason]++;
    }
  }
  let matchGroups = 0;
  let grouped = 0;
  for (const gs of groups.byFile) {
    matchGroups += gs.length;
    for (const g of gs) grouped += g.members;
  }
  return { demoted_matches: demoted, demoted_by_reason: byReason, match_groups: matchGroups, grouped_matches: grouped };
}

/** "a" or "an" before a number written in digits. */
function articleForNumber(n: number): string {
  const s = String(n);
  // eight..., eleven..., eighteen... (11 and 18 lead only when the digit count is 2 mod 3).
  if (s.startsWith('8')) return 'an';
  if ((s.startsWith('11') || s.startsWith('18')) && s.length % 3 === 2) return 'an';
  return 'a';
}

/** "a" or "an" before a format name read letter by letter or as a word. */
function articleForFormat(name: string): string {
  return /^[aeiom]/.test(name) ? 'an' : 'a';
}

/**
 * The reason a demoted match carries, in one sentence (section 8.1), shared
 * by the text output and the VS Code extension.
 */
export function demotionText(d: ContentDemotion): string {
  const format = d.format.replace(/^\./, '');
  const what = `${articleForFormat(format)} ${format} ${d.family}`;
  const where =
    d.reason === 'data-uri-binary-payload'
      ? `${d.run_length}-character data:${d.media_type ?? ''};base64 payload`
      : `${d.run_length}-character base64 run`;
  return `demoted from ${d.from}: inside ${articleForNumber(d.run_length)} ${where} that decodes to ${what}`;
}

/**
 * What a pull-request run took from the base ref, and what the head proposed
 * to change about it.
 *
 * Present only on a run given `--trust-base`, so its absence means the run was
 * inside the trust boundary already (a local scan, a pre-commit hook) rather
 * than that it found nothing. `proposals` is the field an umbrella sums across
 * gates to say, in one sentence, that a pull request tried to loosen them.
 */
export interface TrustBaseReport {
  /** The ref every control input was read from. */
  ref: string;
  /** One line per control input the head proposes to change. Never applied. */
  proposals: string[];
  configChanged: boolean;
  baselineChanged: boolean;
  /** How the head changed the config file's type or mode, or null. */
  configShapeChange: 'symlink' | 'not-a-file' | 'removed' | 'mode' | null;
  /** The same for the baseline file. */
  baselineShapeChange: 'symlink' | 'not-a-file' | 'removed' | 'mode' | null;
  /** True when any `.gitattributes` differs between the base ref and HEAD. */
  attributesChanged?: boolean;
  /** Those paths, sorted. */
  attributesPaths?: string[];
}

export interface JsonOutput {
  version: string;
  scannedAt: string;
  summary: { files: number; secrets: number };
  /** Present when the caller passes {@link FormatOptions.run}. */
  run?: JsonRunMetadata;
  /** Present only on a pull-request run. See {@link TrustBaseReport}. */
  trustBase?: TrustBaseReport;
  results: Array<{
    file: string;
    matches: Array<{
      type: string;
      severity: string;
      line: number;
      /** 0-based line-relative column. */
      column: number;
      /** 0-based absolute UTF-16 offset in the scanned content. */
      offset: number;
      /** Redacted form, e.g. `sk-a…(37c)`. Never the raw secret. */
      value: string;
      /** SHA-256 hex of `relPath|type|line|offset|matchLength` for baselines (no raw secret). */
      fingerprint: string;
      /**
       * Content fingerprint (`vg-fp-v2`): keyed on the path relative to the
       * repository root, the rule and a digest of the raw match, not on the
       * line. Present only for a value-bearing rule.
       */
      content_fingerprint?: string;
      /** Which copy the match came from: `index`, `head`, `worktree` or `file`. */
      source?: string;
      /** Present when the match was demoted; `severity` is already the demoted one. */
      demotion?: ContentDemotion;
      /** Present when the match is a member of a group in `groups`. */
      group_id?: string;
    }>;
    /** Present only when the file has a group. Presentation: every member is also in `matches`. */
    groups?: MatchGroup[];
  }>;
  /** Non-fatal scan warnings (skipped files, rejected patterns, git issues). */
  diagnostics?: Array<{
    code: string;
    severity: string;
    ctx: Record<string, unknown>;
  }>;
}

export interface FormatOptions {
  /**
   * Base directory to render `file` paths relative to.
   * Defaults to `process.cwd()`. Files outside this root are kept absolute.
   * Pass `null` to skip relativization for `formatJson`'s `file` paths and
   * for SARIF when no {@link scanRoot} is given either. A `scanRoot` still
   * relativizes SARIF `artifactLocation.uri` (and diagnostic ctx) against
   * itself in that case, so `cwd: null` does not skip SARIF relativization
   * on its own.
   */
  cwd?: string | null;
  /**
   * Directory actually being scanned (the scan target), when it differs from
   * {@link cwd}. SARIF only: `artifactLocation.uri` is relativized against
   * this instead of `cwd`, so a finding outside the process cwd but inside the
   * scan target still gets a relative uri. Defaults to `cwd`.
   *
   * `formatJson` uses it the same way for `results[].file`, so a scan whose
   * target sits outside the cwd reports repository-relative paths instead of
   * absolute machine paths. It never reaches a fingerprint: fingerprints are
   * computed from the original path and {@link cwd}, exactly as before.
   */
  scanRoot?: string;
  /**
   * Root the content fingerprint's path is relative to: the repository root
   * inside git, the scan anchor outside it. Defaults to {@link cwd}.
   */
  contentRoot?: string;
  /** Non-fatal diagnostics to include in structured output. */
  diagnostics?: Diagnostic[];
  /** Scan timing / coverage stats for JSON and SARIF `runs[].properties`. */
  run?: JsonRunMetadata;
  /**
   * Pull-request mode's report. Emitted as a `trustBase` block in JSON and as
   * one SARIF `toolExecutionNotification` per proposal: a proposal is a
   * statement about the run's configuration, not a finding in a file, so it
   * has no artifact location and does not belong in `results`.
   */
  trustBase?: TrustBaseReport;
}

/**
 * Normalize a file path for output: cwd-relative when inside `cwd`, absolute
 * otherwise (so we never emit `../../..` traversals).
 *
 * Why this matters: absolute paths in JSON / SARIF leak the developer's home
 * directory and OS username when the output is shared (PR comments, GitHub
 * Code Scanning UI, support tickets, screenshots).
 */
function normalizeFilePath(
  file: string,
  cwd: string | null | undefined,
  scanRoot?: string,
): string {
  if (cwd === null && scanRoot === undefined) return toForwardSlashes(file);
  const anchor = cwd ?? process.cwd();
  const impl = isWindowsStylePath(file) || isWindowsStylePath(anchor) ? path.win32 : path;
  const base = resolveSarifBase(anchor, scanRoot, impl);
  if (base === anchor) return toForwardSlashes(relativizeFilePath(file, anchor));
  // The scan root is outside the cwd: a relative input is judged where it
  // points, not where it is spelled, exactly as the SARIF uri does.
  const abs = impl.isAbsolute(file) ? file : impl.resolve(anchor, file);
  return toForwardSlashes(relativizeFilePath(abs, base));
}

/**
 * The JSON `file` field always uses forward slashes, on every OS, like SARIF
 * uris. On Windows `path.relative` returns `src\a.ts`; leaving that in the
 * document made the field differ by platform for the same tree.
 */
function toForwardSlashes(p: string): string {
  return p.split('\\').join('/');
}

function relativizeFilePath(file: string, cwd: string | null | undefined): string {
  if (cwd === null) return file;
  const base = cwd ?? process.cwd();
  // Same rule as the SARIF uri: a Windows-style path is judged with path.win32
  // even on a POSIX host (tests, or output produced elsewhere).
  const impl = isWindowsStylePath(file) || isWindowsStylePath(base) ? path.win32 : path;
  if (!impl.isAbsolute(file)) return file;
  const rel = impl.relative(base, file);
  if (rel.startsWith('..') || impl.isAbsolute(rel)) return file;
  return rel || '.';
}

/** Matches a Windows drive-letter absolute path (`C:\...`, `C:/...`) or a UNC path (`\\server\share`). */
const WINDOWS_ABSOLUTE_PATH_RE = /^(?:[a-zA-Z]:[\\/]|\\\\)/;

function isWindowsStylePath(p: string): boolean {
  return WINDOWS_ABSOLUTE_PATH_RE.test(p);
}

/**
 * SARIF `artifactLocation.uri` must be a relative-reference URI: forward
 * slashes only, no leading `./`, no leading `/` (the GitHub Code Scanning
 * SARIF spec requires this even when the scanner itself runs on Windows,
 * where `path.relative` returns backslash-separated paths).
 *
 * The base is the scan root (the directory actually being scanned), not the
 * process cwd. Scanning an out-of-tree target from somewhere else used to
 * leave every uri absolute, which published the developer's home directory
 * and OS username to whoever reads the Code Scanning upload.
 *
 * A file genuinely outside the scan root still stays absolute rather than
 * becoming a `../..` traversal: SARIF relative references are resolved
 * against `%SRCROOT%`, so a traversal out of it is not a legal uri, and there
 * is no other root to express such a path against. In practice this only
 * happens for a path a caller injected from outside the scan, since every
 * file the scanner itself walks is under the target it was given -- and a
 * non-absolute `file` is resolved against cwd below before that check runs,
 * so a literal `..` traversal segment never reaches the returned uri either.
 *
 * Picks `path.win32` when either side of the comparison looks like a
 * Windows-style path, so this is correct both when the process itself runs
 * on Windows (native `path` is already `path.win32`) and when a
 * Windows-style path is normalized on a POSIX host (tests, or a SARIF file
 * produced elsewhere and re-normalized).
 */
function toSarifArtifactUri(
  file: string,
  cwd: string | null | undefined,
  scanRoot: string | undefined,
): string {
  if (cwd === null && scanRoot === undefined) return file.split('\\').join('/');
  const anchor = cwd ?? process.cwd();
  const impl = isWindowsStylePath(file) || isWindowsStylePath(anchor) ? path.win32 : path;
  const abs = impl.isAbsolute(file) ? file : impl.resolve(anchor, file);
  const base = resolveSarifBase(anchor, scanRoot, impl);
  const rel = impl.relative(base, abs);
  if (rel.startsWith('..') || impl.isAbsolute(rel)) return abs.split('\\').join('/');
  return (rel || '.').split('\\').join('/');
}

/**
 * The effective SARIF `%SRCROOT%` base. `scanRoot` is honored only when it
 * is genuinely outside `cwd`: a scan root nested inside cwd (or equal to
 * it) must not narrow `%SRCROOT%` to a subdirectory, because GitHub Code
 * Scanning (and any other SARIF consumer) resolves `%SRCROOT%` from its own
 * knowledge of the checkout, not from this uri -- a uri relative to a
 * subdirectory would then name a different file entirely. Mirrors
 * `resolveScanRoot` in `packages/cli/src/utils/scan-utils.ts`, which applies
 * the same rule when it derives `scanRoot` from the CLI's scan target in the
 * first place.
 */
function resolveSarifBase(
  cwd: string,
  scanRoot: string | undefined,
  impl: typeof path,
): string {
  if (scanRoot === undefined) return cwd;
  const rel = impl.relative(cwd, scanRoot);
  if (rel === '' || (!rel.startsWith('..') && !impl.isAbsolute(rel))) return cwd;
  return scanRoot;
}

/**
 * Diagnostic `ctx` reaches SARIF notifications as `JSON.stringify(d.ctx)`
 * (see `formatSarif` above), and some diagnostic sources (`fs.permission_denied`,
 * `file.read_error`) carry the scanned directory or file as an absolute path,
 * plus a `detail` field that is `String(error)` -- Node's own fs error text
 * often bakes that same absolute path in (e.g. "EACCES: permission denied,
 * scandir '/abs/dir'"). Both leak exactly what `artifactLocation.uri`
 * exists to avoid leaking, so ctx gets the same relativize-or-keep-absolute
 * treatment before it is stringified into a notification: any absolute-path
 * ctx value (`dir`, `path`, `file`, or any other field shaped that way) is
 * run through {@link toSarifArtifactUri}, and any other string value has
 * literal occurrences of the base directory stripped out.
 */
function sanitizeDiagnosticCtxForSarif(
  ctx: Record<string, unknown>,
  cwd: string | null | undefined,
  scanRoot: string | undefined,
): Record<string, unknown> {
  if (cwd === null && scanRoot === undefined) return ctx;
  const anchor = cwd ?? process.cwd();
  const base = resolveSarifBase(anchor, scanRoot, path);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(ctx)) {
    if (typeof value !== 'string') {
      out[key] = value;
    } else if (path.isAbsolute(value)) {
      out[key] = toSarifArtifactUri(value, cwd, scanRoot);
    } else {
      out[key] = stripSarifBasePath(value, base);
    }
  }
  return out;
}

/**
 * Removes literal occurrences of the SARIF base directory from a free-form
 * string (diagnostic `detail`, which is `String(error)` and can embed the
 * scanned path inside Node's own message text). This is not a full
 * relative-path rewrite of the string, just enough to keep the base
 * directory out of the document, matching what `artifactLocation.uri` does
 * for the path fields themselves.
 */
function stripSarifBasePath(text: string, base: string): string {
  if (!text.includes(base)) return text;
  const withTrailingSep = base.endsWith(path.sep) ? base : base + path.sep;
  return text.split(withTrailingSep).join('').split(base).join('.');
}

/** The content fingerprint for one match, or undefined for a header-only rule. */
function contentKey(
  opts: FormatOptions,
  fpCwd: string | null,
  file: string,
  m: SecretMatch,
): string | undefined {
  const root = opts.contentRoot ?? fpCwd ?? process.cwd();
  return contentFingerprintForMatch(root, file, m);
}

/** The groups for a formatter call, keyed on the same root as the content fingerprint. */
function groupsFor(results: FileScanResult[], opts: FormatOptions, fpCwd: string | null): FormedGroups {
  return formGroups(results, { contentRoot: opts.contentRoot ?? fpCwd ?? process.cwd() });
}

/** `opts.run` with the four content counts of section 8.2, always present. */
function runWithCounts(opts: FormatOptions, results: FileScanResult[], groups: FormedGroups): JsonRunMetadata | undefined {
  return opts.run ? { ...opts.run, ...contentRunCounts(results, groups) } : undefined;
}

export function formatJson(results: FileScanResult[], opts: FormatOptions = {}): string {
  const fpCwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const groups = groupsFor(results, opts, fpCwd);
  const run = runWithCounts(opts, results, groups);
  const output: JsonOutput = {
    version: '1',
    scannedAt: new Date().toISOString(),
    summary: {
      files: results.length,
      secrets: results.reduce((n, r) => n + r.matches.length, 0),
    },
    ...(run ? { run } : {}),
    ...(opts.trustBase ? { trustBase: opts.trustBase } : {}),
    results: results.map(({ file, matches }, fi) => ({
      file: normalizeFilePath(file, opts.cwd, opts.scanRoot),
      matches: matches.map((m, mi) => {
        const content = contentKey(opts, fpCwd, file, m);
        const group = groups.memberOf[fi][mi];
        return {
          type: m.type,
          severity: m.severity,
          line: m.line,
          column: m.column,
          offset: m.offset,
          value: m.value,
          fingerprint: fingerprintForMatch(fpCwd, file, m),
          ...(content !== undefined ? { content_fingerprint: content } : {}),
          ...(m.source !== undefined ? { source: m.source } : {}),
          ...(m.demotion !== undefined ? { demotion: m.demotion } : {}),
          ...(group !== undefined ? { group_id: group.group_id } : {}),
        };
      }),
      ...(groups.byFile[fi].length > 0 ? { groups: groups.byFile[fi] } : {}),
    })),
  };
  if (opts.diagnostics && opts.diagnostics.length > 0) {
    output.diagnostics = opts.diagnostics.map(d => ({
      code: d.code,
      severity: d.severity,
      ctx: d.ctx,
    }));
  }
  return JSON.stringify(output, null, 2);
}

/** Plain wording for each `unscannable` kind, used in SARIF notifications. */
const UNSCANNABLE_KIND_TEXT: Record<string, string> = {
  read_error: 'could not be read, so it was not scanned',
  too_large: 'over the scan size limit, so it was not scanned',
  scan_budget: 'its scan exceeded the per-file time budget, so the result is not trusted',
};

/** SARIF 2.1.0 -- compatible with GitHub Code Scanning (upload-sarif action). */
export function formatSarif(results: FileScanResult[], opts: FormatOptions = {}): string {
  const fpCwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const rules = [
    ...new Set(results.flatMap(r => r.matches.map(m => m.type))),
  ].map(id => ({
    id,
    name: id
      .split(/[-_]/)
      .map(p => p.charAt(0).toUpperCase() + p.slice(1))
      .join(''),
    shortDescription: { text: `Secret detected: ${id}` },
    helpUri: `https://github.com/vaultcompasshq/vault-guard/blob/main/docs/rules/${id}.md`,
    properties: { tags: ['security', 'secrets'] },
  }));

  const groups = groupsFor(results, opts, fpCwd);
  const run = runWithCounts(opts, results, groups);
  /** Result properties: the copy, the demotion and the group, each only when it applies. */
  const resultProperties = (m: SecretMatch, group: MatchGroup | undefined): Record<string, unknown> | undefined => {
    const p: Record<string, unknown> = {
      ...(m.source !== undefined ? { 'vault-guard/source': m.source } : {}),
      ...(m.demotion !== undefined
        ? { 'vault-guard/demoted_from': m.demotion.from, 'vault-guard/demotion_reason': m.demotion.reason }
        : {}),
      ...(group !== undefined ? { 'vault-guard/group': group.group_id, 'vault-guard/group_size': group.members } : {}),
    };
    return Object.keys(p).length > 0 ? p : undefined;
  };

  // One result per match, grouped or not (section 5.7).
  const sarifResults = results.flatMap(({ file, matches }, fi) =>
    matches.map((m, mi) => ({
      ruleId: m.type,
      level: m.severity === 'critical' ? 'error' : m.severity === 'high' ? 'warning' : 'note',
      // Intentionally do NOT include the masked value here. Reviewers have the
      // exact byte region (startLine/startColumn/endColumn) and the rule id;
      // the masked prefix adds no signal and grows the leak surface area.
      message: { text: `Possible secret of type '${m.type}'` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: toSarifArtifactUri(file, opts.cwd, opts.scanRoot),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: m.line,
              startColumn: m.column + 1,
              endColumn: m.column + m.matchLength + 1,
            },
          },
        },
      ],
      // Same fingerprint the JSON output emits per finding (positional: keyed
      // on relative path + type + line + offset + matchLength). Lets GitHub
      // Code Scanning track a finding's identity across runs.
      // v2 is the content fingerprint, added beside v1 for value-bearing rules.
      partialFingerprints: (() => {
        const content = contentKey(opts, fpCwd, file, m);
        return {
          'vault-guard/v1': fingerprintForMatch(fpCwd, file, m),
          ...(content !== undefined ? { 'vault-guard/v2': content } : {}),
        };
      })(),
      ...((): { properties?: Record<string, unknown> } => {
        const properties = resultProperties(m, groups.memberOf[fi][mi]);
        return properties !== undefined ? { properties } : {};
      })(),
    }))
  );

  // Diagnostics are emitted as SARIF notifications (tool/driver/notifications)
  // so they appear in the GitHub Code Scanning UI as tool warnings rather than
  // results. This keeps the results array clean for triage.
  const notifications =
    opts.diagnostics && opts.diagnostics.length > 0
      ? opts.diagnostics.map(d => ({
          id: d.code,
          level: d.severity === 'error' ? 'error' : 'warning',
          message: {
            text: `${d.code}: ${JSON.stringify(sanitizeDiagnosticCtxForSarif(d.ctx, opts.cwd, opts.scanRoot))}`,
          },
        }))
      : undefined;

  const runProps =
    opts.run !== undefined
      ? {
          vault_guard_run: {
            duration_ms: opts.run.duration_ms,
            files_scanned: opts.run.files_scanned,
            bytes_scanned: opts.run.bytes_scanned,
            patterns_active: opts.run.patterns_active,
            ...(opts.run.diagnostics_count !== undefined
              ? { diagnostics_count: opts.run.diagnostics_count }
              : {}),
            ...(opts.run.baseline_suppressed !== undefined
              ? { baseline_suppressed: opts.run.baseline_suppressed }
              : {}),
            ...(opts.run.inline_suppressed !== undefined
              ? { inline_suppressed: opts.run.inline_suppressed }
              : {}),
            ...(opts.run.inline_suppressed_critical_vendor !== undefined
              ? {
                  inline_suppressed_critical_vendor:
                    opts.run.inline_suppressed_critical_vendor,
                }
              : {}),
            ...(opts.run.vendored_dirs_skipped !== undefined
              ? { vendored_dirs_skipped: opts.run.vendored_dirs_skipped }
              : {}),
            ...(opts.run.type_filtered_files !== undefined
              ? { type_filtered_files: opts.run.type_filtered_files }
              : {}),
            ...(opts.run.binary_files_skipped !== undefined
              ? { binary_files_skipped: opts.run.binary_files_skipped }
              : {}),
            ...(opts.run.binary_files_skipped_by_family !== undefined
              ? { binary_files_skipped_by_family: opts.run.binary_files_skipped_by_family }
              : {}),
            ...(opts.run.binary_worktree_copies_skipped !== undefined
              ? { binary_worktree_copies_skipped: opts.run.binary_worktree_copies_skipped }
              : {}),
            ...(opts.run.binary_type_mismatch_scanned !== undefined
              ? { binary_type_mismatch_scanned: opts.run.binary_type_mismatch_scanned }
              : {}),
            ...(opts.run.binary_type_mismatch !== undefined
              ? { binary_type_mismatch: opts.run.binary_type_mismatch }
              : {}),
            ...(opts.run.scan_budget_retimed !== undefined
              ? { scan_budget_retimed: opts.run.scan_budget_retimed }
              : {}),
            ...(opts.run.config_ignored_files !== undefined
              ? { config_ignored_files: opts.run.config_ignored_files }
              : {}),
            ...(opts.run.unscannable_files !== undefined
              ? { unscannable_files: opts.run.unscannable_files }
              : {}),
            ...(opts.run.file_set !== undefined ? { file_set: opts.run.file_set } : {}),
            ...(opts.run.tracked_ignored_files_scanned !== undefined
              ? { tracked_ignored_files_scanned: opts.run.tracked_ignored_files_scanned }
              : {}),
            ...(opts.run.tracked_nested_vendored_scanned !== undefined
              ? { tracked_nested_vendored_scanned: opts.run.tracked_nested_vendored_scanned }
              : {}),
            ...(opts.run.tracked_files_missing !== undefined
              ? { tracked_files_missing: opts.run.tracked_files_missing }
              : {}),
            ...(opts.run.baseline_entries !== undefined
              ? { baseline_entries: opts.run.baseline_entries }
              : {}),
            ...(opts.run.content_source !== undefined ? { content_source: opts.run.content_source } : {}),
            ...(opts.run.worktree_copies_scanned !== undefined
              ? { worktree_copies_scanned: opts.run.worktree_copies_scanned }
              : {}),
            ...(opts.run.worktree_undecodable !== undefined
              ? { worktree_undecodable: opts.run.worktree_undecodable }
              : {}),
            // Section 8.3: the same four counts as the JSON run, always present.
            demoted_matches: run?.demoted_matches,
            demoted_by_reason: run?.demoted_by_reason,
            match_groups: run?.match_groups,
            grouped_matches: run?.grouped_matches,
          },
        }
      : undefined;

  // A proposal is a statement about the run's CONFIGURATION -- "this pull
  // request also tried to turn the gate down" -- not a finding at a location in
  // a file. SARIF has a place for exactly that, and it is not `results`:
  // `invocations[].toolExecutionNotifications`. Putting it in `results` would
  // make it a code-scanning alert with no file to point at, and a triager would
  // have to dismiss it.
  //
  // A run that could not scan every file it was asked to (the run exits 2) is
  // not a successful execution, whatever its results say: `executionSuccessful`
  // is false and each unscanned file is an error-level notification in the same
  // place, naming the file and the cause. The results then cover only the files
  // that were scanned.
  const unscannable = opts.run?.unscannable ?? [];
  const incomplete = (opts.run?.unscannable_files ?? 0) > 0 || unscannable.length > 0;
  const unscannableNotifications = unscannable.map(u => ({
    descriptor: { id: `vault-guard/unscannable/${u.kind}` },
    level: 'error',
    message: {
      text:
        `${toSarifArtifactUri(u.file, opts.cwd, opts.scanRoot)}: ${UNSCANNABLE_KIND_TEXT[u.kind] ?? 'not scanned'}` +
        (u.exclude ? `; to exclude it on purpose, add ${JSON.stringify(u.exclude)} to "ignore.paths"` : ''),
    },
  }));
  const invocations =
    opts.trustBase !== undefined || incomplete
      ? [
          {
            executionSuccessful: !incomplete,
            toolExecutionNotifications: [
              ...unscannableNotifications,
              ...(opts.trustBase?.proposals ?? []).map(text => ({
                descriptor: { id: 'vault-guard/trust-base/proposal' },
                level: 'warning',
                message: { text },
              })),
            ],
          },
        ]
      : undefined;

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
      {
        ...(runProps ? { properties: runProps } : {}),
        ...(invocations ? { invocations } : {}),
        tool: {
          driver: {
            name: 'vault-guard',
            informationUri: 'https://github.com/vaultcompasshq/vault-guard',
            rules,
            ...(notifications ? { notifications } : {}),
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
