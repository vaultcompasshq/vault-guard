import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';

import { GitError } from '../errors';
import type { IgnoreDirectiveHits, SecretScanner } from '../scanners/secret-scanner';
import type { MatchSource, SecretMatch } from '../types';
import { BlobBatchReader, batchCheckBlobs, type BlobCheck } from './blob-reader';
import {
  SNIFF_BYTES,
  binaryCandidate,
  confirmsBinary,
  isLfsPointer,
  type BinaryFamily,
} from './binary-type';
import { applyPathAwareSeverity } from './path-severity';
import { defaultScanClock, timeSpan, type ClockMeasure, type ScanClock } from './scan-clock';
import { MAX_SCAN_FILE_BYTES } from './scan-file';
import { decodeDiskCopy, decodeTextBuffer } from './text-decode';

/**
 * Where a tracked file's content comes from (design 2026-10-12, section 2).
 *
 * Inside a git repository a tracked file is read from its BLOB, by object id:
 * the index (stage 0) entry in a plain scan and under `--staged`, the HEAD
 * tree entry under `--trust-base`. A checkout transform (`working-tree-
 * encoding`, `eol`, `filter`, `ident`) sits between the blob and the file on
 * disk, and a pull request controls the head's `.gitattributes`, so the disk
 * copy is never the only thing judged. It is scanned AS WELL when git says it
 * differs, when the file has a `filter` attribute, or (plain mode) when the
 * index marks it assume-unchanged or skip-worktree. It can add findings and
 * never removes one.
 */

/** What the run knows about one tracked file it is about to scan. */
export interface TrackedEntry {
  /** Symlink-resolved toplevel of the repository whose object store holds the blob. */
  repoTop: string;
  /** The git file mode of the entry. */
  mode: string;
  /** The stage-0 (plain, `--staged`) or HEAD (pull-request) blob. */
  oid?: string;
  /** A conflicted path: the stage 2 (ours) blob. */
  ours?: string;
  /** A conflicted path: the stage 3 (theirs) blob. */
  theirs?: string;
  /** Scan the copy on disk as well as the blob. */
  worktreeAlso: boolean;
  /** The `working-tree-encoding` attribute, when one is set. */
  encoding?: string;
  /** The path carries a `filter` attribute. */
  filtered: boolean;
  /** The disk copy is absent (staged, then deleted: `AD` or `MD`); only the blob is read. */
  diskAbsent?: boolean;
  /**
   * Where the disk copy is read from when it is not the path itself: the
   * resolved target of a tracked symlink named on the command line, already
   * checked to be a regular file inside the repository.
   */
  diskPath?: string;
}

/** Attributes that decide how a disk copy is read. */
export interface PathAttributes {
  filter: boolean;
  encoding?: string;
}

/** Status columns and attributes for one repository's tracked paths. */
export interface WorktreeInspection {
  /** Root-relative posix path to its two `git status` columns. */
  status: Map<string, string>;
  attrs: Map<string, PathAttributes>;
}

/**
 * Run git for the content plan, throwing {@link GitError} quoting git's stderr.
 * A run that cannot tell whether a disk copy differs does not assume it does
 * not.
 */
export function runContentGit(
  cwd: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  input?: string,
): string {
  const argv = ['-c', 'core.quotePath=false', ...args];
  const r = spawnSync('git', argv, {
    cwd,
    env,
    encoding: 'utf-8',
    stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    maxBuffer: 512 * 1024 * 1024,
    ...(input !== undefined ? { input } : {}),
  });
  if (r.error === undefined && r.status === 0) return r.stdout;
  const stderr = typeof r.stderr === 'string' ? r.stderr.trim() : '';
  const err = r.error ?? new Error(`git exited with status ${String(r.status)}`);
  throw new GitError(
    `vault-guard: git failed while deciding where tracked content in ${cwd} is read from: ` +
      `${stderr.length > 0 ? stderr : String(err)}\nNothing was scanned.`,
    `git ${argv.join(' ')}`,
    err,
  );
}

function splitZ(out: string): string[] {
  return out.split('\0').filter(s => s.length > 0);
}

/**
 * One `git status` and one `git check-attr` for a repository. `spec` limits
 * the status call; `relPaths` (root-relative, posix) are the paths whose
 * attributes are read. `GIT_OPTIONAL_LOCKS=0` must be in `env` so status
 * never writes the index.
 */
export function inspectWorktree(
  repoTop: string,
  spec: string,
  relPaths: string[],
  env: NodeJS.ProcessEnv,
): WorktreeInspection {
  const status = new Map<string, string>();
  const out = runContentGit(
    repoTop,
    [
      '-c', 'core.fsmonitor=false',
      'status', '--porcelain=v1', '-z', '--untracked-files=no', '--ignore-submodules=all',
      '--no-renames', '--', spec,
    ],
    env,
  );
  for (const record of splitZ(out)) {
    if (record.length < 4) continue;
    status.set(record.slice(3), record.slice(0, 2));
  }
  const attrs = new Map<string, PathAttributes>();
  if (relPaths.length > 0) {
    const attrOut = runContentGit(
      repoTop,
      ['check-attr', '-z', '--stdin', 'filter', 'working-tree-encoding'],
      env,
      relPaths.map(p => `${p}\0`).join(''),
    );
    const parts = attrOut.split('\0');
    for (let i = 0; i + 2 < parts.length; i += 3) {
      const [p, attr, value] = [parts[i], parts[i + 1], parts[i + 2]];
      const entry = attrs.get(p) ?? { filter: false };
      const set = value !== 'unspecified' && value !== 'unset';
      if (attr === 'filter' && set) entry.filter = true;
      if (attr === 'working-tree-encoding' && set && value !== 'set') entry.encoding = value;
      attrs.set(p, entry);
    }
  }
  return { status, attrs };
}

/**
 * Whether a tracked file's disk copy is scanned besides its blob (2.4).
 *
 * `xy` is the file's two `git status` columns (absent when status was silent).
 * `tag` is the `ls-files -v` tag (plain mode only). Plain mode: the second
 * column is M, T or A (an intent-to-add entry, whose index blob is empty), or
 * the entry is assume-unchanged (lowercase tag) or skip-worktree (S or s), on
 * which status is silent whatever the disk holds. Pull-request mode: any
 * column that is not a space, so a disk copy that differs from HEAD by way of
 * the index or directly is read. A `filter` attribute always counts.
 */
export function wantsWorktreeCopy(
  blobSource: 'index' | 'head',
  xy: string | undefined,
  tag: string | undefined,
  filtered: boolean,
): boolean {
  if (filtered) return true;
  if (blobSource === 'head') return xy !== undefined && xy !== '  ';
  const y = xy?.[1];
  if (y === 'M' || y === 'T' || y === 'A') return true;
  if (tag !== undefined && tag.length > 0) {
    if (tag !== tag.toUpperCase()) return true;
    if (tag === 'S') return true;
  }
  return false;
}

/** The kept-bytes key for one copy of a file. */
export function copyKey(file: string, source: MatchSource | undefined, stage?: 2 | 3): string {
  return `${file}\0${source ?? 'file'}${stage !== undefined ? `\0${stage}` : ''}`;
}

/**
 * The blob reads of one run: per repository, one `cat-file --batch-check`
 * over every object id the run will read (sizes and missing objects are known
 * before any content moves), and one streaming `cat-file --batch`.
 */
export class GitContentSource {
  private readonly readers = new Map<string, BlobBatchReader>();
  private readonly checks = new Map<string, Map<string, BlobCheck>>();
  /** Paths still to read each blob, keyed by repository and object id. */
  private readonly refs = new Map<string, number>();
  /** `cat-file --batch-check` processes run, for the call-count tests. */
  batchChecks = 0;
  /** Set by close(); a closed source starts no further git process. */
  private closed = false;

  constructor(
    /** `index` for plain and `--staged`, `head` for `--trust-base`. */
    readonly blobSource: 'index' | 'head',
    readonly env: NodeJS.ProcessEnv,
    readonly entries: Map<string, TrackedEntry> = new Map(),
    private readonly window = 10,
  ) {}

  /** Add (or replace) what is known about tracked files. */
  add(entries: Map<string, TrackedEntry>): void {
    for (const [k, v] of entries) this.entries.set(k, v);
  }

  entryFor(file: string): TrackedEntry | undefined {
    return this.entries.get(file);
  }

  /**
   * Run `--batch-check` for every object id the given files will read, one
   * process per repository. Object ids already checked are not asked again.
   */
  prepare(files: Iterable<string>): void {
    const byRepo = new Map<string, Set<string>>();
    for (const f of files) {
      const e = this.entries.get(f);
      if (!e) continue;
      for (const oid of [e.oid, e.ours, e.theirs]) {
        if (oid === undefined) continue;
        // One reference per path that will read this blob, so identical
        // blobs are read once and released after the last of them.
        const ref = `${e.repoTop}\0${oid}`;
        this.refs.set(ref, (this.refs.get(ref) ?? 0) + 1);
        if (this.checks.get(e.repoTop)?.has(oid)) continue;
        const set = byRepo.get(e.repoTop) ?? new Set<string>();
        set.add(oid);
        byRepo.set(e.repoTop, set);
      }
    }
    for (const [repoTop, oids] of byRepo) {
      this.batchChecks++;
      const answers = batchCheckBlobs(repoTop, oids, this.env);
      const known = this.checks.get(repoTop) ?? new Map<string, BlobCheck>();
      for (const [oid, c] of answers) known.set(oid, c);
      this.checks.set(repoTop, known);
    }
  }

  check(repoTop: string, oid: string): BlobCheck {
    let c = this.checks.get(repoTop)?.get(oid);
    if (c === undefined) {
      this.batchChecks++;
      c = batchCheckBlobs(repoTop, [oid], this.env).get(oid);
      if (c === undefined) {
        throw new GitError(`vault-guard: git cat-file gave no answer for ${oid}`, 'git cat-file --batch-check');
      }
      const known = this.checks.get(repoTop) ?? new Map<string, BlobCheck>();
      known.set(oid, c);
      this.checks.set(repoTop, known);
    }
    return c;
  }

  read(repoTop: string, oid: string): Promise<Buffer> {
    // After close() no reader may be created: a sibling file in the same
    // batch can still get here after a git error ended the run, and a new
    // reader's git process would be left open, keeping the process alive.
    if (this.closed) {
      return Promise.reject(
        new GitError(
          `vault-guard: the run ended before ${oid} was read from ${repoTop}; the content source is closed`,
          'git cat-file --batch',
        ),
      );
    }
    let r = this.readers.get(repoTop);
    if (!r) {
      r = new BlobBatchReader(repoTop, this.env, this.window);
      this.readers.set(repoTop, r);
    }
    return r.read(oid);
  }

  /** The first `n` bytes of a blob, through the same reader and process (design 2026-10-17, 4.2). */
  readHead(repoTop: string, oid: string, n: number): Promise<Buffer> {
    if (this.closed) {
      return Promise.reject(
        new GitError(
          `vault-guard: the run ended before ${oid} was read from ${repoTop}; the content source is closed`,
          'git cat-file --batch',
        ),
      );
    }
    let r = this.readers.get(repoTop);
    if (!r) {
      r = new BlobBatchReader(repoTop, this.env, this.window);
      this.readers.set(repoTop, r);
    }
    return r.readHead(oid, n);
  }

  /** Body bytes piped through `cat-file` for head reads, for the bench (not an output field). */
  get headReadBytes(): number {
    let n = 0;
    for (const r of this.readers.values()) n += r.headReadBytes;
    return n;
  }

  /**
   * One path has finished with a blob. When no prepared path still needs it,
   * the reader forgets its bytes, so memory is bounded by the blobs in use
   * (the read window), not by the total tracked size (design 2026-10-12, 2.3).
   */
  done(repoTop: string, oid: string): void {
    const ref = `${repoTop}\0${oid}`;
    const left = (this.refs.get(ref) ?? 1) - 1;
    if (left > 0) {
      this.refs.set(ref, left);
      return;
    }
    this.refs.delete(ref);
    this.readers.get(repoTop)?.release(oid);
  }

  /** Blobs currently held by every reader, for the memory-bound test. */
  get blobsHeld(): number {
    let n = 0;
    for (const r of this.readers.values()) n += r.held;
    return n;
  }

  /** The most blobs any reader held at once, for the memory-bound test. */
  get maxBlobsHeld(): number {
    let n = 0;
    for (const r of this.readers.values()) n = Math.max(n, r.maxHeld);
    return n;
  }

  /** `cat-file --batch` processes started, for the call-count tests. */
  get batchReads(): number {
    let n = 0;
    for (const r of this.readers.values()) n += r.spawned;
    return n;
  }

  /** Object ids written to `cat-file --batch`, for the call-count tests. */
  get blobsRequested(): number {
    let n = 0;
    for (const r of this.readers.values()) n += r.requested;
    return n;
  }

  close(): void {
    this.closed = true;
    for (const r of this.readers.values()) r.close();
  }

  /** Settles once every git process any reader started has exited. */
  exited(): Promise<void> {
    return Promise.all([...this.readers.values()].map(r => r.exited())).then(() => undefined);
  }

  /**
   * Close every reader and wait, bounded, for its git process to exit; a
   * stuck one is killed. Every scan path calls this in its `finally`, so no
   * git process outlives the scan (on Windows a live process keeps its
   * working directory locked). Never rejects.
   */
  async closeAndWait(timeoutMs?: number): Promise<void> {
    this.closed = true;
    await Promise.all([...this.readers.values()].map(r => r.closeAndWait(timeoutMs)));
  }

  /** git processes started by every reader and not yet exited. */
  get liveChildren(): number {
    let n = 0;
    for (const r of this.readers.values()) n += r.liveChildren;
    return n;
  }
}

/** The outcome of scanning every copy of one file. */
export interface FileContentOutcome {
  /** Blob matches first (stage 2 before stage 3), then surviving disk matches. */
  matches: SecretMatch[];
  /** Set when the file could not be scanned; `matches` is then empty. */
  failure?:
    | { kind: 'too_large'; bytes: number }
    | { kind: 'read_error'; reason: string };
  /** Raw bytes read, over every copy. */
  bytesRead: number;
  /** The disk copy of a tracked file was scanned as well as its blob. */
  worktreeScanned: boolean;
  /** The disk copy's declared encoding, when it could not be honoured. */
  undecodable?: string;
  /** Raw bytes of each copy that produced a header-only match, by {@link copyKey}. */
  kept: Map<string, Buffer>;
  /** Slowest single copy's deciding measurement (CPU time, design 2026-10-17, 6.2). */
  elapsedMs: number;
  /**
   * Every copy that would have been read was confirmed binary (name and bytes
   * agree): nothing was decoded or scanned, `matches` is empty and
   * `bytesRead` is the head bytes only.
   */
  skippedByType?: { family: BinaryFamily };
  /** Disk copies confirmed binary while another copy of the file was scanned (the LFS case). */
  binaryCopiesSkipped: number;
  /** A copy had a binary extension, was not confirmed, and was not an LFS pointer: scanned as text. */
  typeMismatch?: { family: BinaryFamily };
  /** Set when a copy's scan went over the budget and its result is not trusted (6.3). */
  untrusted?: BudgetUntrusted;
  /** A copy went over the budget once, was re-timed, and was then trusted. */
  retimed: boolean;
}

/** Why a copy's result is not trusted, with the numbers the diagnostic carries. */
export interface BudgetUntrusted {
  reason: string;
  /** The deciding measurement: the re-time when there was one. */
  elapsedMs: number;
  firstMs: number;
  wallMs: number;
  budgetMs: number;
  measure: ClockMeasure;
  retimed: boolean;
}

export interface ScanFileContentOptions {
  pathRoot?: string;
  maxBytes?: number;
  ignoreHits?: IgnoreDirectiveHits;
  /**
   * Apply the binary classifier (design 2026-10-17, section 2) to each copy.
   * Off by default, so a caller that asked for a file to be scanned gets it
   * scanned as text.
   */
  classify?: boolean;
  /** CPU-time budget per copy, in ms. Without it no copy is judged, and nothing is re-timed. */
  budgetMs?: number;
  /** The clock seam; defaults to {@link defaultScanClock}. */
  clock?: ScanClock;
}

const MISSING_BLOB_REASON =
  'the committed blob for this tracked file is not in the local object store (a damaged ' +
  'repository, or a partial clone that cannot fetch it)';

interface CopyScan {
  matches: SecretMatch[];
  ms: number;
  untrusted?: BudgetUntrusted;
  retimed: boolean;
}

const sameMatches = (a: SecretMatch[], b: SecretMatch[]): boolean =>
  a.length === b.length &&
  a.every(
    (m, i) =>
      m.type === b[i].type &&
      m.line === b[i].line &&
      m.offset === b[i].offset &&
      m.matchLength === b[i].matchLength &&
      m.valueDigest === b[i].valueDigest,
  );

/**
 * Scan one decoded copy and judge it against the budget (design 2026-10-17,
 * 6.3): within the budget, trusted; over twice the budget, untrusted with no
 * second pass; otherwise one more pass over the same text with a discarded
 * inline tally, trusted only if that pass is within the budget and its
 * matches equal the first pass's. The first pass's matches are reported.
 */
function scanText(
  scanner: SecretScanner,
  text: string,
  file: string,
  opts: ScanFileContentOptions,
  hits: IgnoreDirectiveHits | undefined,
): CopyScan {
  const clock = opts.clock ?? defaultScanClock();
  const pass = (h: IgnoreDirectiveHits | undefined): SecretMatch[] =>
    applyPathAwareSeverity(
      scanner.scanContent(text, { filePath: file, ignoreHits: h, pathRoot: opts.pathRoot }),
      file,
      opts.pathRoot,
    );
  const first = timeSpan(clock, () => pass(hits));
  const budget = opts.budgetMs;
  if (budget === undefined || first.ms <= budget) return { matches: first.value, ms: first.ms, retimed: false };
  const c1 = Math.round(first.ms);
  const base = { firstMs: c1, budgetMs: budget, measure: clock.measure };
  if (first.ms > 2 * budget) {
    return {
      matches: first.value,
      ms: first.ms,
      retimed: false,
      untrusted: {
        ...base,
        reason: `scan exceeded the ${budget} ms CPU budget (took ${c1} ms, over twice the budget, so it was not re-timed)`,
        elapsedMs: c1,
        wallMs: Math.round(first.wallMs),
        retimed: false,
      },
    };
  }
  const second = timeSpan(clock, () => pass(hits ? freshHits() : undefined));
  const c2 = Math.round(second.ms);
  if (second.ms > budget) {
    return {
      matches: first.value,
      ms: second.ms,
      retimed: false,
      untrusted: {
        ...base,
        reason: `scan exceeded the ${budget} ms CPU budget twice (first ${c1} ms, re-timed ${c2} ms)`,
        elapsedMs: c2,
        wallMs: Math.round(second.wallMs),
        retimed: true,
      },
    };
  }
  if (!sameMatches(first.value, second.value)) {
    return {
      matches: first.value,
      ms: second.ms,
      retimed: false,
      untrusted: {
        ...base,
        reason: 'scan results differed between two passes over the same content',
        elapsedMs: c2,
        wallMs: Math.round(second.wallMs),
        retimed: true,
      },
    };
  }
  return { matches: first.value, ms: second.ms, retimed: true };
}

/** Fold one copy's budget verdict into the file's: the first untrusted copy decides. */
function foldBudget(into: { untrusted?: BudgetUntrusted; retimed: boolean; elapsedMs: number }, c: CopyScan): void {
  into.elapsedMs = Math.max(into.elapsedMs, c.ms);
  if (c.untrusted && !into.untrusted) into.untrusted = c.untrusted;
  if (c.retimed) into.retimed = true;
}

/** Read up to {@link SNIFF_BYTES} from the start of an open file without moving its position. */
async function readHeadFrom(fh: fs.promises.FileHandle): Promise<Buffer> {
  const head = Buffer.alloc(SNIFF_BYTES);
  let got = 0;
  while (got < SNIFF_BYTES) {
    const { bytesRead } = await fh.read(head, got, SNIFF_BYTES - got, got);
    if (bytesRead === 0) break;
    got += bytesRead;
  }
  return head.subarray(0, got);
}

/** The rest of an open file after a positional head read: the whole file, from the same descriptor. */
async function readAllFrom(fh: fs.promises.FileHandle, size: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let pos = 0;
  let total = 0;
  for (;;) {
    const buf = Buffer.alloc(Math.max(65536, Math.min(size - pos, 8 * 1024 * 1024)));
    const { bytesRead } = await fh.read(buf, 0, buf.length, pos);
    if (bytesRead === 0) break;
    chunks.push(buf.subarray(0, bytesRead));
    pos += bytesRead;
    total += bytesRead;
  }
  return Buffer.concat(chunks, total);
}

function tag(matches: SecretMatch[], source: MatchSource, stage?: 2 | 3): SecretMatch[] {
  return matches.map(m => ({ ...m, source, ...(stage !== undefined ? { stage } : {}) }));
}

function freshHits(): IgnoreDirectiveHits {
  return { count: 0, lines: [], criticalVendorAnchored: 0 };
}

/**
 * Fold a disk copy's inline-directive tally into the blob's. The same
 * directive in both copies is one suppression, not two: only what the disk
 * copy suppressed beyond the blob is added.
 */
function foldHits(into: IgnoreDirectiveHits, blob: IgnoreDirectiveHits, disk: IgnoreDirectiveHits): void {
  into.count += blob.count + Math.max(0, disk.count - blob.count);
  into.criticalVendorAnchored =
    (into.criticalVendorAnchored ?? 0) +
    (blob.criticalVendorAnchored ?? 0) +
    Math.max(0, (disk.criticalVendorAnchored ?? 0) - (blob.criticalVendorAnchored ?? 0));
  into.lines.push(...new Set([...blob.lines, ...disk.lines]));
}

const valueKey = (m: SecretMatch): string => `${m.type}\0${m.valueDigest ?? ''}`;
const identityKey = (m: SecretMatch): string =>
  `${m.type}\0${m.valueDigest ?? ''}\0${m.line}\0${m.offset}\0${m.matchLength}`;

/**
 * Report once per distinct finding (2.5, step 1). Value-bearing matches (with
 * a `valueDigest`) are deduplicated as a multiset of `(rule, valueDigest)`:
 * stage 3 against stage 2 for a conflicted path, then the disk copy against
 * the blob side. The same secret in both is reported once, from the blob; a
 * second copy that exists only on disk is still reported. Header-only matches
 * are all kept here; {@link dropHeaderOnlyTwins} runs after the baseline.
 */
export function mergeCopies(blobSides: SecretMatch[][], disk: SecretMatch[]): SecretMatch[] {
  const blob: SecretMatch[] = [];
  const counts = new Map<string, number>();
  const take = (m: SecretMatch): boolean => {
    if (m.valueDigest === undefined) return false;
    const k = valueKey(m);
    const n = counts.get(k) ?? 0;
    if (n === 0) return false;
    counts.set(k, n - 1);
    return true;
  };
  blobSides.forEach((side, i) => {
    const before = new Map(counts);
    for (const m of side) {
      // A later stage is deduplicated only against the earlier stages.
      if (i > 0 && m.valueDigest !== undefined) {
        const k = valueKey(m);
        const n = before.get(k) ?? 0;
        if (n > 0) {
          before.set(k, n - 1);
          continue;
        }
      }
      blob.push(m);
      if (m.valueDigest !== undefined) counts.set(valueKey(m), (counts.get(valueKey(m)) ?? 0) + 1);
    }
  });
  const kept = disk.filter(m => !take(m));
  return [...blob, ...kept];
}

/**
 * 2.5, step 3, run AFTER the baseline: a disk-copy header-only match is
 * dropped only when an UNSUPPRESSED blob match has the same rule, line,
 * offset and length. One whose twin the baseline suppressed stays and is
 * judged on its own bytes.
 */
export function dropHeaderOnlyTwins<T extends { file: string; matches: SecretMatch[] }>(results: T[]): T[] {
  const out: T[] = [];
  for (const r of results) {
    const twins = new Set(
      r.matches
        .filter(m => m.source !== 'worktree' && m.valueDigest === undefined)
        .map(m => `${m.type}\0${m.line}\0${m.offset}\0${m.matchLength}`),
    );
    const matches = r.matches.filter(
      m =>
        !(
          m.source === 'worktree' &&
          m.valueDigest === undefined &&
          twins.has(`${m.type}\0${m.line}\0${m.offset}\0${m.matchLength}`)
        ),
    );
    if (matches.length > 0) out.push({ ...r, matches });
  }
  return out;
}

/**
 * Scan every copy of one file. `entry` and `source` are absent for a file
 * with no blob (untracked, outside git): it is read from disk as `file`.
 *
 * Throws {@link GitError} when git fails, which the caller must let through:
 * a git failure while reading tracked content is could-not-run, never a quiet
 * fall back to the disk copy.
 */
export async function scanFileContent(
  scanner: SecretScanner,
  file: string,
  entry: TrackedEntry | undefined,
  source: GitContentSource | undefined,
  opts: ScanFileContentOptions = {},
): Promise<FileContentOutcome> {
  const max = opts.maxBytes ?? MAX_SCAN_FILE_BYTES;
  const kept = new Map<string, Buffer>();
  const outcome = (o: Partial<FileContentOutcome>): FileContentOutcome => ({
    matches: [],
    bytesRead: 0,
    worktreeScanned: false,
    kept,
    elapsedMs: 0,
    binaryCopiesSkipped: 0,
    retimed: false,
    ...o,
  });

  if (!entry || !source) {
    const cand = opts.classify ? binaryCandidate(file) : undefined;
    let bytes: Buffer;
    let typeMismatch: { family: BinaryFamily } | undefined;
    if (cand) {
      // One descriptor: the bytes judged are the bytes read (4.3).
      const fh = await fs.promises.open(file, 'r');
      try {
        const head = await readHeadFrom(fh);
        if (confirmsBinary(cand.ext, head)) {
          return outcome({ skippedByType: { family: cand.family }, bytesRead: head.length });
        }
        const st = await fh.stat();
        if (!isLfsPointer(head, st.size)) typeMismatch = { family: cand.family };
        if (st.size > max) {
          return outcome({ failure: { kind: 'too_large', bytes: st.size }, ...(typeMismatch ? { typeMismatch } : {}) });
        }
        bytes = await readAllFrom(fh, st.size);
      } finally {
        await fh.close();
      }
    } else {
      const st = await fs.promises.stat(file);
      if (st.size > max) return outcome({ failure: { kind: 'too_large', bytes: st.size } });
      bytes = await fs.promises.readFile(file);
    }
    const mm = typeMismatch ? { typeMismatch } : {};
    if (bytes.length > max) return outcome({ failure: { kind: 'too_large', bytes: bytes.length }, ...mm });
    const hits = opts.ignoreHits ? freshHits() : undefined;
    const scanned = scanText(scanner, decodeTextBuffer(bytes), file, opts, hits);
    if (hits && opts.ignoreHits) foldHits(opts.ignoreHits, hits, freshHits());
    if (scanned.matches.some(m => m.valueDigest === undefined)) kept.set(copyKey(file, 'file'), bytes);
    const budget = { elapsedMs: 0, retimed: false } as { untrusted?: BudgetUntrusted; retimed: boolean; elapsedMs: number };
    foldBudget(budget, scanned);
    return outcome({
      matches: tag(scanned.matches, 'file'),
      bytesRead: bytes.length,
      elapsedMs: budget.elapsedMs,
      retimed: budget.retimed && !budget.untrusted,
      ...(budget.untrusted ? { untrusted: budget.untrusted } : {}),
      ...mm,
    });
  }

  const blobs: Array<{ oid: string; stage?: 2 | 3 }> =
    entry.oid !== undefined
      ? [{ oid: entry.oid }]
      : [
          ...(entry.ours !== undefined ? [{ oid: entry.ours, stage: 2 as const }] : []),
          ...(entry.theirs !== undefined ? [{ oid: entry.theirs, stage: 3 as const }] : []),
        ];
  try {
    return await scanTrackedCopies(scanner, file, entry, source, opts, blobs, max, kept, outcome);
  } finally {
    // Whatever happened to this path, it no longer needs these blobs.
    for (const b of blobs) source.done(entry.repoTop, b.oid);
  }
}

/** The blob and disk reads of one tracked file, for {@link scanFileContent}. */
async function scanTrackedCopies(
  scanner: SecretScanner,
  file: string,
  entry: TrackedEntry,
  source: GitContentSource,
  opts: ScanFileContentOptions,
  blobs: Array<{ oid: string; stage?: 2 | 3 }>,
  max: number,
  kept: Map<string, Buffer>,
  outcome: (o: Partial<FileContentOutcome>) => FileContentOutcome,
): Promise<FileContentOutcome> {
  // Each copy is judged on its own bytes (design 2026-10-17, 4.2 and 4.3).
  // The blob is judged by the name the path was given; the disk read by the
  // name of what it holds (a named symlink's resolved target).
  const blobCand = opts.classify ? binaryCandidate(file) : undefined;
  const diskFile = entry.diskPath ?? file;
  const diskCand = opts.classify ? binaryCandidate(diskFile) : undefined;
  let typeMismatch: { family: BinaryFamily } | undefined;
  const mm = (): Partial<FileContentOutcome> => (typeMismatch ? { typeMismatch } : {});
  let headBytes = 0;
  const scanBlobs: Array<{ oid: string; stage?: 2 | 3 }> = [];
  for (const b of blobs) {
    const c = source.check(entry.repoTop, b.oid);
    if (c.kind === 'missing') return outcome({ failure: { kind: 'read_error', reason: MISSING_BLOB_REASON }, ...mm() });
    if (c.kind === 'other') {
      throw new GitError(
        `vault-guard: ${file} is listed as a tracked file, but its object ${b.oid} is a ${c.type}, ` +
          'not a blob. The repository changed under the run. Nothing was scanned.',
        'git cat-file --batch-check',
      );
    }
    if (blobCand) {
      // Head first: a confirmed binary is skipped at any size (4.7).
      const head = await source.readHead(entry.repoTop, b.oid, SNIFF_BYTES);
      if (confirmsBinary(blobCand.ext, head)) {
        headBytes += head.length;
        continue;
      }
      if (!isLfsPointer(head, c.size)) typeMismatch = { family: blobCand.family };
    }
    if (c.size > max) return outcome({ failure: { kind: 'too_large', bytes: c.size }, ...mm() });
    scanBlobs.push(b);
  }
  const readDisk = entry.worktreeAlso && !entry.diskAbsent;
  let diskBytes: Buffer | undefined;
  let diskSkipped = false;
  if (readDisk) {
    let st: fs.Stats;
    try {
      st = await fs.promises.lstat(diskFile);
    } catch (error) {
      return outcome({ failure: { kind: 'read_error', reason: String(error) }, ...mm() });
    }
    if (diskCand) {
      try {
        const fh = await fs.promises.open(diskFile, 'r');
        try {
          const head = await readHeadFrom(fh);
          if (confirmsBinary(diskCand.ext, head, entry.encoding)) {
            diskSkipped = true;
            headBytes += head.length;
          } else {
            const fst = await fh.stat();
            if (!isLfsPointer(head, fst.size)) typeMismatch = { family: diskCand.family };
            if (fst.size > max) return outcome({ failure: { kind: 'too_large', bytes: fst.size }, ...mm() });
            diskBytes = await readAllFrom(fh, fst.size);
          }
        } finally {
          await fh.close();
        }
      } catch (error) {
        return outcome({ failure: { kind: 'read_error', reason: String(error) }, ...mm() });
      }
    } else if (st.size > max) {
      return outcome({ failure: { kind: 'too_large', bytes: st.size }, ...mm() });
    }
  }

  // No copy left to scan: the file is skipped by type.
  if (scanBlobs.length === 0 && (!readDisk || diskSkipped)) {
    const family = (blobCand ?? diskCand)?.family as BinaryFamily;
    return outcome({ skippedByType: { family }, bytesRead: headBytes });
  }

  const blobSides: SecretMatch[][] = [];
  const blobHits = opts.ignoreHits ? freshHits() : undefined;
  let bytesRead = 0;
  const budget = { elapsedMs: 0, retimed: false } as { untrusted?: BudgetUntrusted; retimed: boolean; elapsedMs: number };
  for (const b of scanBlobs) {
    const bytes = await source.read(entry.repoTop, b.oid);
    bytesRead += bytes.length;
    const scanned = scanText(scanner, decodeTextBuffer(bytes), file, opts, blobHits);
    foldBudget(budget, scanned);
    const src = source.blobSource;
    if (scanned.matches.some(m => m.valueDigest === undefined)) kept.set(copyKey(file, src, b.stage), bytes);
    blobSides.push(tag(scanned.matches, src, b.stage));
  }

  let disk: SecretMatch[] = [];
  let undecodable: string | undefined;
  const diskHits = opts.ignoreHits ? freshHits() : undefined;
  const scanDisk = readDisk && !diskSkipped;
  if (scanDisk) {
    if (diskBytes === undefined) {
      try {
        diskBytes = await fs.promises.readFile(diskFile);
      } catch (error) {
        return outcome({ failure: { kind: 'read_error', reason: String(error) }, ...mm() });
      }
    }
    bytesRead += diskBytes.length;
    const decoded = decodeDiskCopy(diskBytes, entry.encoding, entry.filtered);
    undecodable = decoded.unsupported;
    const seen = new Set<string>();
    const texts = decoded.texts.filter((t, i) => i === 0 || t !== decoded.texts[0]);
    for (const text of texts) {
      const scanned = scanText(scanner, text, file, opts, diskHits);
      foldBudget(budget, scanned);
      const matches = scanned.matches;
      for (const m of matches) {
        const k = identityKey(m);
        if (seen.has(k)) continue;
        seen.add(k);
        disk.push(m);
      }
    }
    if (disk.some(m => m.valueDigest === undefined)) kept.set(copyKey(file, 'worktree'), diskBytes);
    disk = tag(disk, 'worktree');
  }
  if (opts.ignoreHits && blobHits && diskHits) foldHits(opts.ignoreHits, blobHits, diskHits);

  return outcome({
    matches: mergeCopies(blobSides, disk),
    bytesRead,
    worktreeScanned: scanDisk,
    ...(undecodable !== undefined ? { undecodable } : {}),
    elapsedMs: budget.elapsedMs,
    binaryCopiesSkipped: diskSkipped ? 1 : 0,
    retimed: budget.retimed && !budget.untrusted,
    ...(budget.untrusted ? { untrusted: budget.untrusted } : {}),
    ...mm(),
  });
}

/** Resolve symlinks; fall back to the input when that is not possible. */
function canonical(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/** A tracked symlink named on the command line, and where it resolves. */
export interface NamedLinkResolution {
  /** The regular file inside the repository it points at, or undefined. */
  target?: string;
  /** Why it was not followed, when it was not. */
  reason?: 'outside' | 'missing' | 'loop' | 'not-a-file';
}

/**
 * Resolve a named tracked symlink once and compare the result with the
 * canonical repository root (2.1). Only a regular file inside the root is
 * followed; anything else is reported and not read.
 */
export function resolveNamedLink(link: string, repoTop: string): NamedLinkResolution {
  let real: string;
  try {
    real = fs.realpathSync.native(link);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException | undefined)?.code;
    return { reason: code === 'ELOOP' ? 'loop' : 'missing' };
  }
  const rel = path.relative(canonical(repoTop), real);
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) return { reason: 'outside' };
  let st: fs.Stats;
  try {
    st = fs.statSync(real);
  } catch {
    return { reason: 'missing' };
  }
  if (!st.isFile()) return { reason: 'not-a-file' };
  return { target: real };
}

/** The warning sentence for a named link that was not followed. */
export function namedLinkWarning(display: string, reason: NonNullable<NamedLinkResolution['reason']>): string {
  switch (reason) {
    case 'outside':
      return `${display}: symlink target is outside the repository, not followed`;
    case 'missing':
      return `${display}: symlink target does not exist, not followed`;
    case 'loop':
      return `${display}: symlink target cannot be resolved (a loop), not followed`;
    case 'not-a-file':
      return `${display}: symlink target is not a regular file, not followed`;
  }
}

/**
 * Tracked files named explicitly on the command line (2.3, last table row).
 * Grouped by the toplevel `git rev-parse --show-toplevel` reports for each
 * file's directory (a file inside a submodule belongs to the submodule), and
 * each group listed with ONE `ls-files -z -s -v` (plain) or `ls-tree -z HEAD`
 * (pull-request) call at that toplevel, plus one status and one check-attr.
 * Files outside any repository, or not tracked, are absent from the result.
 *
 * `isInsideGit` decides, by the presence of a `.git` entry, whether a file's
 * directory is inside git at all; once it is, a git failure throws.
 */
export function listNamedTrackedFiles(
  files: string[],
  blobSource: 'index' | 'head',
  env: NodeJS.ProcessEnv,
  isInsideGit: (dir: string) => boolean,
): Map<string, TrackedEntry> {
  const result = new Map<string, TrackedEntry>();
  const topByDir = new Map<string, string>();
  const groups = new Map<string, Array<{ given: string; rel: string }>>();
  for (const given of files) {
    const dir = path.dirname(given);
    if (!isInsideGit(dir)) continue;
    let top = topByDir.get(dir);
    if (top === undefined) {
      top = canonical(runContentGit(dir, ['rev-parse', '--show-toplevel'], env).trim());
      topByDir.set(dir, top);
    }
    const physical = path.join(canonical(dir), path.basename(given));
    const rel = path.relative(top, physical).split(path.sep).join('/');
    if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) continue;
    const g = groups.get(top) ?? [];
    g.push({ given, rel });
    groups.set(top, g);
  }
  for (const [top, group] of groups) {
    const specs = group.map(g => `:(literal)${g.rel}`);
    const byRel = new Map<string, { mode: string; tag?: string; oid?: string; ours?: string; theirs?: string }>();
    if (blobSource === 'head') {
      for (const record of splitZ(runContentGit(top, ['ls-tree', '-z', 'HEAD', '--', ...specs], env))) {
        const t = record.indexOf('\t');
        if (t === -1) continue;
        const [mode, type, oid] = record.slice(0, t).split(' ');
        if (type !== 'blob') continue;
        byRel.set(record.slice(t + 1), { mode, oid });
      }
    } else {
      for (const record of splitZ(runContentGit(top, ['ls-files', '-z', '-s', '-v', '--', ...specs], env))) {
        const t = record.indexOf('\t');
        if (t === -1) continue;
        const [tagCol, mode, oid, stage] = record.slice(0, t).split(' ');
        if (mode === '160000') continue;
        const rel = record.slice(t + 1);
        const e = byRel.get(rel) ?? { mode, tag: tagCol };
        if (stage === '0') e.oid = oid;
        else if (stage === '2') e.ours = oid;
        else if (stage === '3') e.theirs = oid;
        byRel.set(rel, e);
      }
    }
    if (byRel.size === 0) continue;
    const rels = [...byRel.keys()];
    const inspection = inspectWorktree(top, ':(literal).', rels, env);
    for (const { given, rel } of group) {
      const e = byRel.get(rel);
      if (!e || (e.oid === undefined && e.ours === undefined && e.theirs === undefined)) continue;
      const attrs = inspection.attrs.get(rel) ?? { filter: false };
      const conflicted = e.oid === undefined;
      result.set(given, {
        repoTop: top,
        mode: e.mode,
        ...(e.oid !== undefined ? { oid: e.oid } : {}),
        ...(e.ours !== undefined ? { ours: e.ours } : {}),
        ...(e.theirs !== undefined ? { theirs: e.theirs } : {}),
        worktreeAlso:
          e.mode !== '120000' &&
          (conflicted || wantsWorktreeCopy(blobSource, inspection.status.get(rel), e.tag, attrs.filter)),
        ...(attrs.encoding !== undefined ? { encoding: attrs.encoding } : {}),
        filtered: attrs.filter,
      });
    }
  }
  return result;
}
