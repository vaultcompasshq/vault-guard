import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import type { SecretMatch } from './types';
import type { FileScanResult } from './scan-output';
import { listConfigSearchDirs } from './config';
import {
  fingerprintForMatch,
  contentFingerprintForMatch,
  rootPositionalFingerprint,
} from './match-fingerprint';

/** Default baseline filename (same discovery walk as `.vault-guard.json`). */
export const BASELINE_FILENAME = '.vault-guard.baseline.json';

export interface BaselineFileV1 {
  version: 1;
  fingerprints: string[];
  entries?: BaselineEntry[];
}

export type BaselineSeverity = SecretMatch['severity'];

const SEVERITY_RANK: Record<BaselineSeverity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

function isBaselineSeverity(v: unknown): v is BaselineSeverity {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(SEVERITY_RANK, v);
}

/**
 * One accepted finding in the `entries` list.
 *
 * For a value-bearing rule `fingerprint` is the content fingerprint
 * (`vg-fp-v2`). For a header-only rule it is the positional fingerprint taken
 * relative to the content root, and `file_digest` (SHA-256 over the file's raw
 * bytes) must match too. Which of the two applies is decided by the CURRENT
 * rule table at read time, never by the entry's shape.
 */
export interface BaselineEntry {
  fingerprint: string;
  /** Null when the stored severity is missing or unknown: the entry then suppresses nothing. */
  severity: BaselineSeverity | null;
  /** How many matches with this key the entry may suppress. */
  count: number;
  rule?: string;
  file?: string;
  line?: number;
  file_digest?: string;
}

export interface LoadBaselineOutcome {
  /** Absolute path of the baseline file that was read, if any. */
  sourcePath?: string;
  /** The positional list. Used for matching only when `entries` is null. */
  fingerprints: Set<string>;
  /**
   * The `entries` list. Null when the file has none, which means positional
   * matching as before 1.10. An empty array (including a malformed list) means
   * entries mode with nothing to suppress: it never falls back to positional.
   */
  entries?: BaselineEntry[] | null;
  /** Present when a baseline file existed but JSON was invalid or wrong shape. */
  parseError?: string;
}

/** The parsed form of one baseline document. */
export interface ParsedBaseline {
  fingerprints: Set<string>;
  entries: BaselineEntry[] | null;
  parseError?: string;
}

/**
 * Parse an `entries` value. Returns the entries, or an error for the whole
 * list (not an array, an entry that is not an object, a missing or non-string
 * fingerprint, a count that is not a positive integer). An individual entry
 * whose severity is missing or unknown is kept with severity null, so it
 * suppresses nothing, and is named in `warnings`.
 */
function parseEntries(value: unknown): { entries: BaselineEntry[]; error?: string; warnings: string[] } {
  if (!Array.isArray(value)) {
    return { entries: [], error: 'entries must be an array', warnings: [] };
  }
  const entries: BaselineEntry[] = [];
  const warnings: string[] = [];
  for (let i = 0; i < value.length; i++) {
    const e = value[i] as unknown;
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      return { entries: [], error: `entries[${i}] is not an object`, warnings: [] };
    }
    const o = e as Record<string, unknown>;
    if (typeof o.fingerprint !== 'string' || o.fingerprint.length === 0) {
      return { entries: [], error: `entries[${i}] has no string fingerprint`, warnings: [] };
    }
    if (typeof o.count !== 'number' || !Number.isInteger(o.count) || o.count < 1) {
      return { entries: [], error: `entries[${i}] count must be a positive integer`, warnings: [] };
    }
    const severity = isBaselineSeverity(o.severity) ? o.severity : null;
    if (severity === null) {
      const where = typeof o.file === 'string' ? ` (${o.file}${typeof o.line === 'number' ? `:${o.line}` : ''})` : '';
      warnings.push(
        `entries[${i}]${where} has severity ${JSON.stringify(o.severity ?? null)}, not one of ` +
          'critical, high, medium, low, so it suppresses nothing',
      );
    }
    entries.push({
      fingerprint: o.fingerprint,
      severity,
      count: o.count,
      ...(typeof o.rule === 'string' ? { rule: o.rule } : {}),
      ...(typeof o.file === 'string' ? { file: o.file } : {}),
      ...(typeof o.line === 'number' ? { line: o.line } : {}),
      ...(typeof o.file_digest === 'string' ? { file_digest: o.file_digest } : {}),
    });
  }
  return { entries, warnings };
}

/**
 * Parse one baseline document. Shared by the working-tree load below and by
 * the base-ref load in pull-request mode, so the two sides of a base-versus-
 * head comparison are read by the same code and cannot drift apart.
 *
 * Never throws: a malformed baseline yields an empty fingerprint set and a
 * `parseError`, which is the fail-closed direction (nothing is suppressed) and
 * is reported rather than swallowed. A malformed `entries` list likewise
 * suppresses nothing: it does NOT fall back to `fingerprints`, because a
 * fallback would let one broken key quietly restore the weaker positional
 * matching.
 */
export function parseBaselineText(raw: string): ParsedBaseline {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return { fingerprints: new Set(), entries: null, parseError: 'not an object' };
    }
    const v = (parsed as { version?: unknown }).version;
    const fps = (parsed as { fingerprints?: unknown }).fingerprints;
    if (v !== 1) {
      return {
        fingerprints: new Set(),
        entries: null,
        parseError: `unsupported version (expected 1, got ${String(v)})`,
      };
    }
    if (!Array.isArray(fps)) {
      return { fingerprints: new Set(), entries: null, parseError: 'fingerprints must be an array' };
    }
    const out = new Set<string>();
    for (const x of fps) {
      if (typeof x === 'string' && x.length > 0) out.add(x);
    }
    if (!Object.prototype.hasOwnProperty.call(parsed, 'entries')) {
      return { fingerprints: out, entries: null };
    }
    const { entries, error, warnings } = parseEntries((parsed as { entries?: unknown }).entries);
    if (error !== undefined) {
      return { fingerprints: out, entries: [], parseError: `${error}; nothing is suppressed` };
    }
    return {
      fingerprints: out,
      entries,
      ...(warnings.length > 0 ? { parseError: warnings.join('; ') } : {}),
    };
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    return { fingerprints: new Set(), entries: null, parseError: `JSON: ${detail}` };
  }
}

/**
 * Walk the same directories as {@link loadConfig} and load the nearest
 * `.vault-guard.baseline.json`.
 */
export function loadBaseline(startDir: string = process.cwd()): LoadBaselineOutcome {
  const dirs = listConfigSearchDirs(startDir);
  for (const dir of dirs) {
    const filePath = path.join(dir, BASELINE_FILENAME);
    if (!fs.existsSync(filePath)) continue;

    let raw: string;
    try {
      raw = fs.readFileSync(filePath, 'utf-8');
    } catch (e) {
      const detail = e instanceof Error ? e.message : String(e);
      return {
        sourcePath: filePath,
        fingerprints: new Set(),
        parseError: `read failed: ${detail}`,
      };
    }

    return { sourcePath: filePath, ...parseBaselineText(raw) };
  }

  return { fingerprints: new Set() };
}

export function filterResultsByBaseline(
  cwd: string | null,
  results: FileScanResult[],
  baseline: Set<string>,
): { results: FileScanResult[]; suppressed: number } {
  if (baseline.size === 0) return { results, suppressed: 0 };

  let suppressed = 0;
  const out: FileScanResult[] = [];

  for (const r of results) {
    const kept: SecretMatch[] = [];
    for (const m of r.matches) {
      const fp = fingerprintForMatch(cwd, r.file, m);
      if (baseline.has(fp)) suppressed++;
      else kept.push(m);
    }
    if (kept.length > 0) out.push({ file: r.file, matches: kept });
  }

  return { results: out, suppressed };
}

/** What the baseline reader needs to know about the run it is filtering. */
export interface BaselineMatchContext {
  /** The run's anchor, which positional fingerprints are relative to. */
  anchor: string | null;
  /** The repository root inside git, the anchor outside it: what entry keys are relative to. */
  contentRoot: string;
  /**
   * The CURRENT rule table's answer for a rule id. The matching kind of an
   * entry is decided by this, never by whether the entry has a file_digest.
   */
  isValueBearing: (ruleId: string) => boolean;
  /**
   * The bytes that were SCANNED for a file, for a header-only entry's
   * `file_digest`. Defaults to the file on disk; a `--staged` run passes the
   * index blob, so the digest is never over different bytes from the ones the
   * finding came from.
   */
  readBytes?: (file: string) => Buffer;
}

/**
 * SHA-256 hex over a file's raw bytes (no line-ending or encoding
 * normalisation), or null when they cannot be read.
 */
export function fileDigest(
  file: string,
  readBytes: (file: string) => Buffer = f => fs.readFileSync(f),
): string | null {
  try {
    return createHash('sha256').update(readBytes(file)).digest('hex');
  } catch {
    return null;
  }
}

/**
 * Apply a parsed baseline to the results.
 *
 * Without an `entries` list the positional list is applied exactly as before
 * 1.10. With one, ONLY entries are used:
 *
 *  - a value-bearing match is looked up by its content fingerprint;
 *  - a match from a rule that is not value-bearing (by the current table) is
 *    looked up by its root-relative positional fingerprint, and the entry must
 *    also carry a `file_digest` equal to the digest of the file's raw bytes
 *    now. An entry without one suppresses nothing;
 *  - an entry suppresses at most `count` matches;
 *  - an entry suppresses a match only if the match's current severity is no
 *    higher than the severity the entry recorded, and never when that severity
 *    was missing or unknown.
 */
export function applyBaseline(
  results: FileScanResult[],
  baseline: { fingerprints: Set<string>; entries?: BaselineEntry[] | null },
  ctx: BaselineMatchContext,
): { results: FileScanResult[]; suppressed: number } {
  if (baseline.entries === null || baseline.entries === undefined) {
    return filterResultsByBaseline(ctx.anchor, results, baseline.fingerprints);
  }
  if (baseline.entries.length === 0) return { results, suppressed: 0 };

  const byKey = new Map<string, Array<{ entry: BaselineEntry; left: number }>>();
  for (const entry of baseline.entries) {
    const list = byKey.get(entry.fingerprint) ?? [];
    list.push({ entry, left: entry.count });
    byKey.set(entry.fingerprint, list);
  }
  const digests = new Map<string, string | null>();
  const digestOf = (file: string): string | null => {
    if (!digests.has(file)) digests.set(file, fileDigest(file, ctx.readBytes));
    return digests.get(file) ?? null;
  };

  let suppressed = 0;
  const out: FileScanResult[] = [];
  for (const r of results) {
    const kept: SecretMatch[] = [];
    for (const m of r.matches) {
      const valueBearing = ctx.isValueBearing(m.type);
      const key = valueBearing
        ? contentFingerprintForMatch(ctx.contentRoot, r.file, m)
        : rootPositionalFingerprint(ctx.contentRoot, r.file, m);
      const candidates = key === undefined ? undefined : byKey.get(key);
      const slot = candidates?.find(
        c =>
          c.left > 0 &&
          c.entry.severity !== null &&
          SEVERITY_RANK[m.severity] <= SEVERITY_RANK[c.entry.severity] &&
          (valueBearing ||
            (c.entry.file_digest !== undefined && c.entry.file_digest === digestOf(r.file))),
      );
      if (slot) {
        slot.left--;
        suppressed++;
      } else {
        kept.push(m);
      }
    }
    if (kept.length > 0) out.push({ file: r.file, matches: kept });
  }
  return { results: out, suppressed };
}
