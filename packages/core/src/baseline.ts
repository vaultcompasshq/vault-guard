import fs from 'fs';
import path from 'path';
import type { SecretMatch } from './types';
import type { FileScanResult } from './scan-output';
import { listConfigSearchDirs } from './config';
import { fingerprintForMatch } from './match-fingerprint';

/** Default baseline filename (same discovery walk as `.vault-guard.json`). */
export const BASELINE_FILENAME = '.vault-guard.baseline.json';

export interface BaselineFileV1 {
  version: 1;
  fingerprints: string[];
}

export interface LoadBaselineOutcome {
  /** Absolute path of the baseline file that was read, if any. */
  sourcePath?: string;
  fingerprints: Set<string>;
  /** Present when a baseline file existed but JSON was invalid or wrong shape. */
  parseError?: string;
}

/**
 * Parse one baseline document. Shared by the working-tree load below and by
 * the base-ref load in pull-request mode, so the two sides of a base-versus-
 * head comparison are read by the same code and cannot drift apart.
 *
 * Never throws: a malformed baseline yields an empty fingerprint set and a
 * `parseError`, which is the fail-closed direction (nothing is suppressed) and
 * is reported rather than swallowed.
 */
export function parseBaselineText(raw: string): {
  fingerprints: Set<string>;
  parseError?: string;
} {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      return { fingerprints: new Set(), parseError: 'not an object' };
    }
    const v = (parsed as { version?: unknown }).version;
    const fps = (parsed as { fingerprints?: unknown }).fingerprints;
    if (v !== 1) {
      return {
        fingerprints: new Set(),
        parseError: `unsupported version (expected 1, got ${String(v)})`,
      };
    }
    if (!Array.isArray(fps)) {
      return { fingerprints: new Set(), parseError: 'fingerprints must be an array' };
    }
    const out = new Set<string>();
    for (const x of fps) {
      if (typeof x === 'string' && x.length > 0) out.add(x);
    }
    return { fingerprints: out };
  } catch (e) {
    const detail = e instanceof Error ? e.message : String(e);
    return { fingerprints: new Set(), parseError: `JSON: ${detail}` };
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
