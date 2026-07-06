import path from 'path';
import type { SecretMatch } from './types';
import type { Diagnostic } from './diagnostics';
import { fingerprintForMatch } from './match-fingerprint';

/** One file's scan outcome — shared by CLI, MCP, and SARIF/JSON formatters. */
export interface FileScanResult {
  file: string;
  matches: SecretMatch[];
}

/** Optional machine-readable scan run metadata (JSON + SARIF driver properties). */
export interface JsonRunMetadata {
  duration_ms: number;
  /** Files opened and scanned for secrets (excludes skipped binaries). */
  files_scanned: number;
  /** Total bytes read from disk for those scans (capped at per-file read limit when streaming). */
  bytes_scanned: number;
  /** Active regex rules after config (built-ins minus "off", plus accepted extra_patterns). */
  patterns_active: number;
  diagnostics_count?: number;
  /** Matches removed because they appeared in `.vault-guard.baseline.json`. */
  baseline_suppressed?: number;
}

export interface JsonOutput {
  version: string;
  scannedAt: string;
  summary: { files: number; secrets: number };
  /** Present when the caller passes {@link FormatOptions.run}. */
  run?: JsonRunMetadata;
  results: Array<{
    file: string;
    matches: Array<{
      type: string;
      severity: string;
      line: number;
      /** 0-based line-relative column. */
      column: number;
      /** Redacted form, e.g. `sk-a…(37c)`. Never the raw secret. */
      value: string;
      /** SHA-256 hex of `relPath|type|line|offset|matchLength` for baselines (no raw secret). */
      fingerprint: string;
    }>;
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
   * Pass `null` to skip relativization entirely.
   */
  cwd?: string | null;
  /** Non-fatal diagnostics to include in structured output. */
  diagnostics?: Diagnostic[];
  /** Scan timing / coverage stats for JSON and SARIF `runs[].properties`. */
  run?: JsonRunMetadata;
}

/**
 * Normalize a file path for output: cwd-relative when inside `cwd`, absolute
 * otherwise (so we never emit `../../..` traversals).
 *
 * Why this matters: absolute paths in JSON / SARIF leak the developer's home
 * directory and OS username when the output is shared (PR comments, GitHub
 * Code Scanning UI, support tickets, screenshots).
 */
function normalizeFilePath(file: string, cwd: string | null | undefined): string {
  if (cwd === null) return file;
  const base = cwd ?? process.cwd();
  if (!path.isAbsolute(file)) return file;
  const rel = path.relative(base, file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return file;
  return rel || '.';
}

export function formatJson(results: FileScanResult[], opts: FormatOptions = {}): string {
  const fpCwd = opts.cwd === undefined ? process.cwd() : opts.cwd;
  const output: JsonOutput = {
    version: '1',
    scannedAt: new Date().toISOString(),
    summary: {
      files: results.length,
      secrets: results.reduce((n, r) => n + r.matches.length, 0),
    },
    ...(opts.run ? { run: opts.run } : {}),
    results: results.map(({ file, matches }) => ({
      file: normalizeFilePath(file, opts.cwd),
      matches: matches.map(m => ({
        type: m.type,
        severity: m.severity,
        line: m.line,
        column: m.column,
        value: m.value,
        fingerprint: fingerprintForMatch(fpCwd, file, m),
      })),
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

/** SARIF 2.1.0 — compatible with GitHub Code Scanning (upload-sarif action). */
export function formatSarif(results: FileScanResult[], opts: FormatOptions = {}): string {
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

  const sarifResults = results.flatMap(({ file, matches }) =>
    matches.map(m => ({
      ruleId: m.type,
      level: m.severity === 'critical' ? 'error' : m.severity === 'high' ? 'warning' : 'note',
      // Intentionally do NOT include the masked value here. Reviewers have the
      // exact byte region (startLine/startColumn/endColumn) and the rule id;
      // the masked prefix adds no signal and grows the leak surface area.
      message: { text: `Possible secret of type '${m.type}'` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: normalizeFilePath(file, opts.cwd), uriBaseId: '%SRCROOT%' },
            region: {
              startLine: m.line,
              startColumn: m.column + 1,
              endColumn: m.column + m.matchLength + 1,
            },
          },
        },
      ],
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
          message: { text: `${d.code}: ${JSON.stringify(d.ctx)}` },
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
          },
        }
      : undefined;

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
      {
        ...(runProps ? { properties: runProps } : {}),
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
