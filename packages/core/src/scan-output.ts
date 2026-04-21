import path from 'path';
import type { SecretMatch } from './types';

/** One file’s scan outcome — shared by CLI, MCP, and SARIF/JSON formatters. */
export interface FileScanResult {
  file: string;
  matches: SecretMatch[];
}

export interface JsonOutput {
  version: string;
  scannedAt: string;
  summary: { files: number; secrets: number };
  results: Array<{
    file: string;
    matches: Array<{
      type: string;
      severity: string;
      line: number;
      column: number;
      /** Redacted form, e.g. `sk-a…(37c)`. Never the raw secret. */
      value: string;
    }>;
  }>;
}

export interface FormatOptions {
  /**
   * Base directory to render `file` paths relative to.
   * Defaults to `process.cwd()`. Files outside this root are kept absolute.
   * Pass `null` to skip relativization entirely.
   */
  cwd?: string | null;
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
  const output: JsonOutput = {
    version: '1',
    scannedAt: new Date().toISOString(),
    summary: {
      files: results.length,
      secrets: results.reduce((n, r) => n + r.matches.length, 0),
    },
    results: results.map(({ file, matches }) => ({
      file: normalizeFilePath(file, opts.cwd),
      matches: matches.map(m => ({
        type: m.type,
        severity: m.severity,
        line: m.line,
        column: m.column,
        value: m.value,
      })),
    })),
  };
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

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'vault-guard',
            informationUri: 'https://github.com/vaultcompasshq/vault-guard',
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
