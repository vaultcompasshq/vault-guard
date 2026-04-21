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
      value: string;
    }>;
  }>;
}

export function formatJson(results: FileScanResult[]): string {
  const output: JsonOutput = {
    version: '1',
    scannedAt: new Date().toISOString(),
    summary: {
      files: results.length,
      secrets: results.reduce((n, r) => n + r.matches.length, 0),
    },
    results: results.map(({ file, matches }) => ({
      file,
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
export function formatSarif(results: FileScanResult[]): string {
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
      message: { text: `Possible secret of type '${m.type}' detected (masked: ${m.value})` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: file, uriBaseId: '%SRCROOT%' },
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
