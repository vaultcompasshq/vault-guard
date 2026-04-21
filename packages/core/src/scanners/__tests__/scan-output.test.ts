import path from 'path';
import { formatJson, formatSarif, type FileScanResult } from '../../scan-output';
import type { SecretMatch } from '../../types';

function makeMatch(over: Partial<SecretMatch> = {}): SecretMatch {
  return {
    type: 'anthropic',
    value: 'sk-a…(37c)',
    line: 4,
    column: 12,
    matchLength: 37,
    severity: 'critical',
    ...over,
  };
}

describe('scan-output formatters', () => {
  describe('relative path normalization', () => {
    const cwd = '/repo/project';
    const insideFile = '/repo/project/src/leak.ts';
    const outsideFile = '/somewhere/else/leak.ts';

    it('formatJson rewrites absolute paths inside cwd as relative', () => {
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const out = JSON.parse(formatJson(results, { cwd }));
      expect(out.results[0].file).toBe(path.join('src', 'leak.ts'));
    });

    it('formatJson preserves paths that are outside cwd (no .. traversal)', () => {
      const results: FileScanResult[] = [{ file: outsideFile, matches: [makeMatch()] }];
      const out = JSON.parse(formatJson(results, { cwd }));
      expect(out.results[0].file).toBe(outsideFile);
    });

    it('formatSarif rewrites absolute paths inside cwd as relative', () => {
      const results: FileScanResult[] = [{ file: insideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe(path.join('src', 'leak.ts'));
    });

    it('formatSarif preserves paths that are outside cwd', () => {
      const results: FileScanResult[] = [{ file: outsideFile, matches: [makeMatch()] }];
      const sarif = JSON.parse(formatSarif(results, { cwd }));
      const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
      expect(uri).toBe(outsideFile);
    });
  });

  describe('value redaction in formatter output', () => {
    it('SARIF message does not contain the masked value at all', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ value: 'sk-a…(37c)' })] }];
      const sarif = formatSarif(results, { cwd: null });
      expect(sarif).not.toContain('masked:');
      expect(sarif).not.toContain('sk-a…(37c)');
    });

    it('JSON output exposes only the redacted value field', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ value: 'sk-a…(37c)' })] }];
      const out = JSON.parse(formatJson(results, { cwd: null }));
      expect(out.results[0].matches[0].value).toBe('sk-a…(37c)');
      expect(JSON.stringify(out)).not.toContain('verylongkeyhere');
    });
  });
});
