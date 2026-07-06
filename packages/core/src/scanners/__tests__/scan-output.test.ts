import path from 'path';
import { formatJson, formatSarif, type FileScanResult } from '../../scan-output';
import type { SecretMatch } from '../../types';

function makeMatch(over: Partial<SecretMatch> = {}): SecretMatch {
  return {
    type: 'anthropic',
    value: 'sk-a…(37c)',
    line: 4,
    column: 12,
    offset: 112,
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

    it('JSON matches include a 64-char sha256 fingerprint', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch()] }];
      const out = JSON.parse(formatJson(results, { cwd: null }));
      const fp = out.results[0].matches[0].fingerprint as string;
      expect(fp).toMatch(/^[a-f0-9]{64}$/);
    });

    it('formatSarif embeds run metadata under runs[0].properties when opts.run is set', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch()] }];
      const sarif = JSON.parse(
        formatSarif(results, {
          cwd: null,
          run: {
            duration_ms: 12,
            files_scanned: 3,
            bytes_scanned: 99,
            patterns_active: 40,
          },
        }),
      );
      expect(sarif.runs[0].properties.vault_guard_run.patterns_active).toBe(40);
      expect(sarif.runs[0].properties.vault_guard_run.bytes_scanned).toBe(99);
    });

    it('formatSarif uses line-relative columns for regions', () => {
      const results: FileScanResult[] = [{ file: '/tmp/x.ts', matches: [makeMatch({ column: 12, offset: 212 })] }];
      const sarif = JSON.parse(formatSarif(results, { cwd: null }));
      const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;
      expect(region.startLine).toBe(4);
      expect(region.startColumn).toBe(13);
      expect(region.endColumn).toBe(50);
    });
  });
});
