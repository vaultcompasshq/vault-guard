import fs from 'fs';
import os from 'os';
import path from 'path';
import { loadBaseline, filterResultsByBaseline, BASELINE_FILENAME } from '../baseline';
import { fingerprintForMatch } from '../match-fingerprint';
import type { FileScanResult } from '../scan-output';
import type { SecretMatch } from '../types';

function match(over: Partial<SecretMatch> = {}): SecretMatch {
  return {
    type: 'anthropic',
    value: 'sk-a…(37c)',
    line: 2,
    column: 0,
    matchLength: 10,
    severity: 'critical',
    ...over,
  };
}

describe('baseline + fingerprints', () => {
  it('fingerprint is stable for the same cwd, file, and span', () => {
    const cwd = '/repo';
    const file = path.join('/repo', 'src', 'a.ts');
    const m = match();
    expect(fingerprintForMatch(cwd, file, m)).toBe(fingerprintForMatch(cwd, file, m));
  });

  it('filterResultsByBaseline removes matches whose fingerprint is listed', () => {
    const cwd = '/repo';
    const file = path.join('/repo', 'src', 'a.ts');
    const m = match();
    const fp = fingerprintForMatch(cwd, file, m);
    const results: FileScanResult[] = [{ file, matches: [m] }];
    const { results: out, suppressed } = filterResultsByBaseline(cwd, results, new Set([fp]));
    expect(suppressed).toBe(1);
    expect(out).toEqual([]);
  });

  it('loadBaseline reads nearest baseline file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-bl-'));
    try {
      const sub = path.join(dir, 'sub');
      fs.mkdirSync(sub, { recursive: true });
      const fp = fingerprintForMatch(sub, path.join(sub, 'x.ts'), match());
      fs.writeFileSync(
        path.join(sub, BASELINE_FILENAME),
        JSON.stringify({ version: 1, fingerprints: [fp] }),
        'utf8',
      );
      const loaded = loadBaseline(sub);
      expect(loaded.fingerprints.has(fp)).toBe(true);
      expect(loaded.sourcePath).toBe(path.join(sub, BASELINE_FILENAME));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
