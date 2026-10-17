import * as fs from 'fs';

import type { ScanClock } from '@vaultcompass/vault-guard-core';
import { scanCommand } from '../../commands/scan';
import { capture, commitAll, initRepo, tmpDir, write } from './git-fixture';
import { f17Svg, gcpKey } from './data-file-fixtures';

/**
 * A23 of the 2026-10-17 data-file design: the demotion depends on the text
 * only, so a copy re-timed after a slow first pass gets the same matches and
 * the same demotion records. The clock seam wraps core's scanFileContent, as
 * in scan-budget-retime.test.ts.
 */

const seam: { clock?: ScanClock } = {};

jest.mock('@vaultcompass/vault-guard-core', () => {
  const actual = jest.requireActual('@vaultcompass/vault-guard-core');
  return {
    ...actual,
    scanFileContent: (...args: unknown[]) => {
      const [s, f, e, src, o] = args as [unknown, string, unknown, unknown, Record<string, unknown> | undefined];
      const clock = f.endsWith('logo.svg') ? seam.clock : undefined;
      return actual.scanFileContent(s, f, e, src, { ...(o ?? {}), ...(clock ? { clock } : {}) });
    },
  };
});

/** The n-th measured span advances CPU and wall by cpu[n]. */
function scripted(cpu: number[]): ScanClock {
  let c = 0;
  let cc = 0;
  let w = 0;
  let wc = 0;
  return {
    measure: 'thread-cpu',
    cpuMs: () => {
      if (cc % 2 === 1) c += cpu[(cc - 1) / 2] ?? 0;
      cc++;
      return c;
    },
    wallMs: () => {
      if (wc % 2 === 1) w += cpu[(wc - 1) / 2] ?? 0;
      wc++;
      return w;
    },
  };
}

describe('A23: a re-timed copy keeps its demotion', () => {
  const originalCwd = process.cwd();
  const dirs: string[] = [];

  afterEach(() => {
    seam.clock = undefined;
    process.chdir(originalCwd);
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it('6000 then 100 ms: scan_budget_retimed 1, the same match and record as A4, exit 0', async () => {
    const d = tmpDir('vg-data-retime-');
    dirs.push(d);
    initRepo(d);
    write(d, 'src/ok.ts', 'export const ok = 1;\n');
    write(d, 'assets/logo.svg', f17Svg(gcpKey(3), 64 * 1024));
    commitAll(d, 'init');
    process.chdir(d);

    const plain = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout);
    seam.clock = scripted([6000, 100]);
    const r = await capture(() => scanCommand('.', 'json'));
    const doc = JSON.parse(r.stdout);
    expect(r.code).toBe(0);
    expect(doc.run.scan_budget_retimed).toBe(1);
    expect(doc.run.unscannable_files).toBeUndefined();
    const strip = (x: { results: Array<{ matches: unknown[] }> }) => x.results.map(e => e.matches);
    expect(strip(doc)).toEqual(strip(plain));
    expect(doc.results[0].matches[0].demotion).toMatchObject({ from: 'critical', reason: 'data-uri-binary-payload' });
  });
});
