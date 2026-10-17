import fs from 'fs';
import os from 'os';
import path from 'path';

import { scanFileContent } from '../content-source';
import { THREAD_CPU_STABLE_NODE, defaultScanClock, threadCpuClockUsable } from '../scan-clock';
import { SecretScanner } from '../../scanners/secret-scanner';

/**
 * Section 6.2 of the 2026-10-17 design: the per-thread CPU clock is used only
 * when `process.threadCpuUsage` exists AND the Node version is in the
 * recorded stable range, decided statically; otherwise the measure is the
 * smaller of process CPU and wall time.
 */
describe('the scan clock decision', () => {
  it.each([
    ['22.0.0', true, false],
    ['22.18.9', true, false],
    ['22.19.0', true, true],
    ['22.23.2', true, true],
    ['23.8.0', true, false],
    ['23.9.0', true, true],
    ['24.0.0', true, true],
    ['25.2.1', true, true],
    ['v24.10.0', true, true],
    ['99.0.0', true, false],
    ['24.0.0', false, false],
    ['22.23.2', false, false],
    ['not a version', true, false],
  ])('Node %s with threadCpuUsage present=%s: per-thread %s', (v, present, expected) => {
    expect(threadCpuClockUsable(v, present)).toBe(expected);
  });

  it('records every Node line of the CI matrix', () => {
    const majors = THREAD_CPU_STABLE_NODE.map(r => r.major);
    for (const m of [22, 24, 25]) expect(majors).toContain(m);
  });

  it('the default clock takes the branch the static rule names for this process', () => {
    const hasFn = typeof (process as { threadCpuUsage?: unknown }).threadCpuUsage === 'function';
    const expected = threadCpuClockUsable(process.versions.node, hasFn) ? 'thread-cpu' : 'min-process-cpu-wall';
    expect(defaultScanClock().measure).toBe(expected);
  });
});

describe('a scan emits no process warning', () => {
  it('no warning event during a full scan with the budget on (run on every CI Node line)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-clock-warn-'));
    const warnings: unknown[] = [];
    const onWarning = (w: unknown): void => {
      warnings.push(w);
    };
    process.on('warning', onWarning);
    try {
      const file = path.join(dir, 'a.ts');
      fs.writeFileSync(file, 'export const x = 1;\n'.repeat(2000));
      const o = await scanFileContent(new SecretScanner(), file, undefined, undefined, {
        classify: true,
        budgetMs: 5000,
      });
      expect(o.untrusted).toBeUndefined();
      // Warnings are emitted on the next tick.
      await new Promise(r => setImmediate(r));
      expect(warnings).toEqual([]);
    } finally {
      process.off('warning', onWarning);
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
