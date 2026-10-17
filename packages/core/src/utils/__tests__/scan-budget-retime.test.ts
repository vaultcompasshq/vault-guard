import fs from 'fs';
import os from 'os';
import path from 'path';

import { scanFileContent } from '../content-source';
import type { ClockMeasure, ScanClock } from '../scan-clock';
import { SecretScanner } from '../../scanners/secret-scanner';
import type { IgnoreDirectiveHits } from '../../scanners/secret-scanner';

/**
 * The budget re-time of the 2026-10-17 design, section 6.3, at the unit
 * level (the scanCommand-level rows A13 to A17 live in the CLI suite).
 */

const KEY = ['AKIA', 'Q7MZR2XVB9', 'NTD4WH'].join('');

/** A clock whose n-th measured span advances CPU by cpu[n] and wall by wall[n]. */
export function scriptedClock(measure: ClockMeasure, cpu: number[], wall: number[] = cpu): ScanClock {
  let c = 0;
  let w = 0;
  let cc = 0;
  let wc = 0;
  return {
    measure,
    cpuMs: () => {
      if (cc % 2 === 1) c += cpu[(cc - 1) / 2] ?? 0;
      cc++;
      return c;
    },
    wallMs: () => {
      if (wc % 2 === 1) w += wall[(wc - 1) / 2] ?? 0;
      wc++;
      return w;
    },
  };
}

describe('the scan budget re-time', () => {
  let dir: string;
  let file: string;
  const scanner = new SecretScanner();

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-retime-'));
    file = path.join(dir, 'a.ts');
    fs.writeFileSync(file, `const k = "${KEY}";\n`);
  });
  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const run = (clock: ScanClock, hits?: IgnoreDirectiveHits) =>
    scanFileContent(scanner, file, undefined, undefined, { budgetMs: 5000, clock, ...(hits ? { ignoreHits: hits } : {}) });

  it('A13: 6000 then 100 is trusted, re-timed, and the first pass findings stand', async () => {
    const o = await run(scriptedClock('thread-cpu', [6000, 100]));
    expect(o.untrusted).toBeUndefined();
    expect(o.retimed).toBe(true);
    expect(o.matches.length).toBeGreaterThan(0);
  });

  it('A14: 6000 then 6000 is untrusted, twice', async () => {
    const o = await run(scriptedClock('thread-cpu', [6000, 6000]));
    expect(o.retimed).toBe(false);
    expect(o.untrusted).toEqual(
      expect.objectContaining({
        reason: 'scan exceeded the 5000 ms CPU budget twice (first 6000 ms, re-timed 6000 ms)',
        elapsedMs: 6000,
        firstMs: 6000,
        retimed: true,
        measure: 'thread-cpu',
        budgetMs: 5000,
      }),
    );
  });

  it('A15: a first pass over twice the budget is untrusted with the scanner called once', async () => {
    const spy = jest.spyOn(scanner, 'scanContent');
    const o = await run(scriptedClock('thread-cpu', [12000]));
    expect(spy).toHaveBeenCalledTimes(1);
    expect(o.untrusted?.retimed).toBe(false);
    expect(o.untrusted?.elapsedMs).toBe(12000);
  });

  it('A16: two passes that disagree are untrusted', async () => {
    const real = scanner.scanContent.bind(scanner);
    let calls = 0;
    jest.spyOn(scanner, 'scanContent').mockImplementation((text, o) => {
      const r = real(text, o);
      calls++;
      return calls === 2 ? [...r, { ...r[0], line: r[0].line + 1 }] : r;
    });
    const o = await run(scriptedClock('thread-cpu', [6000, 100]));
    expect(o.untrusted?.reason).toBe('scan results differed between two passes over the same content');
  });

  it('A17a: per-thread CPU decides, not wall time', async () => {
    const o = await run(scriptedClock('thread-cpu', [50], [10000]));
    expect(o.untrusted).toBeUndefined();
    expect(o.retimed).toBe(false);
  });

  it('A17b: the fallback takes the smaller of process CPU and wall time', async () => {
    const o = await run(scriptedClock('min-process-cpu-wall', [12000, 12000], [10000, 10000]));
    expect(o.untrusted).toEqual(
      expect.objectContaining({ measure: 'min-process-cpu-wall', elapsedMs: 10000, firstMs: 10000, wallMs: 10000 }),
    );
  });

  it('U13: the second pass inline tally is discarded', async () => {
    fs.writeFileSync(file, `const k = "${KEY}"; // vault-guard: ignore-line\nconst j = "${KEY}";\n`);
    const hits: IgnoreDirectiveHits = { count: 0, lines: [] };
    const o = await run(scriptedClock('thread-cpu', [6000, 100]), hits);
    expect(o.retimed).toBe(true);
    expect(hits.count).toBe(1);
  });

  it('no budget given: nothing is judged and nothing re-timed', async () => {
    const o = await scanFileContent(scanner, file, undefined, undefined, { clock: scriptedClock('thread-cpu', [60000]) });
    expect(o.untrusted).toBeUndefined();
    expect(o.retimed).toBe(false);
    expect(o.elapsedMs).toBe(60000);
  });
});
