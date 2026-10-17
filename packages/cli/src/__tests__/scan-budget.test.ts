import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DiagnosticBus, type ScanClock } from '@vaultcompass/vault-guard-core';
import type { SecretScanner } from '@vaultcompass/vault-guard-core';
import { scanFilesAsync, scanFileListAsync, type UnreadableFile } from '../utils/scan-utils';

/**
 * Defense-in-depth per-file CPU-time budget.
 *
 * The regex bounds are the specific fix for the two audited patterns; this
 * budget is the backstop for any future pattern (built-in or user `extra_`)
 * whose scan runs away. A file whose scan blows the budget is treated exactly
 * like an unreadable file: recorded in `unreadable` (so the staged path fails
 * closed via the existing stagedScanIncomplete -> exit 2 logic) and reported
 * via a `file.scan_timeout` error diagnostic, while a directory scan keeps
 * going.
 */
describe('per-file scan budget', () => {
  let dir: string;
  const originalCwd = process.cwd();

  // A scanner that finds nothing; the slowness comes from the clock seam.
  // Cast through unknown: only the two scan entry points are exercised.
  const slowScanner = {
    scan: () => [],
    scanContent: () => [],
  } as unknown as SecretScanner;
  // The budget is CPU time with one re-time (design 2026-10-17, section 6).
  // A busy-wait is descheduled on a loaded machine and its CPU time can stay
  // under the budget, so the slow cases make every measured span 60 ms
  // through the clock seam instead, over twice the 10 ms budget.
  const slowClock = (): ScanClock => {
    let t = 0;
    return { measure: 'thread-cpu', cpuMs: () => (t += 60), wallMs: () => t };
  };

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-budget-')));
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('directory scan: over-budget file is recorded and scanning keeps going', async () => {
    fs.writeFileSync(path.join(dir, 'a.txt'), 'hello\n');
    fs.writeFileSync(path.join(dir, 'b.txt'), 'world\n');
    const bus = new DiagnosticBus();
    const unreadable: UnreadableFile[] = [];

    const results = await scanFilesAsync([dir], slowScanner, {
      bus,
      unreadable,
      scanBudgetMs: 10,
      scanClock: slowClock(),
    });

    // Both files blew the 10ms budget (each measured span is 60ms on the seam).
    expect(unreadable.length).toBe(2);
    const diags = bus.drain();
    expect(diags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'file.scan_timeout', severity: 'error' }),
      ]),
    );
    // Directory scan returns normally rather than throwing.
    expect(Array.isArray(results)).toBe(true);
  });

  it('staged (file list) scan: over-budget file lands in unreadable', async () => {
    fs.writeFileSync(path.join(dir, 'staged.txt'), 'secret-ish\n');
    const bus = new DiagnosticBus();
    const unreadable: UnreadableFile[] = [];

    await scanFileListAsync([path.join(dir, 'staged.txt')], slowScanner, {
      bus,
      unreadable,
      scanBudgetMs: 10,
      scanClock: slowClock(),
      cwd: dir,
    });

    // scanCommand turns a non-empty `unreadable` on the staged path into
    // exit 2 (covered by staged-unreadable-fail-closed.test.ts); here we prove
    // the budget feeds that same list.
    expect(unreadable.length).toBe(1);
    expect(unreadable[0].reason).toMatch(/budget|timeout/i);
  });

  it('a fast scan under budget records nothing', async () => {
    fs.writeFileSync(path.join(dir, 'fast.txt'), 'nothing here\n');
    const fastScanner = {
      scan: () => [],
      scanContent: () => [],
    } as unknown as SecretScanner;
    const bus = new DiagnosticBus();
    const unreadable: UnreadableFile[] = [];

    await scanFilesAsync([dir], fastScanner, { bus, unreadable, scanBudgetMs: 5000 });

    expect(unreadable.length).toBe(0);
    expect(bus.drain()).toEqual([]);
  });
});
