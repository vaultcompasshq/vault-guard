import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DiagnosticBus } from '@vaultcompass/vault-guard-core';
import type { SecretScanner } from '@vaultcompass/vault-guard-core';
import { scanFilesAsync, scanFileListAsync, type UnreadableFile } from '../utils/scan-utils';

/**
 * Defense-in-depth per-file wall-clock budget.
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

  // A scanner whose per-file scan deliberately busy-waits past a small forced
  // budget. Cast through unknown: only the two scan entry points are exercised.
  const busyWait = (ms: number): void => {
    const end = Date.now() + ms;
    // eslint-disable-next-line no-empty
    while (Date.now() < end) {}
  };
  const slowScanner = {
    scan: () => {
      busyWait(60);
      return [];
    },
    scanContent: () => {
      busyWait(60);
      return [];
    },
  } as unknown as SecretScanner;

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
    });

    // Both files blew the 10ms budget (each busy-waits 60ms).
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
