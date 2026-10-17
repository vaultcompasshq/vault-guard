import * as fs from 'fs';

import type { ClockMeasure, ScanClock } from '@vaultcompass/vault-guard-core';
import { scanCommand } from '../../commands/scan';
import { AWS_KEY, capture, commitAll, initRepo, parse, tmpDir, write } from './git-fixture';
import { firstStderrLine } from './binary-fixtures';

/**
 * The CPU-time budget and its one re-time, through scanCommand (design
 * 2026-10-17, section 6.3, rows A13 to A17 and A20 (b)). The clock seam is
 * injected by wrapping core's scanFileContent; the scanner is the real one.
 */

const seam: { clock?: ScanClock; baselineThrows?: boolean } = {};

jest.mock('@vaultcompass/vault-guard-core', () => {
  const actual = jest.requireActual('@vaultcompass/vault-guard-core');
  return {
    ...actual,
    scanFileContent: (...args: unknown[]) => {
      const [s, f, e, src, o] = args as [unknown, string, unknown, unknown, Record<string, unknown> | undefined];
      // Only the subject file runs on the scripted clock.
      const clock = f.endsWith('subject.md') ? seam.clock : undefined;
      return actual.scanFileContent(s, f, e, src, { ...(o ?? {}), ...(clock ? { clock } : {}) });
    },
    applyBaseline: (...args: unknown[]) => {
      if (seam.baselineThrows) {
        const opts = args[2] as { readBytes: (f: string, source: string) => Buffer };
        // The seam the run uses for a header-only entry's file digest, asked
        // for bytes the scan did not keep: it throws "no bytes kept".
        opts.readBytes('/nowhere/subject.md', 'index');
      }
      return actual.applyBaseline(...args);
    },
  };
});

/** The n-th measured span advances CPU by cpu[n] and wall by wall[n]. */
function scripted(measure: ClockMeasure, cpu: number[], wall: number[] = cpu): ScanClock {
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

describe('the scan budget through scanCommand', () => {
  const originalCwd = process.cwd();
  const dirs: string[] = [];

  afterEach(() => {
    seam.clock = undefined;
    seam.baselineThrows = false;
    jest.restoreAllMocks();
    process.chdir(originalCwd);
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  /** A repository with src/ok.ts and docs/subject.md holding a low finding (below the default gate). */
  function repo(subject = 'Set `api_key = "aB3cD4eF5gH6iJ7kLmNoPqRs"` in your config.\n'): string {
    const d = tmpDir('vg-retime-');
    dirs.push(d);
    initRepo(d);
    write(d, 'src/ok.ts', 'export const ok = 1;\n');
    write(d, 'docs/subject.md', subject);
    commitAll(d, 'init');
    process.chdir(d);
    return d;
  }

  const scanContentSpy = async () => {
    const { SecretScanner } = await import('@vaultcompass/vault-guard-core');
    return jest.spyOn(SecretScanner.prototype, 'scanContent');
  };

  it('A13: 6000 then 100 is trusted on its findings, re-timed, no INCOMPLETE', async () => {
    repo();
    seam.clock = scripted('thread-cpu', [6000, 100]);
    const r = await capture(() => scanCommand('.', 'json'));
    const doc = parse(r.stdout);
    expect(r.code).toBe(0);
    expect(doc.run.scan_budget_retimed).toBe(1);
    expect(doc.run.unscannable_files).toBeUndefined();
    expect(r.err).not.toMatch(/INCOMPLETE/);
    expect(doc.results.find(x => x.file === 'docs/subject.md')).toBeDefined();
  });

  it('A13 (text): the re-time line', async () => {
    repo();
    seam.clock = scripted('thread-cpu', [6000, 100]);
    const r = await capture(() => scanCommand('.', 'text'));
    expect(r.log).toContain('Files re-timed after a slow first scan, then trusted: 1');
  });

  it('A14: 6000 then 6000 is exit 2, the reason says twice, first_ms 6000', async () => {
    repo();
    seam.clock = scripted('thread-cpu', [6000, 6000]);
    const r = await capture(() => scanCommand('.', 'json'));
    const doc = parse(r.stdout);
    expect(r.code).toBe(2);
    expect(r.err).toContain('scan exceeded the 5000 ms CPU budget twice (first 6000 ms, re-timed 6000 ms)');
    expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: docs\/subject\.md\. /);
    const diag = doc.diagnostics?.find(x => x.code === 'file.scan_timeout');
    expect(diag?.ctx).toEqual(
      expect.objectContaining({ file: 'docs/subject.md', elapsed_ms: 6000, first_ms: 6000, budget_ms: 5000, measure: 'thread-cpu', retimed: true }),
    );
  });

  it('A15: 12000 on the first pass is exit 2 with the scanner called once for that copy', async () => {
    repo();
    seam.clock = scripted('thread-cpu', [12000]);
    const spy = await scanContentSpy();
    const r = await capture(() => scanCommand('.', 'json'));
    expect(r.code).toBe(2);
    const calls = spy.mock.calls.filter(c => (c[1] as { filePath?: string } | undefined)?.filePath?.endsWith('subject.md'));
    expect(calls).toHaveLength(1);
  });

  it('A16: a second pass with one extra match is exit 2, results differed', async () => {
    repo();
    seam.clock = scripted('thread-cpu', [6000, 100]);
    const { SecretScanner } = await import('@vaultcompass/vault-guard-core');
    const original = SecretScanner.prototype.scanContent;
    let n = 0;
    jest.spyOn(SecretScanner.prototype, 'scanContent').mockImplementation(function (
      this: InstanceType<typeof SecretScanner>,
      ...a: Parameters<typeof original>
    ) {
      const out = original.apply(this, a);
      if (!a[1]?.filePath?.endsWith('subject.md')) return out;
      n++;
      return n === 2 ? [...out, { ...out[0], line: 99 }] : out;
    });
    const r = await capture(() => scanCommand('.', 'json'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('scan results differed between two passes over the same content');
  });

  it('A17a: per-thread, wall 10 s and CPU 50 ms: exit 0 on findings, no re-time', async () => {
    repo();
    seam.clock = scripted('thread-cpu', [50], [10000]);
    const r = await capture(() => scanCommand('.', 'json'));
    expect(r.code).toBe(0);
    expect(parse(r.stdout).run.scan_budget_retimed).toBe(0);
  });

  it('A17b: fallback, process CPU 12 s and wall 10 s twice: exit 2, elapsed_ms 10000, never 12000', async () => {
    repo();
    seam.clock = scripted('min-process-cpu-wall', [12000, 12000], [10000, 10000]);
    const r = await capture(() => scanCommand('.', 'json'));
    const doc = parse(r.stdout);
    expect(r.code).toBe(2);
    const diag = doc.diagnostics?.find(x => x.code === 'file.scan_timeout');
    expect(diag?.ctx).toEqual(expect.objectContaining({ measure: 'min-process-cpu-wall', elapsed_ms: 10000, first_ms: 10000 }));
  });

  it('U13: an ignore-line directive during a re-time is counted once', async () => {
    repo(`const k = "${AWS_KEY}"; // vault-guard: ignore-line\n`);
    seam.clock = scripted('thread-cpu', [6000, 100]);
    const r = await capture(() => scanCommand('.', 'json'));
    const doc = parse(r.stdout);
    expect(doc.run.scan_budget_retimed).toBe(1);
    expect(doc.run.inline_suppressed).toBe(1);
  });

  it('A20 (b): the baseline readBytes seam throwing after the scan prints no note, exit 2', async () => {
    repo();
    seam.baselineThrows = true;
    const r = await capture(() => scanCommand('.', 'json'));
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/Fatal error/);
    expect(r.err).toMatch(/no bytes kept/);
    expect(r.err).not.toMatch(/note: earlier vault-guard versions/);
  });
});
