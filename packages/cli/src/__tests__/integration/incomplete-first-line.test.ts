import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';
import { capture, commitAll, git, gitStub, initRepo, runCli, tmpDir, write } from './git-fixture';
import { firstStderrLine, lineIndex } from './binary-fixtures';

/**
 * On a run that cannot complete, the reason is the first thing said (design
 * 2026-10-17, sections 7 and 8): rows A18, A19, A20, A23, A23b, A26 and A27.
 * Each asserts on stderr after the cleaning the umbrella applies.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;
const LOW = 'Set `api_key = "aB3cD4eF5gH6iJ7kLmNoPqRs"` in your config.\n';
const BAD_PATTERN_CONFIG = JSON.stringify({ extra_patterns: [{ id: 'bad', regex: '(a+)+$', severity: 'low' }] });
const BIG = 33 * 1024 * 1024;

function setStderrTty(value: boolean | undefined): () => void {
  const had = Object.getOwnPropertyDescriptor(process.stderr, 'isTTY');
  Object.defineProperty(process.stderr, 'isTTY', { value, configurable: true, writable: true });
  return () => {
    if (had) Object.defineProperty(process.stderr, 'isTTY', had);
    else delete (process.stderr as { isTTY?: boolean }).isTTY;
  };
}

describe('INCOMPLETE is the first line on stderr', () => {
  const originalCwd = process.cwd();
  const dirs: string[] = [];
  let restoreTty: () => void = () => undefined;

  beforeEach(() => {
    restoreTty = setStderrTty(false);
  });

  afterEach(() => {
    restoreTty();
    process.chdir(originalCwd);
    for (const d of dirs.splice(0)) {
      try {
        for (const p of ['locked.txt', 'locked']) {
          if (fs.existsSync(path.join(d, p))) fs.chmodSync(path.join(d, p), 0o755);
        }
      } catch {
        // best effort
      }
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  function fresh(prefix = 'vg-first-'): string {
    const d = tmpDir(prefix);
    dirs.push(d);
    return d;
  }

  /** A18's tree: a low finding, an invalid baseline, a rejected extra_pattern, and (optionally) two unscannable files. */
  function a18Tree(unscannable: boolean): string {
    const d = fresh();
    initRepo(d);
    write(d, 'src/ok.ts', 'export const ok = 1;\n');
    write(d, 'docs/setup.md', LOW);
    write(d, '.vault-guard.json', BAD_PATTERN_CONFIG);
    write(d, '.vault-guard.baseline.json', '{not json');
    if (unscannable) write(d, 'big.txt', Buffer.alloc(BIG, 0x61));
    commitAll(d, 'init');
    if (unscannable) {
      write(d, 'locked.txt', 'secret-ish\n');
      fs.chmodSync(path.join(d, 'locked.txt'), 0o000);
    }
    return d;
  }

  describe('A18: the upgrade note is dropped on exit 2, and every advisory line follows INCOMPLETE', () => {
    for (const format of ['text', 'json', 'sarif'] as const) {
      itPosix(
        `${format}: exit 2, no note, INCOMPLETE first`,
        async () => {
          const d = a18Tree(true);
          process.chdir(d);
          const r = await capture(() => scanCommand('.', format));
          expect(r.code).toBe(2);
          expect(r.err).not.toMatch(/note: earlier vault-guard versions/);
          expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: big\.txt\. /);
          const inc = lineIndex(r.err, /INCOMPLETE:/);
          if (format === 'text') {
            for (const re of [/extra_pattern rejected:/, /Error scanning file:/, /Baseline file invalid/, /warning\(s\)/]) {
              const at = lineIndex(r.err, re);
              expect(at).toBeGreaterThan(inc);
            }
          } else {
            expect(() => JSON.parse(r.stdout)).not.toThrow();
          }
        },
        120_000,
      );
    }
  });

  describe('A19: the control, with nothing unscannable', () => {
    for (const format of ['text', 'json', 'sarif'] as const) {
      it(`${format}: the note is printed and the run exits 0`, async () => {
        const d = a18Tree(false);
        process.chdir(d);
        const r = await capture(() => scanCommand('.', format));
        expect(r.code).toBe(0);
        expect(r.err).toMatch(/note: earlier vault-guard versions/);
      });
    }
  });

  describe('A20 (a): an exit 2 reached after the scan with findings in hand prints no note', () => {
    itPosix('--trust-base with listTrackedIgnoredFiles failing (subprocess)', () => {
      const d = fresh();
      initRepo(d);
      write(d, 'src/ok.ts', 'export const ok = 1;\n');
      commitAll(d, 'base');
      git(d, ['tag', 'base']);
      write(d, 'docs/setup.md', LOW);
      commitAll(d, 'head');
      const stubDir = fresh('vg-first-stub-');
      const bin = gitStub(stubDir, path.join(stubDir, 'log.jsonl'), { fail: 'ls-files', failArg: '--ignored' });
      const r = runCli(['scan', '.', '--format', 'json', '--trust-base', 'base'], d, {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
      });
      expect(r.code).toBe(2);
      expect(r.stderr).toMatch(/Git error/);
      expect(r.stderr).not.toMatch(/note: earlier vault-guard versions/);
    });
  });

  describe('A23: progress on a pipe', () => {
    itPosix('a text run over 12 files with one unreadable: no carriage return, INCOMPLETE first (subprocess)', () => {
      const d = fresh();
      initRepo(d);
      for (let i = 0; i < 12; i++) write(d, `src/f${i}.ts`, `export const v${i} = ${i};\n`);
      commitAll(d, 'init');
      write(d, 'locked.txt', 'x\n');
      fs.chmodSync(path.join(d, 'locked.txt'), 0o000);
      const r = runCli(['scan', '.'], d);
      expect(r.code).toBe(2);
      expect(r.stderr).not.toContain('\r');
      expect(firstStderrLine(r.stderr)).toMatch(/^INCOMPLETE: First: locked\.txt\. /);
    });
  });

  describe('A23b: progress on a terminal', () => {
    itPosix('progress is drawn, and its line ends with a newline before INCOMPLETE', async () => {
      restoreTty();
      restoreTty = setStderrTty(true);
      const d = fresh();
      initRepo(d);
      for (let i = 0; i < 12; i++) write(d, `src/f${i}.ts`, `export const v${i} = ${i};\n`);
      commitAll(d, 'init');
      write(d, 'locked.txt', 'x\n');
      fs.chmodSync(path.join(d, 'locked.txt'), 0o000);
      process.chdir(d);
      let raw = '';
      const origErr = console.error;
      const origLog = console.log;
      const origWrite = process.stderr.write;
      const origOut = process.stdout.write;
      console.error = (...a: unknown[]): void => {
        raw += `${a.map(String).join(' ')}\n`;
      };
      console.log = (): void => undefined;
      process.stderr.write = ((s: string | Uint8Array): boolean => {
        raw += String(s);
        return true;
      }) as typeof process.stderr.write;
      process.stdout.write = (() => true) as typeof process.stdout.write;
      let code: number;
      try {
        code = await scanCommand('.', 'text');
      } finally {
        console.error = origErr;
        console.log = origLog;
        process.stderr.write = origWrite;
        process.stdout.write = origOut;
      }
      expect(code).toBe(2);
      expect(raw).toMatch(/Scanning\.\.\. 100%/);
      const between = raw.slice(raw.lastIndexOf('Scanning...'), raw.indexOf('INCOMPLETE'));
      expect(between).toContain('\n');
    });
  });

  describe('A26: walk-time warnings outside git follow the INCOMPLETE block', () => {
    itPosix('an unreadable subdirectory and a 33 MiB text file', async () => {
      const d = fresh('vg-first-walk-');
      expect(fs.existsSync(path.join(d, '.git'))).toBe(false);
      write(d, 'locked/inner.txt', 'x\n');
      fs.chmodSync(path.join(d, 'locked'), 0o000);
      write(d, 'big.txt', Buffer.alloc(BIG, 0x61));
      write(d, 'ok.ts', 'export const ok = 1;\n');
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.code).toBe(2);
      expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: big\.txt\. /);
      expect(lineIndex(r.err, /Warning: Cannot read directory/)).toBeGreaterThan(lineIndex(r.err, /INCOMPLETE:/));
    }, 120_000);
  });

  describe('A27: path-not-found and invalid-path lines follow the INCOMPLETE block', () => {
    it('scan a.ts missing.ts', async () => {
      const d = fresh();
      write(d, 'a.ts', 'export const a = 1;\n');
      process.chdir(d);
      const r = await capture(() => scanCommand(['a.ts', 'missing.ts'], 'text'));
      expect(r.code).toBe(2);
      expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: missing\.ts\. /);
      expect(lineIndex(r.err, /Error: Path not found/)).toBeGreaterThan(lineIndex(r.err, /INCOMPLETE:/));
    });

    itPosix('scan a.ts fifo', async () => {
      const d = fresh();
      write(d, 'a.ts', 'export const a = 1;\n');
      expect(spawnSync('mkfifo', [path.join(d, 'fifo')]).status).toBe(0);
      process.chdir(d);
      const r = await capture(() => scanCommand(['a.ts', 'fifo'], 'text'));
      expect(r.code).toBe(2);
      expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: fifo\. /);
      expect(lineIndex(r.err, /Error: Invalid path/)).toBeGreaterThan(lineIndex(r.err, /INCOMPLETE:/));
    });
  });
});
