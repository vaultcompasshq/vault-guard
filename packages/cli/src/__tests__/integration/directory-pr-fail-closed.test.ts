import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';

/**
 * Directory mode and pull-request mode fail closed, like --staged.
 *
 * Until 1.9.1 a directory or pull-request run over an unreadable file, an
 * over-budget file or one of several missing targets exited 0 and printed
 * "No secrets found" beside a count nobody reads. A gate that cannot say it
 * looked at everything says exit 2 instead, names what it could not look at,
 * and says how to declare the exclusion on purpose. A file excluded through
 * the config's own `ignore` list is a DECLARED skip: exit 0, counted, reported.
 *
 * Under `integration/` because the unreadable cases turn on chmod 0o000, which
 * Windows does not honour.
 */
const itPosix = process.platform === 'win32' ? it.skip : it;

interface Captured {
  code: number;
  log: string;
  err: string;
  stdout: string;
}

async function capture(fn: () => Promise<number>): Promise<Captured> {
  const logs: string[] = [];
  const errs: string[] = [];
  const outs: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const origOut = process.stdout.write;
  const origErrW = process.stderr.write;
  console.log = (...a: unknown[]): boolean => {
    logs.push(a.map(String).join(' '));
    return true;
  };
  console.error = (...a: unknown[]): boolean => {
    errs.push(a.map(String).join(' '));
    return true;
  };
  process.stdout.write = ((s: string | Uint8Array): boolean => {
    outs.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((): boolean => true) as typeof process.stderr.write;
  let code: number;
  try {
    code = await fn();
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.stdout.write = origOut;
    process.stderr.write = origErrW;
  }
  return { code, log: logs.join('\n'), err: errs.join('\n'), stdout: outs.join('') };
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

interface RunJson {
  run: Record<string, number | string | undefined>;
}

describe('directory and pull-request mode fail closed', () => {
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const originalCwd = process.cwd();
  let dir: string;

  function write(rel: string, text: string): void {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
  }

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-dir-closed-')));
    process.chdir(dir);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.chdir(originalCwd);
    try {
      fs.chmodSync(path.join(dir, 'locked.txt'), 0o644);
    } catch {
      /* not created in every case */
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /** Every Date.now() call jumps forward, so any timed section reads as long. */
  function makeEveryScanSlow(): void {
    let t = 1_700_000_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => {
      t += 6000;
      return t;
    });
  }

  describe('several targets, one missing', () => {
    it('exits 2 and names the missing path', async () => {
      write('a.ts', 'export const a = 1;\n');
      const r = await capture(() => scanCommand(['a.ts', 'missing.ts'], 'text', false));
      expect(r.code).toBe(2);
      expect(r.err).toContain('missing.ts');
      expect(r.log).not.toMatch(/SUCCESS/);
    });

    it('JSON output still carries the document and exits 2', async () => {
      write('a.ts', 'export const a = 1;\n');
      const r = await capture(() => scanCommand(['a.ts', 'missing.ts'], 'json', false));
      expect(r.code).toBe(2);
      expect((JSON.parse(r.stdout) as RunJson).run.unscannable_files).toBe(1);
    });
  });

  describe('a file that cannot be read', () => {
    itPosix('directory mode exits 2, names the file, and says what to do', async () => {
      if (isRoot) return;
      write('clean.ts', 'export const x = 1;\n');
      write('locked.txt', 'hello\n');
      fs.chmodSync(path.join(dir, 'locked.txt'), 0o000);
      const r = await capture(() => scanCommand('.', 'text', false));
      expect(r.code).toBe(2);
      expect(r.err).toContain('locked.txt');
      expect(r.err).toContain('ignore.paths');
      expect(r.err).toContain('"/locked.txt"');
      expect(r.log).not.toMatch(/SUCCESS/);
    });

    itPosix('the same file declared in the config ignore list is a counted skip, exit 0', async () => {
      if (isRoot) return;
      write('.vault-guard.json', JSON.stringify({ ignore: { paths: ['/locked.txt'] } }));
      write('clean.ts', 'export const x = 1;\n');
      write('locked.txt', 'hello\n');
      fs.chmodSync(path.join(dir, 'locked.txt'), 0o000);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect((JSON.parse(r.stdout) as RunJson).run.config_ignored_files).toBe(1);
    });

    itPosix('pull-request mode exits 2 over an unreadable tracked file', async () => {
      if (isRoot) return;
      git(dir, ['init', '-q', '-b', 'main']);
      git(dir, ['config', 'user.email', 'test@example.invalid']);
      git(dir, ['config', 'user.name', 'Test']);
      git(dir, ['config', 'commit.gpgsign', 'false']);
      write('.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
      write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [] }));
      write('src/app.ts', 'export const greeting = "hello";\n');
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'base']);
      git(dir, ['branch', 'base-snapshot']);
      git(dir, ['checkout', '-q', '-b', 'feature']);
      write('locked.txt', 'hello\n');
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'head']);
      fs.chmodSync(path.join(dir, 'locked.txt'), 0o000);

      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('locked.txt');
      expect(r.err).toMatch(/base/i);
    });
  });

  describe('pull-request mode: a tracked file that cannot be statted', () => {
    function seedPr(): void {
      git(dir, ['init', '-q', '-b', 'main']);
      git(dir, ['config', 'user.email', 'test@example.invalid']);
      git(dir, ['config', 'user.name', 'Test']);
      git(dir, ['config', 'commit.gpgsign', 'false']);
      write('.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
      write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [] }));
      write('src/app.ts', 'export const greeting = "hello";\n');
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'base']);
      git(dir, ['branch', 'base-snapshot']);
      git(dir, ['checkout', '-q', '-b', 'feature']);
      write('src/locked/creds.txt', 'hello\n');
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'head']);
    }

    afterEach(() => {
      try {
        fs.chmodSync(path.join(dir, 'src', 'locked'), 0o755);
      } catch {
        /* not created in every case */
      }
    });

    itPosix('a file under a directory that cannot be entered exits 2 and is named', async () => {
      if (isRoot) return;
      seedPr();
      fs.chmodSync(path.join(dir, 'src', 'locked'), 0o000);
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('creds.txt');
      expect(r.err).toContain('"/src/locked/creds.txt"');
      expect(r.log).not.toMatch(/SUCCESS/);
    });

    it('a head-tree file that is missing on disk exits 2 and is named', async () => {
      seedPr();
      fs.rmSync(path.join(dir, 'src', 'locked', 'creds.txt'));
      const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('creds.txt');
    });

    it('the same file declared in the base ignore list is a counted skip', async () => {
      seedPr();
      git(dir, ['checkout', '-q', 'main']);
      write(
        '.vault-guard.json',
        JSON.stringify({ fail_on: 'medium', ignore: { paths: ['/src/locked/creds.txt'] } }),
      );
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'declare']);
      git(dir, ['checkout', '-q', 'feature']);
      git(dir, ['branch', '-f', 'base-snapshot', 'main']);
      fs.rmSync(path.join(dir, 'src', 'locked', 'creds.txt'), { force: true });
      const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(0);
      expect((JSON.parse(r.stdout) as RunJson).run.config_ignored_files).toBe(1);
    });
  });

  describe('a scan that blows the budget', () => {
    it('directory mode exits 2 and names the file and the exclude to add', async () => {
      write('a.txt', 'hello\n');
      makeEveryScanSlow();
      const r = await capture(() => scanCommand('.', 'text', false));
      expect(r.code).toBe(2);
      expect(r.err).toContain('a.txt');
      expect(r.err).toMatch(/budget/);
      expect(r.err).toContain('"/a.txt"');
      expect(r.log).not.toMatch(/SUCCESS/);
    });

    it('a declared exclude is a skip, exit 0, counted', async () => {
      write('.vault-guard.json', JSON.stringify({ ignore: { paths: ['/big.json'] } }));
      write('big.json', '{"a": 1}\n');
      write('ok.ts', 'export const a = 1;\n');
      const slow = jest.spyOn(Date, 'now');
      // Only the scan of ok.ts is timed; the excluded file must never be scanned.
      let t = 1_700_000_000_000;
      slow.mockImplementation(() => t++);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      const run = (JSON.parse(r.stdout) as RunJson).run;
      expect(run.config_ignored_files).toBe(1);
    });

    it('text mode reports the declared skip', async () => {
      write('.vault-guard.json', JSON.stringify({ ignore: { paths: ['/big.json'] } }));
      write('big.json', '{"a": 1}\n');
      write('ok.ts', 'export const a = 1;\n');
      const r = await capture(() => scanCommand('.', 'text', false));
      expect(r.code).toBe(0);
      expect(r.log).toMatch(/Excluded by config ignore: 1/);
    });
  });

  describe('exit 2 explains itself in every output format', () => {
    for (const format of ['json', 'sarif'] as const) {
      it(`${format}: stderr names the file, the reason and the exclude`, async () => {
        write('a.txt', 'hello\n');
        makeEveryScanSlow();
        const r = await capture(() => scanCommand('.', format, false));
        expect(r.code).toBe(2);
        expect(r.err).toMatch(/INCOMPLETE/);
        expect(r.err).toContain('a.txt');
        expect(r.err).toMatch(/budget/);
        expect(r.err).toContain('to exclude it on purpose, add "/a.txt" to "ignore.paths"');
        // stdout stays a parseable document
        expect(() => JSON.parse(r.stdout)).not.toThrow();
      });
    }

    it('json: run.unscannable lists file, kind and exclude', async () => {
      write('a.txt', 'hello\n');
      makeEveryScanSlow();
      const r = await capture(() => scanCommand('.', 'json', false));
      const run = (JSON.parse(r.stdout) as { run: { unscannable?: unknown } }).run;
      expect(run.unscannable).toEqual([
        { file: 'a.txt', kind: 'scan_budget', exclude: '/a.txt' },
      ]);
    });

    it('a missing target in json has no exclude, and says to check the path', async () => {
      write('a.ts', 'export const a = 1;\n');
      const r = await capture(() => scanCommand(['a.ts', 'missing.ts'], 'json', false));
      expect(r.code).toBe(2);
      expect(r.err).toContain('missing.ts');
      expect(r.err).toMatch(/check the path/);
      const run = (JSON.parse(r.stdout) as { run: { unscannable?: Array<{ file: string; kind: string }> } }).run;
      expect(run.unscannable).toEqual([{ file: 'missing.ts', kind: 'read_error' }]);
    });

    itPosix('pull-request mode json: the base-ref note is on stderr', async () => {
      if (isRoot) return;
      git(dir, ['init', '-q', '-b', 'main']);
      git(dir, ['config', 'user.email', 'test@example.invalid']);
      git(dir, ['config', 'user.name', 'Test']);
      git(dir, ['config', 'commit.gpgsign', 'false']);
      write('.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
      write('.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [] }));
      write('src/app.ts', 'export const greeting = "hello";\n');
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'base']);
      git(dir, ['branch', 'base-snapshot']);
      git(dir, ['checkout', '-q', '-b', 'feature']);
      write('locked.txt', 'hello\n');
      git(dir, ['add', '-A']);
      git(dir, ['commit', '-q', '-m', 'head']);
      fs.chmodSync(path.join(dir, 'locked.txt'), 0o000);
      const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
      expect(r.code).toBe(2);
      expect(r.err).toContain('base ref "base-snapshot"');
    });
  });

  describe('binary files are skipped, and the skip is counted', () => {
    it('a binary extension the walk lets through is counted in the run', async () => {
      write('ok.ts', 'export const a = 1;\n');
      fs.writeFileSync(path.join(dir, 'blob.bin'), Buffer.alloc(2048, 7));
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect((JSON.parse(r.stdout) as RunJson).run.binary_files_skipped).toBe(1);
    });

    it('a PNG removed by the walk filter is counted as type-filtered, before any budget', async () => {
      write('ok.ts', 'export const a = 1;\n');
      fs.writeFileSync(path.join(dir, 'logo.png'), Buffer.alloc(1_300_000, 9));
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect((JSON.parse(r.stdout) as RunJson).run.type_filtered_files).toBe(1);
    });

    it('text mode states both counts', async () => {
      write('ok.ts', 'export const a = 1;\n');
      fs.writeFileSync(path.join(dir, 'blob.bin'), Buffer.alloc(2048, 7));
      const r = await capture(() => scanCommand('.', 'text', false));
      expect(r.log).toMatch(/Binary files skipped: 1/);
    });
  });
});
