import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';

/**
 * A file is scanned whole up to 32 MiB (the limit --staged already uses). There
 * is no line-by-line mode and no line-length cutoff, so a key at the top of a
 * large file, or on a very long line, is found. A file above the limit that the
 * config does not exclude is unscannable: exit 2, naming the file and the exact
 * exclude. A declared exclude is a counted skip.
 */
const FAKE_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');
const PEM = [
  ['-----BEGIN ', 'RSA PRIVATE', ' KEY-----'].join(''),
  'MIIEowIBAAKCAQEAtZ3mQpL8vXkR2hN7cWfT9yBd4uJ1aKsGx0eMoPq6RzVnYwHa',
  'c2gtcnNhAAAAAwEAAQAAAYEAtZ3mQpL8vXkR2hN7cWfT9yBd4uJ1aKsGx0eMoPq6',
  ['-----END ', 'RSA PRIVATE', ' KEY-----'].join(''),
  '',
].join('\n');
const MIB = 1024 * 1024;

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
  const origWarn = console.warn;
  const origOut = process.stdout.write;
  const origErrW = process.stderr.write;
  console.log = (...a: unknown[]): void => void logs.push(a.map(String).join(' '));
  console.error = (...a: unknown[]): void => void errs.push(a.map(String).join(' '));
  console.warn = (): void => undefined;
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
    console.warn = origWarn;
    process.stdout.write = origOut;
    process.stderr.write = origErrW;
  }
  return { code, log: logs.join('\n'), err: errs.join('\n'), stdout: outs.join('') };
}

describe('large files are scanned whole, and the limit is a refusal', () => {
  const originalCwd = process.cwd();
  let dir: string;

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-oversized-')));
    process.chdir(dir);
  });
  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('a PEM at the top of an 11 MiB text file is found', async () => {
    fs.writeFileSync(path.join(dir, 'big.txt'), PEM + 'filler line of ordinary text\n'.repeat(11 * MIB / 29));
    expect(fs.statSync(path.join(dir, 'big.txt')).size).toBeGreaterThan(11 * MIB);
    const r = await capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(1);
    expect(r.log).toMatch(/ssh-private-key/);
  });

  it('a secret on a line over 1 MiB inside such a file is found', async () => {
    const longLine = `${'x'.repeat(1.2 * MIB)} export const key = "${FAKE_KEY}"\n`;
    fs.writeFileSync(
      path.join(dir, 'long.txt'),
      'filler line of ordinary text\n'.repeat(11 * MIB / 29) + longLine,
    );
    const r = await capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(1);
    expect(r.log).toMatch(/anthropic/);
  });

  describe('when nothing else was scanned, the run still explains itself', () => {
    const writeOver = (): void => {
      fs.writeFileSync(path.join(dir, 'over.txt'), Buffer.alloc(33 * MIB, 0x61));
    };

    for (const format of ['text', 'json', 'sarif'] as const) {
      it(`${format}: an oversized explicit target`, async () => {
        writeOver();
        const r = await capture(() => scanCommand('over.txt', format, false));
        expect(r.code).toBe(2);
        expect(r.err).toContain('over.txt');
        expect(r.err).toMatch(/32 MiB/);
        expect(r.err).not.toMatch(/resolved to no files/);
        if (format === 'json') {
          const run = (JSON.parse(r.stdout) as { run: { unscannable?: Array<{ file: string }> } }).run;
          expect(run.unscannable?.[0].file).toBe('over.txt');
        } else if (format === 'sarif') {
          expect(() => JSON.parse(r.stdout)).not.toThrow();
        }
      });

      it(`${format}: a directory holding only an oversized file`, async () => {
        writeOver();
        const r = await capture(() => scanCommand('.', format, false));
        expect(r.code).toBe(2);
        expect(r.err).toContain('over.txt');
        expect(r.err).toContain('"/over.txt"');
        expect(r.err).not.toMatch(/resolved to no files/);
        if (format === 'json') {
          const run = (JSON.parse(r.stdout) as { run: { unscannable?: Array<{ file: string; exclude?: string }> } }).run;
          expect(run.unscannable).toEqual([{ file: 'over.txt', kind: 'too_large', exclude: '/over.txt' }]);
        } else if (format === 'sarif') {
          expect(() => JSON.parse(r.stdout)).not.toThrow();
        }
      });
    }
  });

  it('staged: the limit is on the raw blob size, so a UTF-16 file under 32 MiB on disk is scanned', async () => {
    // 24 MiB of UTF-16LE CJK text is about 36 MiB once decoded to UTF-8. The
    // limit is judged on the bytes in the index, like directory mode judges the
    // bytes on disk.
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: dir });
    const raw = Buffer.alloc(2 + 24 * MIB);
    raw[0] = 0xff;
    raw[1] = 0xfe;
    raw.fill(Buffer.from([0x22, 0x6f]), 2);
    fs.writeFileSync(path.join(dir, 'cjk.txt'), raw);
    execFileSync('git', ['add', 'cjk.txt'], { cwd: dir });
    const r = await capture(() => scanCommand('.', 'json', true));
    expect(r.err).not.toMatch(/INCOMPLETE/);
    expect(r.code).toBe(0);
  }, 120000);

  describe('staged: a blob above 32 MiB', () => {
    function stageHuge(): void {
      execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: dir });
      fs.writeFileSync(path.join(dir, 'huge.json'), Buffer.alloc(33 * MIB, 0x61));
      execFileSync('git', ['add', 'huge.json'], { cwd: dir });
    }

    it('exits 2 with the too-large wording and the exclude, not a raw git error', async () => {
      stageHuge();
      const r = await capture(() => scanCommand('.', 'json', true));
      expect(r.code).toBe(2);
      expect(r.err).toContain('huge.json');
      expect(r.err).toMatch(/over the 32 MiB scan limit/);
      expect(r.err).toContain('"/huge.json"');
      expect(r.err).not.toMatch(/ENOBUFS|Failed to read staged blob/);
      const run = (JSON.parse(r.stdout) as { run: { unscannable?: unknown } }).run;
      expect(run.unscannable).toEqual([{ file: 'huge.json', kind: 'too_large', exclude: '/huge.json' }]);
    }, 120000);

    it('sarif: the incomplete staged run is not a successful execution', async () => {
      stageHuge();
      const r = await capture(() => scanCommand('.', 'sarif', true));
      expect(r.code).toBe(2);
      const doc = JSON.parse(r.stdout) as { runs: Array<{ invocations?: Array<{ executionSuccessful: boolean }> }> };
      expect(doc.runs[0].invocations?.[0].executionSuccessful).toBe(false);
    }, 120000);
  });

  describe('above 32 MiB', () => {
    function writeHuge(): void {
      fs.writeFileSync(path.join(dir, 'huge.json'), Buffer.alloc(33 * MIB, 0x61));
      fs.writeFileSync(path.join(dir, 'ok.ts'), 'export const a = 1;\n');
    }

    it('an undeclared file exits 2 and names the file and the exclude', async () => {
      writeHuge();
      const r = await capture(() => scanCommand('.', 'text', false));
      expect(r.code).toBe(2);
      expect(r.err).toContain('huge.json');
      expect(r.err).toMatch(/32 MiB/);
      expect(r.err).toContain('"/huge.json"');
      expect(r.log).not.toMatch(/SUCCESS/);
    });

    it('the same file declared in ignore.paths exits 0 and is counted', async () => {
      writeHuge();
      fs.writeFileSync(
        path.join(dir, '.vault-guard.json'),
        JSON.stringify({ ignore: { paths: ['/huge.json'] } }),
      );
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(0);
      expect((JSON.parse(r.stdout) as { run: { config_ignored_files: number } }).run.config_ignored_files).toBe(1);
    });
  });
});
