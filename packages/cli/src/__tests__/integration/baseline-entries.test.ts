import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';

/**
 * The baseline reader's `entries` list (design 2026-10-11, section 3).
 *
 * Entries here are built from the scan's own JSON output (content_fingerprint,
 * severity) rather than by the writer, so these tests pin the reader alone.
 * Every case that matters for pull requests runs twice: in plain mode, and
 * under --trust-base with the baseline committed on the base, because the
 * base-ref load is a separate code path.
 */

const KEY_A = ['sk-ant-', 'api03-', 'Kq7mZr2xVb9nTd4wHs6yLc3p', 'Jf8gRu5eNa1vBt0iOy7kPd2s', 'Xw4hEj6uCi3q'].join('');
// Same length as KEY_A, different value.
const KEY_B = ['sk-ant-', 'api03-', 'Kq7mZr2xVb9nTd4wHs6yLc3p', 'Jf8gRu5eNa1vBt0iOy7kPd2s', 'Xw4hEj6uCi3r'].join('');
const KEY_C = ['sk-ant-', 'api03-', 'Pz3nQw8eRt5yUi1oPa9sDf2g', 'Hj7kLz4xCv6bNm0qWe3rTy8u', 'Io5pAs1dFg9h'].join('');

const PEM = [
  ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join(''),
  'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn',
  'Zq8mW2xRb7nTd4vHs6yLc3pJf8gRu5eNa1vBt0iOy7kPd2sXw4hEj6uCi3qAbCd',
  ['-----END RSA PRIV', 'ATE KEY-----'].join(''),
  '',
].join('\n');

interface Captured {
  code: number;
  stdout: string;
  err: string;
}

async function capture(fn: () => Promise<number>): Promise<Captured> {
  const errs: string[] = [];
  const outs: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const origOut = process.stdout.write;
  const origErrW = process.stderr.write;
  console.log = (): boolean => true;
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
  return { code, stdout: outs.join(''), err: errs.join('\n') };
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

interface JsonMatch {
  type: string;
  severity: string;
  line: number;
  fingerprint: string;
  content_fingerprint?: string;
}
interface JsonDoc {
  run: Record<string, number | string | undefined>;
  results: Array<{ file: string; matches: JsonMatch[] }>;
  diagnostics?: Array<{ code: string; ctx: Record<string, unknown> }>;
}

describe('baseline entries', () => {
  const originalCwd = process.cwd();
  let dir: string;

  function write(rel: string, text: string): void {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
  }

  function commit(message: string): void {
    git(dir, ['add', '-A', '-f']);
    git(dir, ['commit', '-q', '-m', message]);
  }

  async function scanJson(trustBase?: string): Promise<{ code: number; doc: JsonDoc }> {
    const r = await capture(() => scanCommand('.', 'json', false, undefined, trustBase));
    return { code: r.code, doc: JSON.parse(r.stdout) as JsonDoc };
  }

  /** One content entry per value-bearing match, count 1, at the match's own severity. */
  function entriesFrom(doc: JsonDoc, filter: (m: JsonMatch) => boolean = () => true): unknown[] {
    return doc.results.flatMap(r =>
      r.matches.filter(filter).map(m => ({
        fingerprint: m.content_fingerprint,
        rule: m.type,
        file: r.file,
        line: m.line,
        severity: m.severity,
        count: 1,
      })),
    );
  }

  function writeBaseline(doc: unknown): void {
    write('.vault-guard.baseline.json', JSON.stringify(doc, null, 2));
  }

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-baseline-entries-')));
    git(dir, ['init', '-q', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.invalid']);
    git(dir, ['config', 'user.name', 'Test']);
    git(dir, ['config', 'commit.gpgsign', 'false']);
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  describe('T12: a content entry follows the value, not the line', () => {
    async function seed(): Promise<void> {
      write('src/a.ts', `export const k = "${KEY_A}";\n`);
      const { doc } = await scanJson();
      writeBaseline({ version: 1, fingerprints: [], entries: entriesFrom(doc) });
      commit('base with baseline');
      git(dir, ['branch', 'base-snapshot']);
    }

    it('plain: three lines inserted above keep it suppressed', async () => {
      await seed();
      write('src/a.ts', `// one\n// two\n// three\nexport const k = "${KEY_A}";\n`);
      const { code, doc } = await scanJson();
      expect(code).toBe(0);
      expect(doc.run.baseline_suppressed).toBe(1);
    });

    it('plain: a different value of the same length at the same position blocks', async () => {
      await seed();
      write('src/a.ts', `export const k = "${KEY_B}";\n`);
      const { code } = await scanJson();
      expect(code).toBe(1);
    });

    it('--trust-base: lines inserted above keep it suppressed by the base baseline', async () => {
      await seed();
      write('src/a.ts', `// one\n// two\n// three\nexport const k = "${KEY_A}";\n`);
      commit('head moves the line');
      const { code, doc } = await scanJson('base-snapshot');
      expect(code).toBe(0);
      expect(doc.run.baseline_suppressed).toBe(1);
      expect(doc.run.baseline_entries).toBe(1);
    });

    it('--trust-base: a different value at the same position blocks', async () => {
      await seed();
      write('src/a.ts', `export const k = "${KEY_B}";\n`);
      commit('head swaps the value');
      const { code } = await scanJson('base-snapshot');
      expect(code).toBe(1);
    });
  });

  it('T13: a duplicated baselined line: one suppressed, one blocking', async () => {
    write('src/a.ts', `export const k = "${KEY_A}";\n`);
    const { doc: before } = await scanJson();
    writeBaseline({ version: 1, fingerprints: [], entries: entriesFrom(before) });
    write('src/a.ts', `export const k = "${KEY_A}";\nexport const k2 = "${KEY_A}";\n`);
    const { code, doc } = await scanJson();
    expect(code).toBe(1);
    expect(doc.run.blocking_matches).toBe(1);
    expect(doc.run.baseline_suppressed).toBe(1);
  });

  describe('T14: entries, when present, are the only list', () => {
    async function seed(): Promise<{ posA: string; posC: string; entriesC: unknown[] }> {
      write('src/a.ts', `export const a = "${KEY_A}";\nexport const c = "${KEY_C}";\n`);
      const { doc } = await scanJson();
      const ms = doc.results[0].matches;
      const a = ms.find(m => m.line === 1) as JsonMatch;
      const c = ms.find(m => m.line === 2) as JsonMatch;
      return {
        posA: a.fingerprint,
        posC: c.fingerprint,
        entriesC: entriesFrom(doc, m => m.line === 2),
      };
    }

    it('plain: a finding in fingerprints but not in entries blocks', async () => {
      const { posA, posC, entriesC } = await seed();
      writeBaseline({ version: 1, fingerprints: [posA, posC], entries: entriesC });
      const { code, doc } = await scanJson();
      expect(code).toBe(1);
      expect(doc.run.blocking_matches).toBe(1);
      expect(doc.run.baseline_suppressed).toBe(1);
    });

    it('plain: a positional-only file still suppresses', async () => {
      const { posA, posC } = await seed();
      writeBaseline({ version: 1, fingerprints: [posA, posC] });
      const { code, doc } = await scanJson();
      expect(code).toBe(0);
      expect(doc.run.baseline_suppressed).toBe(2);
      expect(doc.run.baseline_entries).toBe(0);
    });

    it('--trust-base: a finding in fingerprints but not in entries blocks', async () => {
      const { posA, posC, entriesC } = await seed();
      writeBaseline({ version: 1, fingerprints: [posA, posC], entries: entriesC });
      commit('base');
      git(dir, ['branch', 'base-snapshot']);
      write('README.md', 'head change\n');
      commit('head');
      const { code, doc } = await scanJson('base-snapshot');
      expect(code).toBe(1);
      expect(doc.run.blocking_matches).toBe(1);
    });

    it('--trust-base: a positional-only file on the base still suppresses', async () => {
      const { posA, posC } = await seed();
      writeBaseline({ version: 1, fingerprints: [posA, posC] });
      commit('base');
      git(dir, ['branch', 'base-snapshot']);
      write('README.md', 'head change\n');
      commit('head');
      const { code } = await scanJson('base-snapshot');
      expect(code).toBe(0);
    });
  });

  it('T15: an entry accepted at medium does not hide a finding now raised to high', async () => {
    write('.vault-guard.json', JSON.stringify({ severity_overrides: { anthropic: 'high' } }));
    write('src/a.ts', `export const k = "${KEY_A}";\n`);
    const { doc } = await scanJson();
    const entries = (entriesFrom(doc) as Array<Record<string, unknown>>).map(e => ({
      ...e,
      severity: 'medium',
    }));
    writeBaseline({ version: 1, fingerprints: [], entries });
    const { code, doc: after } = await scanJson();
    expect(code).toBe(1);
    expect(after.run.baseline_suppressed ?? 0).toBe(0);
  });

  describe('T21: a malformed entries list suppresses nothing, and says so', () => {
    it('T21a: entries that is not an array never falls back to fingerprints', async () => {
      write('src/a.ts', `export const k = "${KEY_A}";\n`);
      const { doc } = await scanJson();
      const pos = doc.results[0].matches[0].fingerprint;
      writeBaseline({ version: 1, fingerprints: [pos], entries: 'oops' });
      const { code, doc: after } = await scanJson();
      expect(code).toBe(1);
      expect(after.diagnostics?.some(d => d.code === 'baseline.invalid')).toBe(true);
    });

    it('T21b: an entry with an unknown severity suppresses nothing while its sibling works', async () => {
      // Both findings low and the gate at low, so an unknown severity read as
      // "low" would suppress the first one.
      write(
        '.vault-guard.json',
        JSON.stringify({ fail_on: 'low', severity_overrides: { anthropic: 'low' } }),
      );
      write('src/a.ts', `export const a = "${KEY_A}";\nexport const c = "${KEY_C}";\n`);
      const { doc } = await scanJson();
      const entries = (entriesFrom(doc) as Array<Record<string, unknown>>).map(e =>
        e.line === 1 ? { ...e, severity: 'urgent' } : e,
      );
      writeBaseline({ version: 1, fingerprints: [], entries });
      const { code, doc: after } = await scanJson();
      expect(code).toBe(1);
      expect(after.run.blocking_matches).toBe(1);
      expect(after.run.baseline_suppressed).toBe(1);
      const invalid = after.diagnostics?.filter(d => d.code === 'baseline.invalid') ?? [];
      expect(invalid.length).toBeGreaterThan(0);
      expect(JSON.stringify(invalid)).toContain('urgent');
    });

    it('a header-only entry without file_digest suppresses nothing', async () => {
      write('keys/id.pem', PEM);
      const { doc } = await scanJson();
      const pem = doc.results[0].matches.find(m => m.type === 'ssh-private-key') as JsonMatch;
      expect(pem.content_fingerprint).toBeUndefined();
      // The entry carries the right positional key but no file digest, which
      // would match if the reader picked the kind from the entry's shape.
      writeBaseline({
        version: 1,
        fingerprints: [],
        entries: [
          { fingerprint: pem.fingerprint, rule: 'ssh-private-key', file: 'keys/id.pem', line: 1, severity: 'critical', count: 1 },
        ],
      });
      const { code, doc: after } = await scanJson();
      expect(code).toBe(1);
      expect(after.run.baseline_suppressed ?? 0).toBe(0);
    });
  });
});
