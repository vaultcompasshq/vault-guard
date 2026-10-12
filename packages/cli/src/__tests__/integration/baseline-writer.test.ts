import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { baselineCommand } from '../../commands/baseline';
import { scanCommand } from '../../commands/scan';

/**
 * `vault-guard baseline [path] [--write] [--include-critical]` (design
 * 2026-10-11, section 3.4): the only thing that writes the baseline file.
 */

const CRITICAL_KEY = ['sk-ant-', 'api03-', 'Kq7mZr2xVb9nTd4wHs6yLc3p', 'Jf8gRu5eNa1vBt0iOy7kPd2s', 'Xw4hEj6uCi3q'].join('');

/** A JWT that is not one of the published samples: rule jwt-token, severity high. */
function jwt(sig: string): string {
  return ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', 'eyJzdWIiOiJ1c3ItODgyMSIsInJvbGUiOiJvcHMifQ', sig].join('.');
}
const HIGH_A = jwt('Qm9vZ2llV29vZ2llQmFuZ2xlczEyMzQ1Njc4OTBhYmM');
const HIGH_B = jwt('Wn1xR4tY7uI0oP3aS6dF9gH2jK5lZ8xC1vB4nM7qWe');

const PEM_HEADER = ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join('');
const PEM_FOOTER = ['-----END RSA PRIV', 'ATE KEY-----'].join('');
function pem(body: string, eol = '\n'): string {
  return [PEM_HEADER, body, PEM_FOOTER, ''].join(eol);
}
const BODY_1 = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn';
const BODY_2 = 'MIIEpAIBAAKCAQEA7Zq8mW2xRb7nTd4vHs6yLc3pJf8gRu5eNa1vBt0iOy7kPd2s';

function gcp(privateKeyBody: string): string {
  return JSON.stringify(
    {
      type: 'service_account',
      project_id: 'demo-project-8821',
      private_key_id: '5f3c2a1b9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b',
      private_key: `${PEM_HEADER.replace('RSA ', '')}\n${privateKeyBody}\n${PEM_FOOTER.replace('RSA ', '')}\n`,
      client_email: 'svc@demo-project-8821.iam.gserviceaccount.com',
    },
    null,
    2,
  );
}

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

const itPosix = process.platform === 'win32' ? it.skip : it;
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;

interface BaselineDoc {
  version: number;
  fingerprints: string[];
  entries: Array<{
    fingerprint: string;
    rule: string;
    file: string;
    line: number;
    severity: string;
    count: number;
    file_digest?: string;
  }>;
}

describe('vault-guard baseline', () => {
  const originalCwd = process.cwd();
  let dir: string;
  const baselinePath = (): string => path.join(dir, '.vault-guard.baseline.json');
  const readBaseline = (): BaselineDoc =>
    JSON.parse(fs.readFileSync(baselinePath(), 'utf-8')) as BaselineDoc;

  function write(rel: string, text: string): void {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, text);
  }

  function commit(message: string): void {
    git(dir, ['add', '-A', '-f']);
    git(dir, ['commit', '-q', '-m', message]);
  }

  async function scanJson(trustBase?: string): Promise<{ code: number; doc: { run: Record<string, unknown>; results: Array<{ file: string; matches: Array<{ type: string; fingerprint: string }> }> } }> {
    const r = await capture(() => scanCommand('.', 'json', false, undefined, trustBase));
    return { code: r.code, doc: JSON.parse(r.stdout) };
  }

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-baseline-writer-')));
    git(dir, ['init', '-q', '-b', 'main']);
    git(dir, ['config', 'user.email', 'test@example.invalid']);
    git(dir, ['config', 'user.name', 'Test']);
    git(dir, ['config', 'commit.gpgsign', 'false']);
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    try {
      fs.chmodSync(path.join(dir, 'src', 'locked.ts'), 0o644);
    } catch {
      /* not created in every case */
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function seedCriticalAndHigh(): void {
    write('src/crit.ts', `export const k = "${CRITICAL_KEY}";\n`);
    write('src/high.ts', `export const t = "${HIGH_A}";\n`);
    commit('base');
  }

  describe('T10: critical findings are refused unless asked for', () => {
    it('a dry run lists and writes nothing, exit 0', async () => {
      seedCriticalAndHigh();
      const r = await capture(() => baselineCommand('.', { write: false, includeCritical: false }));
      expect(r.code).toBe(0);
      expect(fs.existsSync(baselinePath())).toBe(false);
      expect(r.log).toContain('src/high.ts:1');
    });

    it('--write writes the high finding only, lists the critical, exits 1', async () => {
      seedCriticalAndHigh();
      const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
      expect(r.code).toBe(1);
      const doc = readBaseline();
      expect(doc.entries.map(e => e.rule)).toEqual(['jwt-token']);
      expect(doc.entries[0].severity).toBe('high');
      expect(r.log).toMatch(/not accepted: critical, rotate and remove instead/);
      expect(r.log).toContain('src/crit.ts:1');
    });

    it('--write --include-critical writes both, exit 0', async () => {
      seedCriticalAndHigh();
      const r = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
      expect(r.code).toBe(0);
      expect(readBaseline().entries.map(e => e.rule).sort()).toEqual(['anthropic', 'jwt-token']);
      const after = await scanJson();
      expect(after.code).toBe(0);
      expect(after.doc.run.baseline_suppressed).toBe(2);
    });

    it('T10b: scan never creates the baseline file', async () => {
      seedCriticalAndHigh();
      await capture(() => scanCommand('.', 'text', false));
      await capture(() => scanCommand('.', 'json', false));
      expect(fs.existsSync(baselinePath())).toBe(false);
    });
  });

  it('T11: a pull request cannot baseline its own new finding', async () => {
    seedCriticalAndHigh();
    expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
    commit('base: accept existing findings');
    git(dir, ['branch', 'base-snapshot']);
    git(dir, ['checkout', '-q', '-b', 'feature']);
    write('src/new.ts', `export const n = "${HIGH_B}";\n`);
    commit('feature: add a key');
    expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
    commit('feature: baseline it');

    const json = await scanJson('base-snapshot');
    expect(json.code).toBe(1);
    expect(json.doc.results.map(r => r.file)).toEqual(['src/new.ts']);
    const text = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
    expect(text.code).toBe(1);
    expect(text.log).toContain(
      'Proposed, not applied: baseline changed in this pull request (1 baseline entry added)',
    );
  });

  describe('T16: an incomplete scan writes nothing', () => {
    itPosix('--write with an unreadable tracked file: exit 2, no file', async () => {
      if (isRoot) return;
      seedCriticalAndHigh();
      write('src/locked.ts', 'export const x = 1;\n');
      commit('locked');
      fs.chmodSync(path.join(dir, 'src', 'locked.ts'), 0o000);
      const r = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
      expect(r.code).toBe(2);
      expect(fs.existsSync(baselinePath())).toBe(false);
    });

    it('--trust-base and --staged are refused with exit 2', async () => {
      seedCriticalAndHigh();
      const a = await capture(() =>
        baselineCommand('.', { write: true, includeCritical: true, trustBase: 'x' }),
      );
      expect(a.code).toBe(2);
      const b = await capture(() =>
        baselineCommand('.', { write: true, includeCritical: true, staged: true }),
      );
      expect(b.code).toBe(2);
      expect(fs.existsSync(baselinePath())).toBe(false);
    });

    it('the built CLI refuses baseline --trust-base x with exit 2', () => {
      const cliEntry = path.join(__dirname, '..', '..', '..', 'dist', 'cli-entry.js');
      seedCriticalAndHigh();
      const r = spawnSync(process.execPath, [cliEntry, 'baseline', '--trust-base', 'x'], {
        cwd: dir,
        encoding: 'utf-8',
      });
      expect(r.status).toBe(2);
      expect(fs.existsSync(baselinePath())).toBe(false);
    });
  });

  describe('T17: a header-only finding is bound to the whole file', () => {
    it('a swapped PEM body behind the same header blocks, plain and --trust-base', async () => {
      write('keys/id.pem', pem(BODY_1));
      commit('base');
      expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
      const doc = readBaseline();
      const entry = doc.entries.find(e => e.rule === 'ssh-private-key');
      expect(entry?.file_digest).toMatch(/^[0-9a-f]{64}$/);
      // Spec point 1: a header-only finding stays OUT of the positional list,
      // so a 1.9.x runner, which reads only that list, still shows it.
      const before = await scanJson();
      expect(before.code).toBe(0);
      expect(doc.fingerprints).toHaveLength(0);
      commit('base: baseline');
      git(dir, ['branch', 'base-snapshot']);

      write('keys/id.pem', pem(BODY_2));
      const plain = await scanJson();
      expect(plain.code).toBe(1);
      commit('feature: swap the key body');
      const pr = await scanJson('base-snapshot');
      expect(pr.code).toBe(1);
    });

    it('under --staged the file digest is taken over the staged blob, not the working tree', async () => {
      write('keys/id.pem', pem(BODY_1));
      commit('base');
      await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
      commit('baseline');
      // Stage a swapped body, then put the accepted bytes back in the working
      // tree: the commit would carry the new key.
      write('keys/id.pem', pem(BODY_2));
      git(dir, ['add', 'keys/id.pem']);
      write('keys/id.pem', pem(BODY_1));
      const r = await capture(() => scanCommand('.', 'json', true));
      expect(r.code).toBe(1);
    });

    it('a gcp service account JSON whose private_key changes blocks', async () => {
      write('svc.json', gcp(BODY_1));
      commit('base');
      expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
      expect(readBaseline().entries.some(e => e.rule === 'gcp-service-account')).toBe(true);
      expect((await scanJson()).code).toBe(0);
      commit('base: baseline');
      git(dir, ['branch', 'base-snapshot']);

      write('svc.json', gcp(BODY_2));
      expect((await scanJson()).code).toBe(1);
      commit('feature: rotate in place');
      expect((await scanJson('base-snapshot')).code).toBe(1);
    });

    it('spec point 3: the file digest is over raw bytes, so LF to CRLF stops the match', async () => {
      write('keys/id.pem', pem(BODY_1));
      commit('base');
      await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
      expect((await scanJson()).code).toBe(0);
      write('keys/id.pem', pem(BODY_1, '\r\n'));
      expect((await scanJson()).code).toBe(1);
    });
  });

  describe('T20: the file is written at the repository root, from the root', () => {
    it('--write from a subdirectory exits 2, names the root, writes nothing', async () => {
      write('sub/a.ts', `export const t = "${HIGH_A}";\n`);
      commit('base');
      process.chdir(path.join(dir, 'sub'));
      const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
      expect(r.code).toBe(2);
      expect(r.err).toContain(dir);
      expect(fs.existsSync(baselinePath())).toBe(false);
      expect(fs.existsSync(path.join(dir, 'sub', '.vault-guard.baseline.json'))).toBe(false);
    });

    it('baseline sub/ from the root, then scan . from the root: suppressed', async () => {
      write('sub/a.ts', `export const t = "${HIGH_A}";\n`);
      write('other.ts', 'export const o = 1;\n');
      commit('base');
      const r = await capture(() => baselineCommand('sub', { write: true, includeCritical: false }));
      expect(r.code).toBe(0);
      const after = await scanJson();
      expect(after.code).toBe(0);
      expect(after.doc.run.baseline_suppressed).toBe(1);
    });
  });

  it('T24: an untracked file is never written into the baseline', async () => {
    write('src/high.ts', `export const t = "${HIGH_A}";\n`);
    commit('base');
    write('scratch/notes.ts', `export const u = "${HIGH_B}";\n`);
    const before = await scanJson();
    const untrackedKeys = before.doc.results
      .filter(r => r.file.startsWith('scratch'))
      .flatMap(r => r.matches.map(m => m.fingerprint));
    expect(untrackedKeys).toHaveLength(1);

    const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
    expect(r.code).toBe(0);
    expect(r.log).toContain('untracked files with findings: 1');
    const raw = fs.readFileSync(baselinePath(), 'utf-8');
    expect(raw).not.toContain('scratch');
    expect(raw).not.toContain('notes.ts');
    expect(raw).not.toContain(untrackedKeys[0]);
    expect(readBaseline().entries).toHaveLength(1);
  });

  it('T24: files tracked only by an untracked nested repository are never written', async () => {
    write('src/high.ts', `export const t = "${HIGH_A}";\n`);
    commit('base');
    const nested = path.join(dir, 'nested');
    fs.mkdirSync(nested);
    git(nested, ['init', '-q', '-b', 'main']);
    git(nested, ['config', 'user.email', 'test@example.invalid']);
    git(nested, ['config', 'user.name', 'Test']);
    git(nested, ['config', 'commit.gpgsign', 'false']);
    write('nested/secret.ts', `export const u = "${HIGH_B}";\n`);
    git(nested, ['add', '-A']);
    git(nested, ['commit', '-q', '-m', 'nested']);

    const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
    expect(r.code).toBe(0);
    expect(r.log).toContain('untracked files with findings: 1');
    const raw = fs.readFileSync(baselinePath(), 'utf-8');
    expect(raw).not.toContain('nested');
    expect(readBaseline().entries).toHaveLength(1);
  });

  describe('N1: location follows the target as well as the cwd', () => {
    let outside: string;
    beforeEach(() => {
      outside = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-baseline-out-')));
    });
    afterEach(() => {
      fs.rmSync(outside, { recursive: true, force: true });
    });

    it('cwd outside git, target inside a repository: --write refuses, names the root, writes nothing', async () => {
      write('src/a.ts', `export const t = "${HIGH_A}";\n`);
      commit('base');
      process.chdir(outside);
      const r = await capture(() => baselineCommand(dir, { write: true, includeCritical: false }));
      expect(r.code).toBe(2);
      expect(r.err).toContain(dir);
      expect(fs.existsSync(path.join(outside, '.vault-guard.baseline.json'))).toBe(false);
      expect(fs.existsSync(baselinePath())).toBe(false);
    });

    it('neither cwd nor target in git: says so, and writes in the cwd', async () => {
      fs.writeFileSync(path.join(outside, 'a.ts'), `export const t = "${HIGH_A}";\n`);
      process.chdir(outside);
      const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
      expect(r.code).toBe(0);
      expect(r.log).toContain('not a git repository');
      expect(fs.existsSync(path.join(outside, '.vault-guard.baseline.json'))).toBe(true);
    });
  });

  it('N2: a scoped --write keeps entries outside the scanned path', async () => {
    write('a/k.ts', `export const t = "${HIGH_A}";\n`);
    write('b/k.ts', `export const t = "${HIGH_B}";\n`);
    commit('base');
    expect((await capture(() => baselineCommand('.', { write: true, includeCritical: false }))).code).toBe(0);
    expect(readBaseline().entries).toHaveLength(2);
    const r = await capture(() => baselineCommand('a', { write: true, includeCritical: false }));
    expect(r.code).toBe(0);
    expect(r.log).toContain('1 entries outside the scanned path kept');
    expect(r.log).toContain('kept 1, added 0, dropped 0 (no longer found)');
    expect(readBaseline().entries.map(e => e.file).sort()).toEqual(['a/k.ts', 'b/k.ts']);
    const after = await scanJson();
    expect(after.code).toBe(0);
    expect(after.doc.run.baseline_suppressed).toBe(2);
  });

  it('kept, added and dropped are reported against the previous file', async () => {
    write('src/a.ts', `export const t = "${HIGH_A}";\n`);
    commit('base');
    await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
    write('src/a.ts', 'export const t = 1;\n');
    write('src/b.ts', `export const t = "${HIGH_B}";\n`);
    commit('replace the key');
    const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
    expect(r.log).toContain('kept 0, added 1, dropped 1 (no longer found)');
  });

  it('a positional-only file is converted', async () => {
    write('src/a.ts', `export const t = "${HIGH_A}";\n`);
    commit('base');
    const { doc } = await scanJson();
    write(
      '.vault-guard.baseline.json',
      JSON.stringify({ version: 1, fingerprints: [doc.results[0].matches[0].fingerprint] }),
    );
    const r = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
    expect(r.code).toBe(0);
    expect(r.log).toMatch(/converted 1/);
    expect(readBaseline().entries).toHaveLength(1);
  });
});
