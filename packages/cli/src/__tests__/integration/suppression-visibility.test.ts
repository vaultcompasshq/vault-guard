import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanCommand } from '../../commands/scan';

/**
 * Synthetic Anthropic-shaped key, joined at runtime. A committed provider-key
 * shape trips credential scanners regardless of the value being fake and the
 * file being a test, so no fragment matches a rule on its own. Same convention
 * as bench/generate-fixtures.cjs.
 */
const ANTHROPIC_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

interface Captured {
  code: number;
  /** console.log text (text-mode summary lines). */
  log: string;
  /** console.error text (warnings, notes). */
  err: string;
  /** process.stdout.write payload (the JSON / SARIF document). */
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

describe('suppression visibility', () => {
  let dir: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-suppress-'));
    process.chdir(dir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('prints the baseline-suppressed count on the text summary', async () => {
    fs.writeFileSync(path.join(dir, 'secret.ts'), `const k = "${ANTHROPIC_KEY}";\n`);

    // First pass: read the finding's fingerprint out of the JSON document.
    const json = await capture(() => scanCommand('.', 'json'));
    const doc = JSON.parse(json.stdout) as {
      results: Array<{ matches: Array<{ fingerprint: string }> }>;
    };
    const fp = doc.results[0].matches[0].fingerprint;
    fs.writeFileSync(
      path.join(dir, '.vault-guard.baseline.json'),
      JSON.stringify({ version: 1, fingerprints: [fp] }),
    );

    // Second pass: the finding is now baselined, and text must say so.
    const text = await capture(() => scanCommand('.', 'text'));
    expect(text.log).toMatch(/1 by baseline/);
    expect(text.code).toBe(0);
  });

  it('always states the baseline count in text, even at zero', async () => {
    fs.writeFileSync(path.join(dir, 'clean.ts'), "export const x = 'hello';\n");
    const text = await capture(() => scanCommand('.', 'text'));
    expect(text.log).toMatch(/Suppressed: 0 by baseline/);
  });

  it('reports an inline ignore-directive suppression in text with the count', async () => {
    fs.writeFileSync(
      path.join(dir, 'ignored.ts'),
      `const k = "${ANTHROPIC_KEY}"; // vault-guard: ignore-line\n`,
    );
    const text = await capture(() => scanCommand('.', 'text'));
    // The finding is suppressed (no blocking secret), but the run must say it happened.
    expect(text.log).toMatch(/1 by inline ignore directive/);
    expect(text.code).toBe(0);
  });

  it('reports an inline ignore-directive suppression in JSON with the line number', async () => {
    fs.writeFileSync(
      path.join(dir, 'ignored.ts'),
      `const k = "${ANTHROPIC_KEY}"; // vault-guard: ignore-line\n`,
    );
    const json = await capture(() => scanCommand('.', 'json'));
    const doc = JSON.parse(json.stdout) as {
      run: { inline_suppressed: number };
      diagnostics?: Array<{ code: string; ctx: { lines?: number[]; count?: number } }>;
    };
    expect(doc.run.inline_suppressed).toBe(1);
    const diag = doc.diagnostics?.find(d => d.code === 'suppression.inline');
    expect(diag).toBeDefined();
    expect(diag?.ctx.lines).toEqual([1]);
    expect(diag?.ctx.count).toBe(1);
  });

  it('emits inline_suppressed in JSON even at zero', async () => {
    fs.writeFileSync(path.join(dir, 'clean.ts'), "export const x = 'hello';\n");
    const json = await capture(() => scanCommand('.', 'json'));
    const doc = JSON.parse(json.stdout) as { run: { inline_suppressed: number } };
    expect(doc.run.inline_suppressed).toBe(0);
  });

  it('reports an inline ignore-directive suppression in SARIF with the line number', async () => {
    fs.writeFileSync(
      path.join(dir, 'ignored.ts'),
      `const k = "${ANTHROPIC_KEY}"; // vault-guard: ignore-line\n`,
    );
    const sarif = await capture(() => scanCommand('.', 'sarif'));
    const doc = JSON.parse(sarif.stdout) as {
      runs: Array<{
        properties: { vault_guard_run: { inline_suppressed: number } };
        tool: { driver: { notifications?: Array<{ id: string; message: { text: string } }> } };
      }>;
    };
    expect(doc.runs[0].properties.vault_guard_run.inline_suppressed).toBe(1);
    const note = doc.runs[0].tool.driver.notifications?.find(n => n.id === 'suppression.inline');
    expect(note).toBeDefined();
  });
});
