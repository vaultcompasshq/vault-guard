import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Contract: `--format json` must write exactly one JSON object to stdout (stderr may carry warnings).
 * Call the built CLI entry so behavior matches production / `node dist/cli-entry.js`.
 */
describe('CLI JSON stdout contract', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');
  const monorepoRoot = path.join(packageRoot, '..', '..');

  const runJsonScan = (targetPath: string, cwd: string) => {
    return spawnSync(process.execPath, [cliEntry, 'scan', targetPath, '--format', 'json'], {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });
  };

  const parseStdoutJson = (stdout: string): unknown => {
    const trimmed = stdout.trim();
    expect(trimmed.startsWith('{')).toBe(true);
    expect(trimmed.endsWith('}')).toBe(true);
    return JSON.parse(trimmed);
  };

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  it('writes parseable JSON only to stdout for fixtures/release-smoke (findings)', () => {
    const fixtureDir = path.join(monorepoRoot, 'fixtures', 'release-smoke');
    expect(fs.existsSync(fixtureDir)).toBe(true);

    const proc = runJsonScan(fixtureDir, monorepoRoot);
    expect(proc.error).toBeUndefined();

    expect(proc.stdout.trim().length).toBeGreaterThan(0);
    expect(proc.stderr ?? '').not.toMatch(/🔍 Scanning/);

    const body = parseStdoutJson(proc.stdout) as {
      summary?: { secrets?: number };
      results?: unknown[];
      run?: { duration_ms?: number };
    };

    expect(typeof body.summary?.secrets).toBe('number');
    expect(body.summary!.secrets!).toBeGreaterThan(0);
    expect(Array.isArray(body.results)).toBe(true);
    expect(proc.status).not.toBe(0);
    expect(body.run?.duration_ms).toBeDefined();
  });

  it('flushes a large JSON findings payload before exiting non-zero', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-json-large-'));
    const secretPrefix = ['sk', '-ant', '-api03-'].join('');
    try {
      const lines = Array.from({ length: 2000 }, (_, i) => {
        const suffix = `${String(i).padStart(4, '0')}abcdefghijklmnopqrstuvwxyz`;
        return `const key${i} = "${secretPrefix}${suffix}";`;
      });
      fs.writeFileSync(path.join(tmp, 'many.ts'), `${lines.join('\n')}\n`, 'utf-8');

      const proc = runJsonScan(tmp, tmp);
      expect(proc.error).toBeUndefined();

      const body = parseStdoutJson(proc.stdout) as {
        summary?: { secrets?: number };
        results?: Array<{ matches?: unknown[] }>;
      };

      expect(proc.status).not.toBe(0);
      expect(body.summary?.secrets).toBe(2000);
      expect(body.results?.[0]?.matches?.length).toBe(2000);
    } finally {
      fs.unlinkSync(path.join(tmp, 'many.ts'));
      fs.rmdirSync(tmp);
    }
  });

  it('writes parseable JSON only to stdout for a clean temp directory (no findings)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-json-contract-'));
    try {
      fs.writeFileSync(path.join(tmp, 'clean.ts'), "export const x = 'hello';\n", 'utf-8');

      const proc = runJsonScan(tmp, tmp);
      expect(proc.error).toBeUndefined();

      const body = parseStdoutJson(proc.stdout) as {
        summary?: { secrets?: number };
      };

      expect(body.summary?.secrets).toBe(0);
      expect(proc.status).toBe(0);
      expect(proc.stderr ?? '').not.toMatch(/🔍 Scanning/);
    } finally {
      fs.unlinkSync(path.join(tmp, 'clean.ts'));
      fs.rmdirSync(tmp);
    }
  });
});
