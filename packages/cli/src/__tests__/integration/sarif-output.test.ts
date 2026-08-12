import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Contract: `--format sarif` must write parseable SARIF JSON to stdout only.
 * A leading `--` in argv (forwarded by some npx invocations) must not disable
 * option parsing — otherwise text banners land in the SARIF file and GitHub
 * upload-sarif rejects it.
 */
describe('CLI SARIF stdout contract', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');
  const monorepoRoot = path.join(packageRoot, '..', '..');

  const runSarifScan = (args: string[], cwd: string) => {
    return spawnSync(process.execPath, [cliEntry, ...args], {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });
  };

  const parseStdoutSarif = (stdout: string): { version?: string; runs?: unknown[] } => {
    const trimmed = stdout.trim();
    expect(trimmed.startsWith('{')).toBe(true);
    expect(trimmed).not.toMatch(/🔍/);
    return JSON.parse(trimmed) as { version?: string; runs?: unknown[] };
  };

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  it('writes parseable SARIF only to stdout', () => {
    const fixtureDir = path.join(monorepoRoot, 'fixtures', 'release-smoke');
    const proc = runSarifScan(['scan', fixtureDir, '--format', 'sarif'], monorepoRoot);
    expect(proc.error).toBeUndefined();

    const body = parseStdoutSarif(proc.stdout);
    expect(body.version).toBe('2.1.0');
    expect(Array.isArray(body.runs)).toBe(true);
    expect(proc.status).not.toBe(0);
  });

  it('still honors --format when argv has a leading -- (npx passthrough)', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-sarif-ddash-'));
    try {
      fs.writeFileSync(path.join(tmp, 'clean.ts'), "export const x = 'hello';\n", 'utf-8');

      const proc = runSarifScan(['--', 'scan', tmp, '--format', 'sarif'], tmp);
      expect(proc.error).toBeUndefined();

      const body = parseStdoutSarif(proc.stdout);
      expect(body.version).toBe('2.1.0');
      expect(proc.status).toBe(0);
      expect(proc.stdout).not.toMatch(/Scanning/);
    } finally {
      fs.unlinkSync(path.join(tmp, 'clean.ts'));
      fs.rmdirSync(tmp);
    }
  });
});
