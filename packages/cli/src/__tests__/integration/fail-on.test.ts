import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Contract for the 1.4.0 severity gate.
 *
 * Before 1.4.0 any match at all returned exit 1, which made the scanner's own
 * `low` downgrades (test/docs/example paths, public identifiers) pointless: a
 * `.env.example` still blocked the commit. The gate now defaults to `medium`.
 */
describe('CLI --fail-on gate', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');

  let workdir: string;

  const run = (args: string[]) =>
    spawnSync(process.execPath, [cliEntry, ...args], {
      cwd: workdir,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  beforeEach(() => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-fail-on-'));
    // `low` only: a docs-path generic finding gets downgraded by path-severity.
    fs.mkdirSync(path.join(workdir, 'docs'));
    fs.writeFileSync(
      path.join(workdir, 'docs', 'setup.md'),
      'Set `api_key = "aB3cD4eF5gH6iJ7kLmNoPqRs"` in your config.\n',
    );
  });

  afterEach(() => {
    fs.rmSync(workdir, { recursive: true, force: true });
  });

  const writeCriticalFinding = () => {
    fs.writeFileSync(
      path.join(workdir, 'prod.ts'),
      `const k = ${JSON.stringify(['sk-ant-', 'api03-', 'Zg7kP2mQxN4RvT8wYhLs6FjEbDcA9uKp'].join(''))};\n`,
    );
  };

  it('does not fail the gate on low-severity findings by default', () => {
    const proc = run(['scan', '.', '--format', 'json']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.summary.secrets).toBeGreaterThan(0);
    expect(out.run.fail_on).toBe('medium');
    expect(out.run.blocking_matches).toBe(0);
    expect(proc.status).toBe(0);
  });

  it('still fails the gate on a critical finding', () => {
    writeCriticalFinding();
    const proc = run(['scan', '.', '--format', 'json']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.blocking_matches).toBeGreaterThan(0);
    expect(proc.status).toBe(1);
  });

  it('--fail-on low restores the pre-1.4.0 block-on-anything behaviour', () => {
    const proc = run(['scan', '.', '--format', 'json', '--fail-on', 'low']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.fail_on).toBe('low');
    expect(out.run.blocking_matches).toBeGreaterThan(0);
    expect(proc.status).toBe(1);
  });

  it('--fail-on none reports findings but never fails', () => {
    writeCriticalFinding();
    const proc = run(['scan', '.', '--format', 'json', '--fail-on', 'none']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.summary.secrets).toBeGreaterThan(0);
    expect(out.run.blocking_matches).toBe(0);
    expect(proc.status).toBe(0);
  });

  it('reads fail_on from .vault-guard.json', () => {
    fs.writeFileSync(
      path.join(workdir, '.vault-guard.json'),
      JSON.stringify({ fail_on: 'low' }),
    );
    const proc = run(['scan', '.', '--format', 'json']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.fail_on).toBe('low');
    expect(proc.status).toBe(1);
  });

  it('lets --fail-on override the config value', () => {
    fs.writeFileSync(
      path.join(workdir, '.vault-guard.json'),
      JSON.stringify({ fail_on: 'low' }),
    );
    const proc = run(['scan', '.', '--format', 'json', '--fail-on', 'critical']);
    const out = JSON.parse(proc.stdout.trim());

    expect(out.run.fail_on).toBe('critical');
    expect(proc.status).toBe(0);
  });

  it('rejects an invalid --fail-on value instead of silently defaulting', () => {
    const proc = run(['scan', '.', '--fail-on', 'sometimes']);
    expect(proc.status).toBe(1);
    expect(proc.stderr).toMatch(/Invalid fail-on value/);
  });

  it('text mode explains why findings did not fail the gate', () => {
    const proc = run(['scan', '.']);
    expect(proc.status).toBe(0);
    expect(proc.stdout).toMatch(/none at or above severity "medium"/);
  });

  it('applies the same gate to `check`', () => {
    const proc = run(['check', 'docs/setup.md']);
    expect(proc.status).toBe(0);
  });
});
