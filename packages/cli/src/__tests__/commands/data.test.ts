import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { TelemetryStore, getDbSidecarPaths } from '@vaultcompass/vault-guard-telemetry';
import { dataStatusCommand, dataResetCommand, dataExportCommand } from '../../commands/data';

function tmpDb(label: string): string {
  return path.join(os.tmpdir(), `vg-cli-data-${label}-${Date.now()}-${Math.random()}.sqlite`);
}

function cleanupDb(dbPath: string): void {
  try {
    fs.unlinkSync(dbPath);
  } catch {
    // not present
  }
  for (const sidecar of getDbSidecarPaths(dbPath)) {
    try {
      fs.unlinkSync(sidecar);
    } catch {
      // not present
    }
  }
}

describe('vault-guard data status', () => {
  let stdoutSpy: jest.SpyInstance;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it('prints JSON when --json is passed and never includes raw cwd', async () => {
    const dbPath = tmpDb('json');
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({
        provider: 'anthropic',
        model: 'claude-test',
        cwd: '/home/leaktest/sensitive-dir',
        inputTokens: 10,
        outputTokens: 5,
      });
      seed.close();

      const exit = await dataStatusCommand({ json: true, dbPath });
      expect(exit).toBe(0);

      const writes = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
      expect(writes).toContain('"db_exists":true');
      expect(writes).toContain('"usage_events":1');
      expect(writes).toContain('"distinct_cwd_count":1');
      expect(writes).not.toContain('leaktest');
      expect(writes).not.toContain('sensitive-dir');
    } finally {
      cleanupDb(dbPath);
    }
  });

  it('prints a human-readable summary by default', async () => {
    const dbPath = tmpDb('human');
    try {
      const exit = await dataStatusCommand({ dbPath });
      expect(exit).toBe(0);
      const writes = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
      expect(writes).toContain('Vault Guard local telemetry status');
      expect(writes).toContain('db path');
      expect(writes).toContain('usage events');
    } finally {
      cleanupDb(dbPath);
    }
  });
});

describe('vault-guard data reset', () => {
  let stdoutSpy: jest.SpyInstance;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it('returns 0 and lists nothing when no telemetry files exist', async () => {
    const dbPath = tmpDb('absent');
    try {
      const exit = await dataResetCommand({ yes: true, dbPath, json: true });
      expect(exit).toBe(0);
      const writes = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
      expect(writes).toContain('"removed":[]');
    } finally {
      cleanupDb(dbPath);
    }
  });

  it('does not delete files in --dry-run mode', async () => {
    const dbPath = tmpDb('dry');
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({
        provider: 'anthropic',
        model: 'm',
        inputTokens: 1,
        outputTokens: 1,
      });
      seed.close();

      expect(fs.existsSync(dbPath)).toBe(true);

      const exit = await dataResetCommand({ dryRun: true, dbPath, json: true });
      expect(exit).toBe(0);
      expect(fs.existsSync(dbPath)).toBe(true);

      const writes = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
      const parsed = JSON.parse(writes.trim());
      expect(parsed.dry_run).toBe(true);
      expect(parsed.removed.length).toBeGreaterThan(0);
    } finally {
      cleanupDb(dbPath);
    }
  });

  it('deletes the db when --yes is passed', async () => {
    const dbPath = tmpDb('delete');
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({
        provider: 'anthropic',
        model: 'm',
        inputTokens: 1,
        outputTokens: 1,
      });
      seed.close();
      expect(fs.existsSync(dbPath)).toBe(true);

      const exit = await dataResetCommand({ yes: true, dbPath, json: true });
      expect(exit).toBe(0);
      expect(fs.existsSync(dbPath)).toBe(false);
    } finally {
      cleanupDb(dbPath);
    }
  });

  it('cancels when the confirmFn seam returns false', async () => {
    const dbPath = tmpDb('cancel');
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({
        provider: 'anthropic',
        model: 'm',
        inputTokens: 1,
        outputTokens: 1,
      });
      seed.close();

      const exit = await dataResetCommand({
        dbPath,
        json: true,
        confirmFn: async () => false,
      });
      expect(exit).toBe(0);
      expect(fs.existsSync(dbPath)).toBe(true);

      const writes = stdoutSpy.mock.calls.map(c => String(c[0])).join('');
      expect(writes).toContain('"cancelled":true');
    } finally {
      cleanupDb(dbPath);
    }
  });

  it('proceeds when the confirmFn seam returns true', async () => {
    const dbPath = tmpDb('proceed');
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({
        provider: 'anthropic',
        model: 'm',
        inputTokens: 1,
        outputTokens: 1,
      });
      seed.close();

      const exit = await dataResetCommand({
        dbPath,
        json: true,
        confirmFn: async () => true,
      });
      expect(exit).toBe(0);
      expect(fs.existsSync(dbPath)).toBe(false);
    } finally {
      cleanupDb(dbPath);
    }
  });
});

describe('vault-guard data export', () => {
  let stdoutSpy: jest.SpyInstance;
  let stderrSpy: jest.SpyInstance;

  beforeEach(() => {
    stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    stderrSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it('writes a JSON file containing usage and session rows', async () => {
    const dbPath = tmpDb('export-json');
    const outPath = path.join(os.tmpdir(), `vg-export-${Date.now()}.json`);
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({
        provider: 'anthropic',
        model: 'm',
        cwd: '/home/x/proj',
        inputTokens: 1,
        outputTokens: 1,
      });
      seed.recordSession({ eventType: 'apply', cwd: '/home/x/proj' });
      seed.close();

      const exit = await dataExportCommand({ output: outPath, dbPath });
      expect(exit).toBe(0);
      expect(fs.existsSync(outPath)).toBe(true);

      const parsed = JSON.parse(fs.readFileSync(outPath, 'utf-8'));
      expect(parsed.usage_events).toHaveLength(1);
      expect(parsed.session_events).toHaveLength(1);
      expect(parsed.usage_events[0].cwd).toMatch(/^[a-f0-9]{64}$/);
      expect(parsed.usage_events[0].cwd).toBe(parsed.session_events[0].cwd);

      // Mode 0o600: only the user can read. On macOS/Linux, stat the file.
      const stat = fs.statSync(outPath);
      // mask is platform-dependent (Windows lacks POSIX modes); only assert
      // when the underlying mode bits are populated.
      if (process.platform !== 'win32') {
        expect(stat.mode & 0o077).toBe(0);
      }
    } finally {
      try { fs.unlinkSync(outPath); } catch { /* best-effort cleanup */ }
      cleanupDb(dbPath);
    }
  });

  it('writes one JSONL line per row when --format jsonl is passed', async () => {
    const dbPath = tmpDb('export-jsonl');
    const outPath = path.join(os.tmpdir(), `vg-export-${Date.now()}.jsonl`);
    try {
      const seed = new TelemetryStore(dbPath);
      seed.recordUsage({ provider: 'anthropic', model: 'm', inputTokens: 1, outputTokens: 1 });
      seed.recordSession({ eventType: 'apply' });
      seed.close();

      const exit = await dataExportCommand({ output: outPath, dbPath, format: 'jsonl' });
      expect(exit).toBe(0);

      const lines = fs.readFileSync(outPath, 'utf-8').trim().split('\n');
      expect(lines).toHaveLength(2);
      const tables = lines.map(l => JSON.parse(l).table);
      expect(tables).toContain('usage_events');
      expect(tables).toContain('session_events');
    } finally {
      try { fs.unlinkSync(outPath); } catch { /* best-effort cleanup */ }
      cleanupDb(dbPath);
    }
  });
});
