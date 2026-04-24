import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHmac } from 'crypto';
import Database from 'better-sqlite3';
import { TelemetryStore, getDbSidecarPaths, getOrCreateTelemetrySalt, getTelemetryRetentionDays } from '../store';

describe('getTelemetryRetentionDays', () => {
  const prev = process.env.VG_TELEMETRY_RETENTION_DAYS;

  afterEach(() => {
    if (prev === undefined) delete process.env.VG_TELEMETRY_RETENTION_DAYS;
    else process.env.VG_TELEMETRY_RETENTION_DAYS = prev;
  });

  it('defaults to 90 when unset', () => {
    delete process.env.VG_TELEMETRY_RETENTION_DAYS;
    expect(getTelemetryRetentionDays()).toBe(90);
  });

  it('returns 0 when disabled', () => {
    process.env.VG_TELEMETRY_RETENTION_DAYS = '0';
    expect(getTelemetryRetentionDays()).toBe(0);
  });
});

describe('TelemetryStore cwd migration', () => {
  it('re-hashes legacy plaintext cwd when user_version < 2', () => {
    const dbPath = path.join(os.tmpdir(), `vg-cwd-migrate-${Date.now()}.sqlite`);
    const store1 = new TelemetryStore(dbPath);
    try {
      store1.recordUsage({
        provider: 'anthropic',
        model: 'm',
        cwd: '/tmp/seed',
        inputTokens: 1,
        outputTokens: 1,
      });
    } finally {
      store1.close();
    }

    const raw = new Database(dbPath);
    raw.prepare('UPDATE usage_events SET cwd = ? WHERE id = 1').run('/legacy/plain');
    raw.pragma('user_version = 0');
    raw.close();

    const store2 = new TelemetryStore(dbPath);
    try {
      const salt = getOrCreateTelemetrySalt();
      const expected = createHmac('sha256', salt).update('/legacy/plain', 'utf8').digest('hex');
      const row = store2.exportUsageEvents()[0];
      expect(row.cwd).toBe(expected);
      expect(row.cwd).toMatch(/^[a-f0-9]{64}$/);
    } finally {
      store2.close();
      try {
        fs.unlinkSync(dbPath);
      } catch {
        /* ignore */
      }
      for (const s of getDbSidecarPaths(dbPath)) {
        try {
          fs.unlinkSync(s);
        } catch {
          /* ignore */
        }
      }
    }
  });
});

describe('TelemetryStore retention purge', () => {
  const prevDays = process.env.VG_TELEMETRY_RETENTION_DAYS;
  const prevThrottle = process.env.VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE;

  afterEach(() => {
    if (prevDays === undefined) delete process.env.VG_TELEMETRY_RETENTION_DAYS;
    else process.env.VG_TELEMETRY_RETENTION_DAYS = prevDays;
    if (prevThrottle === undefined) delete process.env.VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE;
    else process.env.VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE = prevThrottle;
  });

  it('deletes events older than VG_TELEMETRY_RETENTION_DAYS', () => {
    process.env.VG_TELEMETRY_RETENTION_DAYS = '30';
    process.env.VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE = '1';

    const dbPath = path.join(os.tmpdir(), `vg-retention-${Date.now()}.sqlite`);
    const old = new Date();
    old.setUTCDate(old.getUTCDate() - 120);

    const store1 = new TelemetryStore(dbPath);
    try {
      store1.recordUsage({
        provider: 'anthropic',
        model: 'm',
        inputTokens: 1,
        outputTokens: 1,
        createdAt: old,
      });
      expect(store1.exportUsageEvents()).toHaveLength(1);
    } finally {
      store1.close();
    }

    const store2 = new TelemetryStore(dbPath);
    try {
      expect(store2.exportUsageEvents()).toHaveLength(0);
    } finally {
      store2.close();
      try {
        fs.unlinkSync(dbPath);
      } catch {
        /* ignore */
      }
      for (const s of getDbSidecarPaths(dbPath)) {
        try {
          fs.unlinkSync(s);
        } catch {
          /* ignore */
        }
      }
    }
  });
});
