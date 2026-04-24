import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { TelemetryStore, getDbSidecarPaths } from '../store';

function tmpDb(label: string): string {
  return path.join(os.tmpdir(), `vg-data-status-${label}-${Date.now()}-${Math.random()}.sqlite`);
}

describe('TelemetryStore.getDataStatus', () => {
  it('reports an empty database with zero counts', () => {
    const dbPath = tmpDb('empty');
    const store = new TelemetryStore(dbPath);
    try {
      const status = store.getDataStatus(dbPath);
      expect(status.db_path).toBe(dbPath);
      expect(status.db_exists).toBe(true);
      expect(status.usage_events).toBe(0);
      expect(status.session_events).toBe(0);
      expect(status.earliest_event_iso).toBeNull();
      expect(status.latest_event_iso).toBeNull();
      expect(status.distinct_cwd_count).toBe(0);
      expect(status.distinct_model_count).toBe(0);
      expect(status.last_model).toBeNull();
    } finally {
      store.close();
      try { fs.unlinkSync(dbPath); } catch { /* best-effort cleanup */ }
      for (const s of getDbSidecarPaths(dbPath)) {
        try { fs.unlinkSync(s); } catch { /* best-effort cleanup */ }
      }
    }
  });

  it('aggregates counts across both tables without leaking raw cwd values', () => {
    const dbPath = tmpDb('populated');
    const store = new TelemetryStore(dbPath);
    try {
      store.recordUsage({
        provider: 'anthropic',
        model: 'claude-x',
        cwd: '/home/alice/secret-project',
        inputTokens: 10,
        outputTokens: 5,
      });
      store.recordUsage({
        provider: 'anthropic',
        model: 'claude-y',
        cwd: '/home/alice/other-project',
        inputTokens: 20,
        outputTokens: 8,
      });
      store.recordSession({
        eventType: 'apply',
        model: 'claude-x',
        cwd: '/home/alice/secret-project',
      });

      const status = store.getDataStatus(dbPath);

      expect(status.usage_events).toBe(2);
      expect(status.session_events).toBe(1);
      expect(status.distinct_cwd_count).toBe(2);
      expect(status.distinct_model_count).toBe(2);
      expect(status.last_model).toBe('claude-y');
      expect(status.earliest_event_iso).not.toBeNull();
      expect(status.latest_event_iso).not.toBeNull();

      const serialized = JSON.stringify(status);
      expect(serialized).not.toContain('alice');
      expect(serialized).not.toContain('secret-project');
      expect(serialized).not.toContain('other-project');
    } finally {
      store.close();
      try { fs.unlinkSync(dbPath); } catch { /* best-effort cleanup */ }
      for (const s of getDbSidecarPaths(dbPath)) {
        try { fs.unlinkSync(s); } catch { /* best-effort cleanup */ }
      }
    }
  });

  it('lists WAL/SHM sidecars when they exist', () => {
    const dbPath = tmpDb('sidecars');
    const store = new TelemetryStore(dbPath);
    try {
      store.recordUsage({
        provider: 'anthropic',
        model: 'm',
        inputTokens: 1,
        outputTokens: 1,
      });

      const status = store.getDataStatus(dbPath);
      const walExists = fs.existsSync(`${dbPath}-wal`);
      if (walExists) {
        const found = status.sidecars.find(s => s.path === `${dbPath}-wal`);
        expect(found).toBeDefined();
      }
    } finally {
      store.close();
      try { fs.unlinkSync(dbPath); } catch { /* best-effort cleanup */ }
      for (const s of getDbSidecarPaths(dbPath)) {
        try { fs.unlinkSync(s); } catch { /* best-effort cleanup */ }
      }
    }
  });

  it('exportUsageEvents and exportSessionEvents return rows with HMAC cwd digests', () => {
    const dbPath = tmpDb('export');
    const store = new TelemetryStore(dbPath);
    try {
      store.recordUsage({
        provider: 'anthropic',
        model: 'm',
        cwd: '/home/x/proj',
        inputTokens: 7,
        outputTokens: 3,
        source: 'unit',
      });
      store.recordSession({
        eventType: 'apply',
        cwd: '/home/x/proj',
        linesAccepted: 4,
      });

      const usage = store.exportUsageEvents();
      const sessions = store.exportSessionEvents();

      expect(usage).toHaveLength(1);
      expect(usage[0].cwd).toMatch(/^[a-f0-9]{64}$/);
      expect(usage[0].cwd).toBe(sessions[0].cwd);
      expect(usage[0].source).toBe('unit');
      expect(usage[0].input_tokens).toBe(7);

      expect(sessions).toHaveLength(1);
      expect(sessions[0].event_type).toBe('apply');
      expect(sessions[0].lines_accepted).toBe(4);
    } finally {
      store.close();
      try { fs.unlinkSync(dbPath); } catch { /* best-effort cleanup */ }
      for (const s of getDbSidecarPaths(dbPath)) {
        try { fs.unlinkSync(s); } catch { /* best-effort cleanup */ }
      }
    }
  });
});
