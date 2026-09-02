// Simulates missing/incompatible `better-sqlite3` native bindings (e.g. a
// Windows install where node-gyp could not find Visual Studio, or an
// `--ignore-scripts` install). `better-sqlite3` is required lazily inside
// `store.ts` via `createRequire`, and jest.mock intercepts that require the
// same way it intercepts an ordinary top-level import.
jest.mock('better-sqlite3', () => {
  throw new Error('simulated missing native binding');
});

import * as os from 'os';
import * as path from 'path';
import { TelemetryStore } from '../store';

function tmpDbPath(label: string): string {
  return path.join(os.tmpdir(), `vg-telemetry-unavailable-${label}-${Date.now()}-${Math.random()}.sqlite`);
}

describe('TelemetryStore with better-sqlite3 unavailable', () => {
  it('constructs without throwing', () => {
    expect(() => new TelemetryStore(tmpDbPath('construct'))).not.toThrow();
  });

  it('reports isAvailable() false', () => {
    const store = new TelemetryStore(tmpDbPath('available'));
    expect(store.isAvailable()).toBe(false);
    store.close();
  });

  it('recordUsage is a silent no-op', () => {
    const store = new TelemetryStore(tmpDbPath('record-usage'));
    expect(() =>
      store.recordUsage({ provider: 'anthropic', inputTokens: 10, outputTokens: 5 }),
    ).not.toThrow();
    store.close();
  });

  it('recordSession is a silent no-op', () => {
    const store = new TelemetryStore(tmpDbPath('record-session'));
    expect(() => store.recordSession({ eventType: 'secret_blocked' })).not.toThrow();
    store.close();
  });

  it('getStatuslinePayload returns a zeroed payload, never throws', () => {
    const store = new TelemetryStore(tmpDbPath('statusline'));
    const payload = store.getStatuslinePayload();
    expect(payload).toMatchObject({
      secrets_today: 0,
      tokens_today_input: 0,
      tokens_today_output: 0,
      est_cost_usd: 0,
      model: null,
    });
    store.close();
  });

  it('suggestModel returns an empty suggestion, never throws', () => {
    const store = new TelemetryStore(tmpDbPath('suggest'));
    const suggestion = store.suggestModel();
    expect(suggestion.suggested_model).toBeNull();
    expect(suggestion.by_model).toEqual([]);
    expect(typeof suggestion.reason).toBe('string');
    store.close();
  });

  it('exportUsageEvents and exportSessionEvents return empty arrays', () => {
    const store = new TelemetryStore(tmpDbPath('export'));
    expect(store.exportUsageEvents()).toEqual([]);
    expect(store.exportSessionEvents()).toEqual([]);
    store.close();
  });

  it('getDataStatus reports zeroed counts without throwing', () => {
    const dbPath = tmpDbPath('data-status');
    const store = new TelemetryStore(dbPath);
    const status = store.getDataStatus(dbPath);
    expect(status.usage_events).toBe(0);
    expect(status.session_events).toBe(0);
    expect(status.earliest_event_iso).toBeNull();
    expect(status.latest_event_iso).toBeNull();
    store.close();
  });

  it('close() and closeAndCheckpoint() never throw', () => {
    const store = new TelemetryStore(tmpDbPath('close'));
    expect(() => store.close()).not.toThrow();
    const store2 = new TelemetryStore(tmpDbPath('checkpoint'));
    expect(() => store2.closeAndCheckpoint()).not.toThrow();
  });
});
