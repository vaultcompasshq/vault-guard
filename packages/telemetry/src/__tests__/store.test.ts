import * as os from 'os';
import * as path from 'path';
import { TelemetryStore } from '../store';

describe('TelemetryStore', () => {
  it('records usage and statusline aggregates by UTC day', () => {
    const dbPath = path.join(os.tmpdir(), `vg-telemetry-${Date.now()}.sqlite`);
    const store = new TelemetryStore(dbPath);
    try {
      store.recordUsage({
        provider: 'anthropic',
        model: 'claude-3-5-sonnet-20241022',
        cwd: '/tmp/proj',
        inputTokens: 1000,
        outputTokens: 500,
        source: 'test',
      });
      const line = store.getStatuslinePayload();
      expect(line.tokens_today_input).toBe(1000);
      expect(line.tokens_today_output).toBe(500);
      expect(line.model).toBe('claude-3-5-sonnet-20241022');
      expect(line.secrets_today).toBe(0);
      expect(line.est_cost_usd).toBeGreaterThan(0);
    } finally {
      store.close();
    }
  });

  it('counts secret_blocked session events for statusline', () => {
    const dbPath = path.join(os.tmpdir(), `vg-telemetry-${Date.now()}-2.sqlite`);
    const store = new TelemetryStore(dbPath);
    try {
      store.recordSession({ eventType: 'secret_blocked', cwd: '/x' });
      store.recordSession({ eventType: 'secret_blocked', cwd: '/y' });
      const line = store.getStatuslinePayload();
      expect(line.secrets_today).toBe(2);
    } finally {
      store.close();
    }
  });

  it('suggestModel picks a model when usage exists', () => {
    const dbPath = path.join(os.tmpdir(), `vg-telemetry-${Date.now()}-3.sqlite`);
    const store = new TelemetryStore(dbPath);
    try {
      store.recordUsage({
        provider: 'anthropic',
        model: 'model-a',
        inputTokens: 100,
        outputTokens: 50,
      });
      store.recordUsage({
        provider: 'anthropic',
        model: 'model-b',
        inputTokens: 10,
        outputTokens: 5,
      });
      const s = store.suggestModel({});
      expect(s.suggested_model).toBeTruthy();
      expect(s.by_model.length).toBe(2);
    } finally {
      store.close();
    }
  });
});
