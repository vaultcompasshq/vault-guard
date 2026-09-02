import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

// TelemetryStore never throws: with better-sqlite3 unavailable,
// store.suggestModel() below returns { suggested_model: null, reason: '...',
// by_model: [] } rather than needing this command to special-case it.
export function suggestModelCommand(options: {
  json: boolean;
  cwd?: string;
  language?: string;
}): void {
  const store = new TelemetryStore();

  try {
    const s = store.suggestModel({ cwd: options.cwd, language: options.language });
    if (options.json) {
      process.stdout.write(`${JSON.stringify(s, null, 2)}\n`);
      return;
    }
    if (!s.suggested_model) {
      process.stdout.write(`${s.reason}\n`);
      return;
    }
    process.stdout.write(`Suggested model: ${s.suggested_model}\n${s.reason}\n`);
  } finally {
    store.close();
  }
}
