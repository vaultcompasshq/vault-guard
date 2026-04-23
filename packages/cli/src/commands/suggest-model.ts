import { TelemetryStore, TelemetryUnavailableError } from '@vaultcompass/vault-guard-telemetry';

export function suggestModelCommand(options: {
  json: boolean;
  cwd?: string;
  language?: string;
}): void {
  let store: TelemetryStore;
  try {
    store = new TelemetryStore();
  } catch (e) {
    if (e instanceof TelemetryUnavailableError) {
      if (options.json) {
        process.stdout.write(
          `${JSON.stringify({ error: 'telemetry_unavailable', message: e.message }, null, 2)}\n`,
        );
      } else {
        process.stderr.write(`vault-guard suggest-model: telemetry unavailable — ${e.message}\n`);
      }
      return;
    }
    throw e;
  }

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
