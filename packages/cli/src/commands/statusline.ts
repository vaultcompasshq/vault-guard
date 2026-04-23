import { TelemetryStore, TelemetryUnavailableError } from '@vaultcompass/vault-guard-telemetry';

export function statuslineCommand(asJson: boolean): void {
  let store: TelemetryStore;
  try {
    store = new TelemetryStore();
  } catch (e) {
    if (e instanceof TelemetryUnavailableError) {
      if (asJson) {
        process.stdout.write(`${JSON.stringify({ error: 'telemetry_unavailable', message: e.message })}\n`);
      } else {
        process.stderr.write(`vault-guard statusline: telemetry unavailable — ${e.message}\n`);
      }
      return;
    }
    throw e;
  }

  try {
    const payload = store.getStatuslinePayload();
    if (asJson) {
      process.stdout.write(`${JSON.stringify(payload)}\n`);
      return;
    }
    process.stdout.write(
      `Vault Guard (today UTC): secrets=${payload.secrets_today} tokens in/out=${payload.tokens_today_input}/${payload.tokens_today_output} est_cost_usd≈${payload.est_cost_usd} model=${payload.model ?? '—'}\n`,
    );
  } finally {
    store.close();
  }
}
