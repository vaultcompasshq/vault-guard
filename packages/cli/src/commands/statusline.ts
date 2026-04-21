import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

export function statuslineCommand(asJson: boolean): void {
  const store = new TelemetryStore();
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
