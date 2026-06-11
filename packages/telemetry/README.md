# @vaultcompass/vault-guard-telemetry

Opt-in, **local-only** store for [Vault Guard](https://github.com/vaultcompasshq/vault-guard). Tracks Anthropic API token cost (via the local `vault-guard proxy`) and session events such as `secret_blocked`, `revert`, and `accept` in `~/.vault-guard/usage.sqlite`. Nothing is sent to Vault & Compass servers, and Cursor/Copilot built-in model usage is not captured.

## Install

```bash
npm install @vaultcompass/vault-guard-telemetry
```

Requires **Node.js 22+** and native `better-sqlite3` bindings (rebuilt automatically on `npm install`).

## Quickstart

```typescript
import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

const store = new TelemetryStore();

// Record Anthropic API usage (e.g. from a local proxy)
store.recordUsage({
  model: 'claude-sonnet-4-20250514',
  inputTokens: 1200,
  outputTokens: 340,
  estCostUsd: 0.0042,
});

// Record a session event (e.g. secret blocked in editor)
store.recordSession({
  eventType: 'secret_blocked',
  extra: { pattern: 'anthropic' },
});

// Statusline payload for editor integrations
const status = store.getStatuslinePayload();
// { secrets_today, tokens_today_input, tokens_today_output, est_cost_usd, model }
```

## Graceful degradation

If `better-sqlite3` bindings are missing (e.g. install with `--ignore-scripts`), catch `TelemetryUnavailableError` and skip telemetry features:

```typescript
import {
  TelemetryStore,
  TelemetryUnavailableError,
} from '@vaultcompass/vault-guard-telemetry';

try {
  const store = new TelemetryStore();
  console.log(store.getStatuslinePayload());
} catch (err) {
  if (err instanceof TelemetryUnavailableError) {
    // Telemetry optional; continue without it
  } else {
    throw err;
  }
}
```

## CLI usage (recommended for end users)

Most users interact with telemetry through the main CLI, not this package directly:

```bash
npm install -g @vaultcompass/vault-guard

vault-guard proxy --listen 127.0.0.1:8765   # Anthropic proxy + usage logging
vault-guard statusline --json
vault-guard data status
vault-guard data export -o usage.json
vault-guard data reset --yes
```

Set `ANTHROPIC_BASE_URL=http://127.0.0.1:8765` to route a client through the proxy.

## Privacy

All data stays on your machine under `~/.vault-guard/`. See [docs/PRIVACY.md](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/PRIVACY.md) for schema, retention, and opt-out steps.

## Main exports

| Export | Description |
|--------|-------------|
| `TelemetryStore` | SQLite-backed usage and session store |
| `TelemetryUnavailableError` | Missing/incompatible native bindings |
| `getDefaultDbPath` | Default `~/.vault-guard/usage.sqlite` path |
| `getTelemetryRetentionDays` | Configurable retention window |

## Documentation

- [GitHub repository](https://github.com/vaultcompasshq/vault-guard)
- [Privacy policy](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/PRIVACY.md)

## License

MIT. [Vault & Compass LLC](https://vaultcompass.io)
