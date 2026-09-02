# @vaultcompass/vault-guard-telemetry

Opt-in, **local-only** store for [Vault Guard](https://github.com/vaultcompasshq/vault-guard). Tracks Anthropic API token cost (via the local `vault-guard proxy`) and session events such as `secret_blocked`, `revert`, and `accept` in `~/.vault-guard/usage.sqlite`. Nothing is sent to Vault & Compass servers, and Cursor/Copilot built-in model usage is not captured.

## Install

```bash
npm install @vaultcompass/vault-guard-telemetry
```

Requires **Node.js 22+**. Native `better-sqlite3` bindings are rebuilt automatically on `npm install` where a prebuilt binary or a working compiler toolchain is available, but they are an **optional dependency**: if the install cannot produce them (for example a Windows machine without the Visual Studio build tools, or an `--ignore-scripts` install), the package still installs and still works. See "Graceful degradation" below.

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

`new TelemetryStore()` never throws, even when `better-sqlite3` native bindings are missing or incompatible. In that case the store quietly becomes a no-op: every `record*` call does nothing, and every `get*`/`export*`/`suggestModel` call returns an empty or zeroed result of the normal shape (an empty array, a statusline payload with every count at zero, a suggestion with `suggested_model: null`) instead of raising an error. There is no exception to catch and no per-call special case to write:

```typescript
import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

const store = new TelemetryStore();
store.recordUsage({ model: 'claude-sonnet-4-20250514', inputTokens: 1200, outputTokens: 340 });
console.log(store.getStatuslinePayload());
// Works identically whether or not better-sqlite3 loaded; with it missing,
// recordUsage recorded nothing and getStatuslinePayload reports all zeros.
```

Call `store.isAvailable()` when you specifically need to distinguish "telemetry is working" from "telemetry degraded to a no-op" (the CLI's `data status` and `data export` commands do this, since their whole purpose is inspecting telemetry and an all-zero result would otherwise look identical to "no usage yet"). `store.getUnavailableReason()` returns the underlying reason as a string, or `null` when available. `TelemetryUnavailableError` stays exported for callers that inject their own loader (tests, or a factory such as the MCP server's `telemetryFactory`) and want to signal the same failure mode themselves; the store no longer throws it internally.

A missing native binding is noted at most once per process, and only when `VG_DEBUG=1` is set in the environment. Telemetry is opt-in local tooling, so it must never print a warning on every command (this matters most for `statusline`, which an editor can invoke every few seconds).

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
