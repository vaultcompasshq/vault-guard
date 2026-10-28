# Opt-in token telemetry (Anthropic only)

vault-guard can log Anthropic token usage locally; useful if you want to see what the proxy costs day-to-day.

```bash
vault-guard proxy --listen 127.0.0.1:8765
```

Forwards `POST /v1/messages` to `api.anthropic.com` and logs `model`, `input_tokens`, `output_tokens`, and estimated cost to **`~/.vault-guard/usage.sqlite`** (local only; nothing is sent to Vault & Compass servers).

Set `ANTHROPIC_BASE_URL=http://127.0.0.1:8765` to route a client through it. See **[PRIVACY.md](./PRIVACY.md)** for the full schema, opt-out steps, and data retention policy.

**Note:** this feature is Anthropic-specific. Token usage from Cursor's built-in models, Copilot, and other providers is not captured.

Inspect or wipe the local data:

```bash
vault-guard data status             # counts only; no raw paths
vault-guard data export -o out.json
vault-guard data reset              # interactive prompt
vault-guard data reset --yes        # non-interactive (CI)
```

Statusline JSON (for custom editor status bars):

```bash
vault-guard statusline --json
# { secrets_today, tokens_today_input, tokens_today_output, est_cost_usd, model }
```

Model hint from recent telemetry:

```bash
vault-guard suggest-model --json
```
