# Security policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Send details to **security@vaultcompass.io** (or the contact listed on
[vaultcompass.io](https://vaultcompass.io) if that address changes). Include:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept if possible)
- Affected versions / components (`@vaultcompass/vault-guard` CLI,
  `@vaultcompass/vault-guard-core`, GitHub Action, etc.)

We aim to acknowledge receipt within **5 business days** and coordinate a fix
and disclosure timeline with you.

## Scope

In scope: secret handling bugs in Vault Guard, credential leakage in CI or
documentation, supply-chain issues in official packages and Docker images.

Out of scope: generic regex false positives (report as a normal issue unless
they cause a security boundary failure), third-party dependencies (report to
the upstream maintainer; we still welcome coordinated notification).

## npm provenance

Published `@vaultcompass/*` packages are built from this repository’s tagged
releases with **npm provenance** enabled where configured in CI.

## `vault-guard proxy` (MVP)

The optional local forwarder only targets **`https://api.anthropic.com`** (fixed
hostname — not a generic open proxy).

### Defaults are fail-closed

The proxy refuses two configurations by default. Both refusals exist because
the previous defaults made it trivial for a local process or a phishing page's
`fetch()` to spend the operator's Anthropic budget without consent
(*"confused-deputy via local LAN"*).

1. **Non-loopback bind.** Binding `0.0.0.0`, a LAN IP, or any address other
   than `127.0.0.1` / `localhost` / `::1` is refused unless you pass
   `--allow-public`. Combined with the fallback below, exposing the proxy on
   a network interface lets anyone reachable on that network use your API key.
2. **Env-key fallback.** If the inbound request omits `x-api-key`, the proxy
   returns `401 missing_api_key`. To opt into the legacy behaviour (read
   `ANTHROPIC_API_KEY` from the proxy host's environment when the caller does
   not present one), pass `--allow-env-fallback`.

Use `--allow-env-fallback` together with `--allow-public` only on a host
where you control every other process and the network is fully trusted; in
practice this is almost never the case on a developer workstation.

3. **Optional `--max-rpm`.** When set, the proxy returns HTTP `429` if more than
   that many `POST /v1/messages` requests arrive within a rolling 60-second
   window (per process). This is a coarse client-side guardrail against runaway
   loops or accidental parallel fan-out; it is not a substitute for Anthropic
   account limits or org-wide API governance.

### Memory + lifecycle

- Inbound request bodies are capped at 32 MB.
- Non-streaming upstream responses are **piped** to the client immediately
  (no full-body buffer on the wire). A separate **1 MB tee** is used to parse
  `usage` for telemetry; on tee overflow the wire pipe is unaffected and a
  `proxy-tee-overflow` row is recorded so the operator can see usage data is
  missing for that request.
- Streaming responses are forwarded byte-for-byte; per-frame SSE usage parsing
  is a planned follow-up — until then streaming requests are logged with
  `0/0` token counts (`source: 'proxy-stream'`).
- `SIGINT`/`SIGTERM` triggers a graceful shutdown: stop accepting new
  connections, drain inflight (5 s grace, then force-close), checkpoint and
  close the local SQLite store.

See `docs/THREAT_MODEL.md` for the full per-component threat model and
`docs/PRIVACY.md` for the local telemetry data flow.
