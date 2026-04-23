# Vault Guard — Privacy

Vault Guard is **local-first**. No telemetry leaves your machine unless you
explicitly point a tool at a remote endpoint (which Vault Guard itself never
does).

If you only run `vault-guard scan` and `vault-guard install-hook`, no data is
collected at all. Telemetry is created only when you also use `vault-guard
proxy`, the MCP server, `vault-guard statusline`, or `vault-guard
suggest-model`.

---

## What is collected

A single SQLite database at `~/.vault-guard/usage.sqlite` (path is the user's
home directory; resolved with `os.homedir()`).

### Tables and columns

#### `usage_events`

Recorded by `vault-guard proxy` after every forwarded request, and by the MCP
`report_token_usage` tool when the caller invokes it.

| Column         | Type    | Source                                                            | PII risk                                              |
|----------------|---------|-------------------------------------------------------------------|-------------------------------------------------------|
| `created_at`   | TEXT    | UTC ISO timestamp                                                 | Low                                                    |
| `provider`     | TEXT    | `'anthropic'` / `'openai'` / `'unknown'`                          | None                                                   |
| `model`        | TEXT    | Echo of the model name (e.g. `claude-3-5-sonnet-20240620`)        | None                                                   |
| `cwd`          | TEXT    | `process.cwd()` at the time of the request                        | **Medium** — usually contains your OS username and project name |
| `input_tokens` | INTEGER | Token count from upstream `usage` block                           | None                                                   |
| `output_tokens`| INTEGER | Same                                                              | None                                                   |
| `est_cost_usd` | REAL    | Computed locally from token counts                                | None                                                   |
| `source`       | TEXT    | `'proxy'` / `'proxy-stream'` / `'proxy-tee-overflow'` / `'proxy-parse-failed'` / `'proxy-non-json'` / `'mcp'` | None |

#### `session_events`

Recorded by the MCP server and editor extensions when the user exposes
acceptance / revert events.

| Column            | Type    | Source                                                | PII risk                                              |
|-------------------|---------|-------------------------------------------------------|-------------------------------------------------------|
| `created_at`      | TEXT    | UTC ISO timestamp                                     | Low                                                    |
| `event_type`      | TEXT    | Free-form, e.g. `'apply'`, `'revert'`, `'secret_blocked'` | None                                                |
| `model`           | TEXT    | Model name                                            | None                                                   |
| `cwd`             | TEXT    | `process.cwd()`                                       | **Medium** — same caveat as above                      |
| `language`        | TEXT    | E.g. `'tsx'`, `'py'`                                  | None                                                   |
| `lines_accepted`  | INTEGER |                                                       | None                                                   |
| `lines_suggested` | INTEGER |                                                       | None                                                   |
| `lines_reverted`  | INTEGER |                                                       | None                                                   |
| `extra_json`      | TEXT    | Caller-supplied `Record<string, unknown>`             | **Caller-controlled** — anything an editor sends lands here |

## Where the data goes

Nowhere. The proxy targets `api.anthropic.com` for forwarding only; it does
not send telemetry to vault & compass servers, and there are no analytics
endpoints in this codebase. You can verify this with `rg -n "https?://" packages/`
and confirm the only outbound URL is the pinned Anthropic host plus
documentation links.

## How to opt out

The simplest opt-out is **don't run the optional surface**: skip `vault-guard
proxy`, don't connect the MCP server, and don't run `statusline` /
`suggest-model`. The scanning surface (`scan`, `install-hook`,
`pre-commit-hook`) creates no telemetry of any kind.

If you have run the optional surface and want the data gone:

```bash
# Wipe everything Vault Guard ever wrote locally.
rm -rf ~/.vault-guard/
```

There is no "off" toggle today; this is being addressed by the planned
`vault-guard data {status,reset,export}` subcommands (post-launch, see
`LAUNCH_PLAN` Phase 6).

## Retention

Today: **forever**. The SQLite database grows unbounded.

Planned: 90-day rotation, configurable via `VG_TELEMETRY_RETENTION_DAYS`.
Tracked as a post-launch task; this document will be updated when it ships.

## What we are explicitly **not** doing

- No remote analytics, no error reporting, no user identifier, no machine
  fingerprint, no IP address logging.
- No outbound network traffic from the scanner under any circumstance.
- No background daemons. Every CLI invocation is a one-shot process.
- No reading of git history, branch names, or remote URLs.

## What you should know about `cwd` storage

We store the working directory verbatim. On a developer machine, this is
typically:

```
/Users/<your-username>/Desktop/Projects/<your-project-name>
```

If you share your `~/.vault-guard/usage.sqlite` (e.g. attaching it to a
support ticket) you are sharing your username and your project names. Treat
the file the same way you would treat your shell history.

A planned change (post-launch) replaces the verbatim `cwd` with an HMAC-SHA256
of the path, salted with a per-machine random key written to
`~/.vault-guard/salt`. After that change, the column is useful for
"distinct repos used today" counts but not human-readable.

## Vulnerability reporting

If you find a privacy bug — anything in this document is wrong, telemetry is
collected that we did not document, or the proxy ever sends data anywhere
other than `api.anthropic.com` — please follow the reporting process in
[`SECURITY.md`](../SECURITY.md). Do not file a public issue.
