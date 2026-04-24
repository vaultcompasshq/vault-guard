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
| `cwd`          | TEXT    | HMAC-SHA256 hex (64 chars) of `process.cwd()` — see below          | **Low** — same path on this machine always maps to the same digest |
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
| `cwd`             | TEXT    | HMAC-SHA256 hex of `process.cwd()`                    | **Low** — digest only; see below                       |
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

If you have run the optional surface and want to inspect or wipe the data:

```bash
# See what's there (file location, size, row counts — no raw cwd values).
vault-guard data status
vault-guard data status --json   # machine-readable

# Export the raw rows (writes a 0600-mode file at the path you choose).
vault-guard data export -o ./my-telemetry.json
vault-guard data export -o ./my-telemetry.jsonl --format jsonl

# Delete the SQLite database and its WAL/SHM/journal sidecars. Interactive
# y/N prompt by default; pass --yes for non-interactive use, --dry-run to
# preview without touching the filesystem.
vault-guard data reset
vault-guard data reset --yes
vault-guard data reset --dry-run --json
```

`data reset` only touches the four files (`usage.sqlite`, `usage.sqlite-wal`,
`usage.sqlite-shm`, `usage.sqlite-journal`) — never the parent directory or
any other contents of `~/.vault-guard/`.

If `vault-guard` is not on your PATH or telemetry native bindings are
unavailable, the equivalent low-level command is:

```bash
rm -f ~/.vault-guard/usage.sqlite \
      ~/.vault-guard/usage.sqlite-wal \
      ~/.vault-guard/usage.sqlite-shm \
      ~/.vault-guard/usage.sqlite-journal
```

## Retention

On each telemetry write (and when a `TelemetryStore` is opened), rows
older than **`VG_TELEMETRY_RETENTION_DAYS`** (default **90**) are deleted from
both `usage_events` and `session_events`. The cutoff uses each row’s
`created_at` ISO timestamp. Set `VG_TELEMETRY_RETENTION_DAYS=0` to disable
automatic deletion (the database can grow without bound).

## What we are explicitly **not** doing

- No remote analytics, no error reporting, no user identifier, no machine
  fingerprint, no IP address logging.
- No outbound network traffic from the scanner under any circumstance.
- No background daemons. Every CLI invocation is a one-shot process.
- No reading of git history, branch names, or remote URLs.

## What you should know about `cwd` storage

The `cwd` column stores a **64-character lowercase hex string**:  
`HMAC-SHA256(utf8(process.cwd()), key)` where `key` is a **32-byte random value**
persisted at `~/.vault-guard/salt` (file mode `0600`, created on first use).

That means:

- The database does **not** contain your raw home directory or project folder
  names.
- The digest is still **per-machine**: copying `usage.sqlite` to another
  computer without the same `salt` file does not let someone recover paths,
  but **with** both files an offline brute-force guess against candidate paths
  is theoretically possible (mitigation: do not share `salt` alongside exports).

`vault-guard data export` emits the stored digests as-is (not plaintext paths).

## Vulnerability reporting

If you find a privacy bug — anything in this document is wrong, telemetry is
collected that we did not document, or the proxy ever sends data anywhere
other than `api.anthropic.com` — please follow the reporting process in
[`SECURITY.md`](../SECURITY.md). Do not file a public issue.
