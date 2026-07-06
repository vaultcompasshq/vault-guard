# Vault Guard MCP

The package **`@vaultcompass/vault-guard-mcp`** exposes a stdio MCP server for editors and agents that support the [Model Context Protocol](https://modelcontextprotocol.io/).

## Tools

File and directory paths are resolved under the MCP server's launch directory.
Paths outside that workspace are rejected.

| Tool | Purpose |
|------|---------|
| `scan_workspace` | Scan a directory (`.gitignore`-aware). Returns `json`, `sarif`, and `summary`. |
| `scan_file` | Scan a single file path. |
| `scan_text` | Scan arbitrary UTF-8 (e.g. a proposed edit). Optional `virtual_path` for SARIF URIs. |
| `report_token_usage` | Rough on-disk token estimate for paths (no network calls). |
| `record_session_event` | Append an opt-in local row to `~/.vault-guard/usage.sqlite` (e.g. `secret_blocked`, `revert`). |

## Cursor / Claude Desktop

Add a server entry that runs the published binary (after `npm i -g @vaultcompass/vault-guard-mcp` or from a clone):

```json
{
  "mcpServers": {
    "vault-guard": {
      "command": "npx",
      "args": ["-y", "@vaultcompass/vault-guard-mcp"]
    }
  }
}
```

From a development clone, use `pnpm exec vault-guard-mcp` with `cwd` set to the repo you want to scan.

## Privacy

All telemetry written by `record_session_event`, the CLI **`vault-guard proxy`**, and **`vault-guard statusline`** stays on disk under **`~/.vault-guard/`** only. Nothing is sent to Vault & Compass servers by these features.
