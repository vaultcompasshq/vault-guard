# @vaultcompass/vault-guard-mcp

[MCP](https://modelcontextprotocol.io/) server for [Vault Guard](https://github.com/vaultcompasshq/vault-guard). Gives Cursor and Claude the ability to scan a proposed edit before it lands, at edit time instead of commit time. One config line, fully local.

## Install

```bash
npm install -g @vaultcompass/vault-guard-mcp
```

Requires **Node.js 22+**.

## Quickstart (Cursor / Claude Desktop)

Add to your MCP config (`~/.cursor/mcp.json`, `claude_desktop_config.json`, etc.):

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

Restart the editor. Vault Guard tools are now available to your AI agent.

## Tools

| Tool | Purpose |
|------|---------|
| `scan_workspace` | Scan a directory (`.gitignore`-aware). Returns JSON, SARIF, and summary. |
| `scan_file` | Scan a single file on disk. |
| `scan_text` | Scan arbitrary UTF-8 text (e.g. a proposed edit). Optional `virtual_path` for SARIF URIs. |
| `report_token_usage` | Rough on-disk token estimate for paths (no network calls). |
| `record_session_event` | Append an opt-in local row to `~/.vault-guard/usage.sqlite` (e.g. `secret_blocked`, `revert`). |

## Example agent workflow

1. Before applying an edit, the agent calls `scan_text` with the proposed content.
2. If secrets are found, the agent warns the user or refuses to apply the change.
3. For repo-wide checks, use `scan_workspace` on the project root.

All scanning runs locally. No secrets or file contents are sent to external servers.

## Development (from a clone)

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install && pnpm --filter @vaultcompass/vault-guard-mcp build
```

Point MCP config at the local binary:

```json
{
  "mcpServers": {
    "vault-guard": {
      "command": "pnpm",
      "args": ["exec", "vault-guard-mcp"],
      "cwd": "/path/to/vault-guard"
    }
  }
}
```

## Privacy

Telemetry written by `record_session_event` stays on disk under `~/.vault-guard/` only. See [docs/PRIVACY.md](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/PRIVACY.md).

## Related packages

| Package | Purpose |
|---------|---------|
| [@vaultcompass/vault-guard](https://www.npmjs.com/package/@vaultcompass/vault-guard) | CLI (`vault-guard scan`, pre-commit hooks, proxy) |
| [@vaultcompass/vault-guard-core](https://www.npmjs.com/package/@vaultcompass/vault-guard-core) | Scanning engine used by this server |

## Documentation

- [Full MCP reference](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/MCP.md)
- [GitHub repository](https://github.com/vaultcompasshq/vault-guard)
- [Detection rules](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/RULES.md)

## License

MIT. [Vault & Compass LLC](https://vaultcompass.io)
