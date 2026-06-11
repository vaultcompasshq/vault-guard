# @vaultcompass/vault-guard

Security and optimization layer for AI-native coding. Catches API keys, tokens, and connection strings in your working tree before they reach a commit or an AI prompt.

## Install

```bash
npm install -g @vaultcompass/vault-guard
```

Requires **Node.js 22+**.

## Quickstart

**Scan a repo or file**

```bash
vault-guard scan .
vault-guard scan --staged          # staged files only (hooks / CI)
vault-guard check src/api.ts       # single file
```

**Block secrets at commit time**

```bash
vault-guard install-hook
```

**Machine-readable output (SARIF or JSON)**

```bash
vault-guard scan . --format sarif
vault-guard scan . --format json
```

## AI editor integration

Use the MCP server package for Cursor, Claude Desktop, and other MCP-capable editors:

```bash
npm install -g @vaultcompass/vault-guard-mcp
```

See [@vaultcompass/vault-guard-mcp](https://www.npmjs.com/package/@vaultcompass/vault-guard-mcp) for MCP config.

## Configuration

Create `.vault-guard.json` at your repo root to ignore paths, override severities, or add custom patterns. See the [full documentation](https://github.com/vaultcompasshq/vault-guard#configuration).

## Related packages

| Package | Purpose |
|---------|---------|
| [@vaultcompass/vault-guard-core](https://www.npmjs.com/package/@vaultcompass/vault-guard-core) | Programmatic scanning API |
| [@vaultcompass/vault-guard-mcp](https://www.npmjs.com/package/@vaultcompass/vault-guard-mcp) | MCP server for AI editors |
| [@vaultcompass/vault-guard-telemetry](https://www.npmjs.com/package/@vaultcompass/vault-guard-telemetry) | Opt-in local usage telemetry |

## Documentation

- [GitHub repository](https://github.com/vaultcompasshq/vault-guard)
- [Detection rules](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/RULES.md)
- [GitHub Action](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/GITHUB_ACTION.md)
- [Privacy & telemetry](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/PRIVACY.md)

## License

MIT. [Vault & Compass LLC](https://vaultcompass.io)
