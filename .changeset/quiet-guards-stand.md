---
"@vaultcompass/vault-guard": patch
"@vaultcompass/vault-guard-core": patch
"@vaultcompass/vault-guard-mcp": patch
"@vaultcompass/vault-guard-telemetry": patch
---

Harden MCP workspace boundaries and fix reported scan locations.

MCP file, workspace, and token-report tools now reject paths outside the server
workspace, including traversal and symlink escapes. MCP workspace scans now also
honor `.vault-guard.json` ignore patterns.

Scan matches now distinguish display columns from absolute offsets, so CLI,
SARIF, and editor diagnostics point at the right line-relative column while
baseline fingerprints remain compatible with existing `.vault-guard.baseline.json`
entries.

The GitHub Action now runs Node 22 and always emits `results-file` before
returning the scanner exit code. `vault-guard check` now delegates to the normal
scan path so config and baselines apply consistently.
