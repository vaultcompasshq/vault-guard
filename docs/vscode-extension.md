# VS Code / Cursor extension

Inline diagnostics for open files (uses `@vaultcompass/vault-guard-core`). Package lives in
`packages/vscode-extension`. It is not published to a marketplace yet.

**Local tryout:** `pnpm --filter vault-guard-vscode build`, then **Run Extension** from VS Code.

**Marketplace:** packaging is ready (`vsce package` / `vsce publish`). See
[packages/vscode-extension/README.md](../packages/vscode-extension/README.md). Publishing
requires the `vaultcompass` publisher token (maintainers only).
