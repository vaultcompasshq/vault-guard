# Vault Guard for VS Code / Cursor

Inline secret diagnostics for open files, powered by
[`@vaultcompass/vault-guard-core`](https://www.npmjs.com/package/@vaultcompass/vault-guard-core).

## Features

- Scans the active editor for high-signal secret patterns
- Severity-mapped diagnostics (critical/high → error)
- Status bar hints via the `vault-guard` CLI (`vaultGuard.executable`)
- Command: **Vault Guard: Copy .vault-guard.json allow-list snippet**

## Requirements

- Node.js is not required inside the editor host for scanning (core is bundled).
- Optional: install the CLI for statusline integration:

```bash
npm install -g @vaultcompass/vault-guard
```

## Install (local / unpublished)

```bash
cd packages/vscode-extension
pnpm build
# Then: VS Code → Run Extension (F5), or:
npx @vscode/vsce package --no-dependencies
code --install-extension vault-guard-vscode-*.vsix
```

## Publish to Marketplace (maintainers)

1. Ensure you have access to the `vaultcompass` publisher on
   [Visual Studio Marketplace](https://marketplace.visualstudio.com/manage).
2. From repo root:

```bash
pnpm --filter vault-guard-vscode build
cd packages/vscode-extension
npx --yes @vscode/vsce login vaultcompass   # once
pnpm run package                   # npx @vscode/vsce package
pnpm run publish                   # npx @vscode/vsce publish
```

Use `--no-dependencies` because the extension bundles core via esbuild.

## Settings

| Setting | Default | Description |
|---|---|---|
| `vaultGuard.executable` | `vault-guard` | CLI on PATH for statusline JSON |

## Privacy

Scanning runs **locally** in the editor process. Nothing is sent to Vault & Compass servers.
See [docs/PRIVACY.md](../../docs/PRIVACY.md).
