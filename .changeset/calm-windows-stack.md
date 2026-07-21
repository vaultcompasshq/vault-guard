---
"@vaultcompass/vault-guard": minor
"@vaultcompass/vault-guard-core": minor
"@vaultcompass/vault-guard-mcp": minor
"@vaultcompass/vault-guard-telemetry": minor
---

Windows pre-commit.cmd companion, init conflict guidance, and 1.3.0 docs.

Native `install-hook` / `init` now write a Windows `pre-commit.cmd` alongside the
POSIX `pre-commit` script. `vault-guard init` detects Husky/Lefthook/pre-commit
framework layouts and prints merge guidance without overwriting files. README
adds a recommended stack (Vault Guard + Gitleaks + TruffleHog); VS Code
extension packaging is Marketplace-ready. TokenCounter extension parsing uses
`path.extname` on the basename so temp dirs with dots no longer mis-bucket files.
