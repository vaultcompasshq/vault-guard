---
"@vaultcompass/vault-guard": minor
"@vaultcompass/vault-guard-core": minor
"@vaultcompass/vault-guard-mcp": minor
"@vaultcompass/vault-guard-telemetry": minor
---

Windows hook companion, staged-index scan fix, init conflict guidance, and 1.3.0 docs.

Native `install-hook` / `init` write an optional `pre-commit.cmd` beside the POSIX
`pre-commit` (Git for Windows still runs the extensionless hook via sh).
`scan --staged` reads index blobs so staged-then-deleted or partially staged secrets
are not skipped. `vault-guard init` detects Husky/Lefthook/pre-commit layouts,
conflicts on foreign `.cmd` files, and refreshes the companion without overwriting
foreign hooks. README adds a recommended stack (Vault Guard + Gitleaks + TruffleHog)
and clarifies Windows hook behavior. TokenCounter uses `path.extname` on the basename
so temp dirs with dots no longer mis-bucket files.
