---
"@vaultcompass/vault-guard": patch
---

Flush structured scan output before returning a non-zero exit code.

Large `scan --format json` and `scan --format sarif` runs can produce enough
stdout that forcing `process.exit(1)` immediately after writing findings may
truncate the output. CLI commands now set `process.exitCode` instead, preserving
the same shell status while letting Node drain stdout and stderr normally.
