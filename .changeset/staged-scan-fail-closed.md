---
'@vaultcompass/vault-guard': patch
'@vaultcompass/vault-guard-core': patch
'@vaultcompass/vault-guard-mcp': patch
'@vaultcompass/vault-guard-telemetry': patch
---

**`scan --staged` no longer reports success over files it never scanned.**
Two defects combined into a fail-open in the pre-commit gate.

First, the staged file list was read with a git command that honours
`diff.relative`, an ordinary repo config. With it set, `git diff --cached
--name-only` printed paths relative to the caller's working directory and
omitted every staged path above it, while the code resolved those paths as
if they were relative to the worktree root. Run from a subdirectory, the
scanner therefore missed staged files entirely and could not read the ones
it did see. `diff.relative` and `core.quotePath` are now forced off per
invocation, and staged paths resolve against the worktree root that git
reports rather than the caller's cwd, so no repository setting can change
which files the gate looks at.

Second, a staged file the scanner could not read was downgraded to a
warning, and the run still printed `SUCCESS: No secrets found` and exited
0. An unreadable staged file is now fatal: exit code 2, no success line, and
a message naming each file and why it could not be read. JSON and SARIF
carry the same fact as `run.unscannable_files` alongside the existing
error-severity `file.read_error` diagnostic.

A directory scan reports an unreadable file the same way but still exits on
findings only. Its file set is discovered rather than declared by git, and
unreadable entries in a walked tree are ordinary; `run.unscannable_files` is
there for integrators who want the stricter rule.
