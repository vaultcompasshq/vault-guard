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

**Consumer-visible exit-code change.** When a `--staged` run both finds a
secret AND could not read some staged file, it now exits 2 rather than 1.
The incomplete scan dominating is deliberate, because a run that skipped
files cannot report a complete finding set, but a script branching on `1`
alone will stop seeing the secrets-found signal in that case. Treat any
non-zero exit as a block; read `run.blocking_matches` and
`run.unscannable_files` to tell the two apart. The installed pre-commit
hooks were updated to match: on exit 2 they say the scan could not complete
and offer no `--no-verify` hint, since the check never ran.

A staged **submodule** pointer bump no longer blocks the commit. Its index
entry is a gitlink rather than a blob, so there is no content to scan;
`--ignore-submodules=all` drops it from the staged listing.

Staged paths are now rendered, serialized, ignore-matched and fingerprinted
against the **repository root** rather than the caller's working directory.
Running the hook from a subdirectory previously emitted absolute machine
paths in JSON `file` and SARIF `uri` for anything above that directory, and
made both `ignore` matching and baseline fingerprints depend on where the
hook was invoked from.
