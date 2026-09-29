---
'@vaultcompass/vault-guard': minor
'@vaultcompass/vault-guard-core': minor
'@vaultcompass/vault-guard-mcp': minor
'@vaultcompass/vault-guard-telemetry': minor
---

**Four ways the scanner reported clean over things it had not properly checked are closed.**
This is a minor release because each fix moves a result in the fail-closed
direction.

**Example keys in docs will now be flagged.** Vendor-anchored rules (Anthropic,
OpenAI, Stripe, AWS, GitHub, Slack and the rest) are no longer downgraded to
`low` in markdown files or `docs/`, `doc/` and `website/` directories. A live
key pasted into `CLAUDE.md`, `AGENTS.md` or a docs page now blocks, and so does
a documentation example that is shaped like a real vendor key. Write examples
with the documented placeholder words (`EXAMPLE`, `test`) or in a shape that
does not match a vendor rule. Generic low-precision patterns (password and
generic key assignments, connection strings, JWTs) are still downgraded in docs.

- **Path context is judged relative to the scan root.** A checkout under a
  directory named `docs`, `doc`, `website`, `examples`, `fixtures`, `tests` or
  anything ending in `test` (`/home/runner/work/docs/docs`, `/tmp/loadtest/repo`)
  used to downgrade vendor-shaped keys and PEM private keys to `low` and exit 0
  when the scan target was absolute or the run was `--staged`. Directories
  above the scanned tree no longer count. Library callers pass the new
  `pathRoot` option to `SecretScanner.scan`, `SecretScanner.scanContent`,
  `scanTextFileAsync` and `applyPathAwareSeverity`.
- **`--staged` no longer skips a blob containing a NUL byte in silence.** A
  staged text-extension file with a key and one NUL byte printed "No secrets
  found" and exited 0. It is now recorded as unscannable (`file.nul_content`,
  counted in `run.unscannable_files`) and the run exits 2. Binary extensions
  are still skipped, as in directory mode.
- **Exit 1 means findings only.** An invalid `.vault-guard.json`, an invalid
  `--fail-on`, `--staged` outside a git repository, and an unexpected fatal
  error now exit 2 instead of 1. Anything that read exit 1 as "secrets found"
  no longer sees a leak where there is a configuration problem.
- **README states exit 2 correctly.** JSON and SARIF documents are written when
  a staged scan ran but some files went unexamined (with
  `run.unscannable_files`), and not written when the run stopped before the scan.
