---
'@vaultcompass/vault-guard': minor
'@vaultcompass/vault-guard-core': minor
'@vaultcompass/vault-guard-mcp': minor
---

**Ways the scanner reported clean over things it had not properly checked are closed.**
This is a minor release because each fix moves a result in the fail-closed
direction. The telemetry package has no change of its own; it is in the fixed
version group and is bumped with the others by that group, not by this file.

**Example keys in docs will now be flagged.** Vendor-anchored rules (Anthropic,
OpenAI, Stripe, AWS, GitHub, Slack and the rest) are no longer downgraded to
`low` in markdown files or `docs/`, `doc/` and `website/` directories. A live
key pasted into `CLAUDE.md`, `AGENTS.md` or a docs page now blocks, and so does
a documentation example shaped like a real vendor key. Write examples with the
documented placeholder words (`EXAMPLE`, `test`) or in a shape that does not
match a vendor rule. A PEM private key (`ssh-private-key`) is likewise no longer
downgraded on documentation or markdown paths; it is still downgraded under
test, fixture and locale paths. The rule counts a header as a key only when a
following line is at least 40 characters of mixed-case base64 holding a digit,
`+` or `/`, so prose that merely names the header is not reported as a key
(interior whitespace is no longer stripped when making that decision). Generic low-precision patterns (password
and generic key assignments, connection strings, JWTs) are still downgraded in
docs.

- **Path context is judged relative to a root, never on the absolute path.**
  A checkout under a directory named `docs`, `doc`, `website`, `examples`,
  `fixtures`, `tests` or anything ending in `test` (`/home/runner/work/docs/docs`,
  `/tmp/loadtest/repo`) used to downgrade PEM private keys and other
  low-precision findings to `low` and exit 0 when the scan target was absolute,
  the scan ran from an ancestor directory, the target was a file, or the run was
  `--staged`. The root is now the git work tree containing the target, or the
  target directory itself when there is no work tree (its parent for a file
  target). Directories above that root no longer count; directories between it
  and the file still do. Library callers pass the new `pathRoot` option to
  `SecretScanner.scan`, `SecretScanner.scanContent`, `scanTextFileAsync` and
  `applyPathAwareSeverity`.
- **UTF-16 files with a byte order mark are now scanned as text.** A key in a
  UTF-16LE or UTF-16BE file (PowerShell 5 redirection writes UTF-16LE with a BOM)
  was read as garbage and passed silently in every mode. A UTF-8 BOM is stripped.
  BOM-less UTF-16 is still not detected.
- **`--staged` no longer skips a blob because it contains a NUL byte.** A staged
  `.ts` file with a key and one NUL byte printed "No secrets found" and exited 0.
  Such blobs are now scanned as text, as directory mode already did. Only the
  binary extensions are skipped.
- **Exit 1 means findings only.** An invalid `.vault-guard.json`, an invalid
  `--fail-on`, an unknown `--format`, `--staged` outside a git repository, a
  Commander usage error (an unknown option or command, a missing required
  option) and an unexpected fatal error now exit 2 instead of 1. `--help`,
  `-h`, `help` and `--version` still exit 0. `init` with an unknown `--manager`
  value still exits 1; it is not a scan verdict and was left alone.
- **JSON file paths use forward slashes on Windows too.** The `file` field
  carried the platform separator (`src\a.ts`) on Windows; it is now `src/a.ts`
  on every OS, matching SARIF uris. Consumers that matched the backslash form
  on Windows need to expect forward slashes.
- **`fix` judges path context the same way `scan` does.**
- **README states exit 2 correctly.** JSON and SARIF documents are written when
  a staged scan ran but some files went unexamined (with
  `run.unscannable_files`), and not written when the run stopped before the scan.
