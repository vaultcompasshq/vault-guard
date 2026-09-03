---
'@vaultcompass/vault-guard': patch
'@vaultcompass/vault-guard-core': patch
'@vaultcompass/vault-guard-mcp': patch
'@vaultcompass/vault-guard-telemetry': patch
---

**SARIF output no longer leaks absolute local paths.** `artifactLocation.uri`
is now relative to the scan root when the target sits outside the cwd
(`--staged` uses cwd itself); an in-checkout target's uri is unchanged.
Diagnostic ctx in SARIF notifications -- dir/path/file fields and
free-form error text -- gets the same treatment, so scan warnings no
longer carry absolute paths into the document either. JSON output is
unchanged; its `file` paths stay cwd-relative.

Covered by unit tests on both formatters and end-to-end scans of an
in-tree and an out-of-tree target (one with an unreadable subdirectory),
asserting no absolute path appears anywhere in the emitted document.
