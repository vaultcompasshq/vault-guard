---
"@vaultcompass/vault-guard": patch
"@vaultcompass/vault-guard-core": patch
"@vaultcompass/vault-guard-mcp": patch
"@vaultcompass/vault-guard-telemetry": patch
---

1.4.2 close-out: a handful of loose ends from the last release.

- `vault-guard init` was still writing a GitHub Actions workflow template
  pinned to `vaultcompasshq/vault-guard@v1.2.0`, three releases behind. It now
  pins the current release tag, and a test asserts the pin always matches the
  CLI's own package version so it cannot go stale again unnoticed.
- SARIF output had two defects: results were missing `partialFingerprints`
  (needed for GitHub Code Scanning to track a finding's identity across
  runs), and `artifactLocation.uri` could come out as an absolute path with
  backslash separators on Windows-style input, which is not a legal SARIF
  relative-reference URI. Both are fixed: results now carry the same
  fingerprint the JSON output already emits per finding, and the uri is
  always scan-root-relative with forward slashes.
- The JSON output documentation (README and docs/PRODUCT_SCOPE.md) now says
  plainly that a pass/fail gate must read `run.blocking_matches`, not
  `summary.secrets`. The first real integrator built its gate on
  `summary.secrets`, which ignores the fail_on threshold. The JSON shape is
  unchanged.
- `qs`, pulled in transitively through `@modelcontextprotocol/sdk` under the
  MCP package, resolved to a version with two moderate audit advisories.
  Pinned via pnpm.overrides to a patched version; `pnpm audit` is clean.
- `better-sqlite3` was a hard dependency of the telemetry package, which was
  in turn a hard dependency of the CLI and MCP packages, and it compiles
  from source. A Windows CI job with no Visual Studio build tools failed at
  install, before any test ran. `better-sqlite3` is now an optional
  dependency, loaded lazily, and every telemetry entry point (recording and
  reading) degrades to a no-op when the native binding is unavailable
  instead of throwing. The CLI, MCP server, and statusline all keep working
  with telemetry absent; nothing is recorded, and nothing warns on every
  command.
