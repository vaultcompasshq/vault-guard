# @vaultcompass/vault-guard-core

## 1.4.2

### Patch Changes

- 46409ac: 1.4.2 close-out: a handful of loose ends from the last release.

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
    relative for files under the scan root, with forward slashes.
  - The JSON output documentation (README and docs/PRODUCT_SCOPE.md) now says
    plainly that a pass/fail gate must read `run.blocking_matches`, not
    `summary.secrets`. The first real integrator built its gate on
    `summary.secrets`, which ignores the fail_on threshold. The JSON shape is
    unchanged.
  - `qs`, pulled in transitively through `@modelcontextprotocol/sdk` under the
    MCP package, resolved to a version with two moderate audit advisories.
    Pinned via pnpm.overrides to a patched version; this repo's own
    `pnpm audit` is clean. That override only cleans this repo's own audit,
    though: a downstream consumer of the published MCP package still gets
    `qs` 6.16.0 by ordinary semver range resolution, not by any guarantee.
    The durable fix is an `@modelcontextprotocol/sdk` bump once one ships
    with a patched `qs` in its own dependency tree.
  - `better-sqlite3` was a hard dependency of the telemetry package, which was
    in turn a hard dependency of the CLI and MCP packages, and it compiles
    from source. A Windows CI job with no Visual Studio build tools failed at
    install, before any test ran. `better-sqlite3` is now an optional
    dependency, loaded lazily, and every telemetry entry point (recording and
    reading) degrades to a no-op when the native binding is unavailable
    instead of throwing. The CLI, MCP server, and statusline all keep working
    with telemetry absent; nothing is recorded, and nothing warns on every
    command.

## 1.3.0

### Minor Changes

- 0a8d125: Windows hook companion, staged-index scan fix, init conflict guidance, and 1.3.0 docs.

  Native `install-hook` / `init` write an optional `pre-commit.cmd` beside the POSIX
  `pre-commit` (Git for Windows still runs the extensionless hook via sh).
  `scan --staged` reads index blobs so staged-then-deleted or partially staged secrets
  are not skipped. `vault-guard init` detects Husky/Lefthook/pre-commit layouts,
  conflicts on foreign `.cmd` files, and refreshes the companion without overwriting
  foreign hooks. README adds a recommended stack (Vault Guard + Gitleaks + TruffleHog)
  and clarifies Windows hook behavior. TokenCounter uses `path.extname` on the basename
  so temp dirs with dots no longer mis-bucket files.

## 1.2.3

### Patch Changes

- fix(core): apply nested `.gitignore` files when scanning from an ancestor directory, and downgrade `gcp-oauth` to low severity (public client ID, not a secret).

## 1.2.2

## 1.2.1

## 1.2.0

## 1.1.2

## 1.1.1

### Patch Changes

- c358939: Harden MCP workspace boundaries and fix reported scan locations.

  MCP file, workspace, and token-report tools now reject paths outside the server
  workspace, including traversal and symlink escapes. MCP workspace scans now also
  honor `.vault-guard.json` ignore patterns.

  Scan matches now distinguish display columns from absolute offsets, so CLI,
  SARIF, editor diagnostics, and JSON output point at the right line-relative
  column. JSON output now includes `matches[].offset` for callers that need an
  absolute position. Baseline fingerprints remain compatible with existing
  `.vault-guard.baseline.json` entries.

  The GitHub Action now runs Node 22 and always emits `results-file` before
  returning the scanner exit code. `vault-guard check` now delegates to the normal
  scan path so config and baselines apply consistently.

## 1.1.0

### Minor Changes

- fix(core): broaden OpenAI key detection with T3BlbkFJ watermark — adds svcacct/admin/legacy

  The previous `openai` pattern (`sk-[a-zA-Z0-9]{48}`) was a fixed 48-char match
  from the pre-2024 key format. Modern OpenAI keys use a `T3BlbkFJ` watermark
  (base64 for "OpenAI") and come in four formats, all of which were missed:

  - `sk-proj-` — project-scoped key (the current default)
  - `sk-svcacct-` — service-account key for non-human identities
  - `sk-admin-` — org-wide admin key (cannot call inference APIs)
  - `sk-` (legacy) — pre-project user key with watermark at positions 20 and 40+

  Each format now has its own rule entry (distinct blast radius). The legacy `sk-`
  catch-all uses a token-boundary lookbehind and requires the watermark, preventing
  short/benign `sk-` identifiers from triggering false positives.

  Per-format recall tests and bench fixtures (TP + FP guard) are included.
  `docs/RULES.md` is updated to reflect the four OpenAI entries.

- fix(proxy): parse Anthropic SSE usage so streaming records real tokens and cost

  The proxy previously recorded `inputTokens: 0, outputTokens: 0` for all streaming
  responses (the "proxy-stream" telemetry source). Streaming is how Cursor and Claude
  Code actually send requests, so the cost-tracking value prop was non-functional for
  real traffic.

  The stream path now tees a bounded copy of the SSE body (same 1 MB cap as the
  non-streaming path) and parses token usage from the Anthropic SSE event stream:
  `message_start` carries `input_tokens`; the last `message_delta` carries cumulative
  `output_tokens`. The cost is computed automatically from the existing `calculateCost`
  table. If the tee cap is exceeded, a new `proxy-stream-overflow` source is recorded
  so missing usage is visible in telemetry.

  A new pure module `proxy-sse.ts` contains the parser; it is unit-testable without
  spinning up an HTTP server. The existing integration test that previously asserted
  the broken `inputTokens: 0` has been updated to assert real token counts.
