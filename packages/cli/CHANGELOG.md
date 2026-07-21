# @vaultcompass/vault-guard

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

### Patch Changes

- Updated dependencies [0a8d125]
  - @vaultcompass/vault-guard-core@1.3.0
  - @vaultcompass/vault-guard-telemetry@1.3.0

## 1.2.3

### Patch Changes

- Updated dependencies
  - @vaultcompass/vault-guard-core@1.2.3
  - @vaultcompass/vault-guard-telemetry@1.2.3

## 1.2.2

### Patch Changes

- Windows CI unit-test job, GitHub Actions pin updates (checkout v7, CodeQL 4.37), and `better-sqlite3` 12.11 for telemetry.
  - @vaultcompass/vault-guard-core@1.2.2
  - @vaultcompass/vault-guard-telemetry@1.2.2

## 1.2.1

### Patch Changes

- Align `vault-guard init` GitHub Actions workflow template with v1.2.0 action pin. Includes post-release CI and public-repo hygiene fixes (hash-only name guard, generic test fixtures).
  - @vaultcompass/vault-guard-core@1.2.1
  - @vaultcompass/vault-guard-telemetry@1.2.1

## 1.2.0

### Minor Changes

- 47c7004: Add `vault-guard init` for one-command repository setup: config, CI workflow, agent guardrail files, pre-commit hook, manifest-based revert, dry-run, and conflict-safe (no-overwrite) behavior.

### Patch Changes

- @vaultcompass/vault-guard-core@1.2.0
- @vaultcompass/vault-guard-telemetry@1.2.0

## 1.1.2

### Patch Changes

- fa2a45d: Flush structured scan output before returning a non-zero exit code.

  Large `scan --format json` and `scan --format sarif` runs can produce enough
  stdout that forcing `process.exit(1)` immediately after writing findings may
  truncate the output. CLI commands now set `process.exitCode` instead, preserving
  the same shell status while letting Node drain stdout and stderr normally.

  - @vaultcompass/vault-guard-core@1.1.2
  - @vaultcompass/vault-guard-telemetry@1.1.2

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

- Updated dependencies [c358939]
  - @vaultcompass/vault-guard-core@1.1.1
  - @vaultcompass/vault-guard-telemetry@1.1.1

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

### Patch Changes

- Updated dependencies
- Updated dependencies
  - @vaultcompass/vault-guard-core@1.1.0
  - @vaultcompass/vault-guard-telemetry@1.1.0
