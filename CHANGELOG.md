# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`DiagnosticBus`** — every previously silent `catch {}` in the scanner, file
  walker, git helpers, and config loader now emits a typed diagnostic
  (`config.parse_error`, `file.too_large`, `fs.permission_denied`,
  `git.staged_files_failed`, `pattern.redos_unsafe`, …). Diagnostics surface in
  JSON output (`diagnostics[]`) and SARIF (tool/driver `notifications`), so a
  swallowed permission error or a corrupt `.vault-guard.json` no longer
  produces a misleading "✅ no secrets found".
- **Heuristic ReDoS gate on user-supplied `extra_patterns`** — length cap,
  quantifier-density cap, and shape checks for `(…[*+]…)[*+]` and
  `(.|.)[*+]`. Rejected patterns surface as `pattern.redos_unsafe` /
  `pattern.too_long` diagnostics rather than being silently dropped.
  `extra_patterns_unsafe: true` opts out of the heuristic; the length cap
  always applies as a memory-use backstop. Tracked threat: catastrophic
  backtracking from a malicious in-repo `.vault-guard.json`.
- **Pre-commit fails closed on git failure.** `getGitStagedFilePaths` now
  throws `GitError` instead of returning `[]` when `git diff --cached` fails.
  The pre-commit path catches it, exits **2**, and prints the failing command
  so a broken git environment can't masquerade as a clean commit.
- **Telemetry native bindings load lazily and degrade gracefully.**
  `better-sqlite3` is loaded with `createRequire` on first use; missing or
  ABI-mismatched bindings throw `TelemetryUnavailableError`. `statusline` and
  `suggest-model` catch this and exit cleanly; `proxy` lets it propagate
  (it is the primary writer and should fail loudly).
- **WAL checkpoint on proxy shutdown.** SIGINT/SIGTERM now triggers
  `wal_checkpoint(TRUNCATE)` before closing the SQLite handle, so usage rows
  written just before shutdown survive without WAL recovery surprises.

- **Tighter secret redaction in all output formats.** Matched values are now redacted
  to a 4-character prefix + length tag (e.g. `sk-a…(37c)`) instead of a 12-character
  prefix. The longer prefix could leak meaningful entropy for some vendor formats.
- **SARIF output no longer embeds the redacted value in the rule message.** The
  `region` (line, startColumn, endColumn) plus `ruleId` are sufficient for reviewers,
  and removing the value shrinks the leak surface when SARIF is uploaded to GitHub
  Code Scanning, attached to PRs, or shared in support tickets.
- **JSON and SARIF outputs now emit cwd-relative file paths** (paths outside the
  scan root remain absolute). Avoids leaking the developer's home directory and OS
  username when output is shared.
- Text output reformatted as `path:line:col` so editors auto-link to the exact
  location (iTerm2, Windows Terminal, VS Code, JetBrains all recognise this form).

### Added

- **`docs/RULES.md`** — generated from `BUILTIN_PATTERNS` via
  `scripts/gen-rules-doc.cjs`. CI fails if the file drifts from the source.
- **`docs/PRIVACY.md`** and **`docs/THREAT_MODEL.md`** — what
  `~/.vault-guard/usage.sqlite` actually stores, and the per-component
  threat model for CLI / proxy / MCP boundaries.
- `.github/dependabot.yml` — weekly npm + GitHub Actions updates, grouped
  by `@types/*`, eslint, and jest.
- `.gitattributes` — repo-wide `text=auto eol=lf` to keep Windows
  contributors from accidentally committing CRLF source files.
- Coverage thresholds in every package's `jest.config.js`, with
  `pnpm test:coverage` wired through `--workspace-concurrency=1` (proxy
  integration tests bind real ports).

- `@vaultcompass/vault-guard-mcp` — stdio MCP server (`scan_workspace`, `scan_file`, `scan_text`, `report_token_usage`, `record_session_event`); plus **`vault-guard statusline`** and VS Code extension package **`vault-guard-vscode`** (inline diagnostics, status bar, allow-list snippet command). See **`docs/MCP.md`**.
- `@vaultcompass/vault-guard-telemetry` — local `~/.vault-guard/usage.sqlite` store, **`vault-guard suggest-model`** heuristic, and **`vault-guard proxy --listen`** (Anthropic `/v1/messages` forwarder MVP with `usage` logging for non-stream JSON).
- `SecretScanner.scanContent()` and shared **`formatJson` / `formatSarif`** in `@vaultcompass/vault-guard-core`.
- **`vault-guard scan --staged`** — scans only git-indexed (staged) files.
- Pre-commit hook respects `core.hooksPath` (local + global), installs `vault-guard scan --staged` with `set -e`, TTY re-attach, and `--no-verify` hint; optional **`--manager`** `native` | `husky` | `lefthook` | `precommit`.
- Git utilities in core: `getGitStagedFilePaths`, `isInsideGitWorkTree`.
- Repo hygiene: `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Dependabot, CodeQL and OpenSSF Scorecard workflows, issue + PR templates.
- Distribution: root **`action.yml`** composite action, **`docker/`** image recipe, **`packaging/homebrew/README.md`**, **`docs/GITHUB_ACTION.md`**.

### Removed

- **`vault-guard monitor`** subcommand. The implementation was a stub that
  printed placeholder text; it has been removed from the CLI surface,
  command index, and tests rather than left as a misleading entry point.
  `vault-guard statusline --json` covers the live-status use case.

### Changed

- **CI / release:** `pnpm` **9** in workflows (matches lockfile v9); `pnpm/action-setup`, CodeQL, Scorecard, and `action-gh-release` pinned to commit SHAs; release job grants **`id-token: write`** for npm provenance; CI has **`workflow_dispatch`** and default **`permissions: contents: read`**.
- Root **`packageManager`**: `pnpm@9.15.9`; engines require **`pnpm >= 9`**.
- **`vault-guard proxy`:** max request/response buffer sizes; stderr warning when bind host is not loopback; **SECURITY.md** documents proxy threat model.
- Workspace root package renamed to `@vaultcompass/vault-guard-monorepo` (avoids clashing with the published CLI package name).
- CI builds before tests; lint failures fail the job; `pnpm audit` uses `--audit-level high`.
- GitHub Releases use `softprops/action-gh-release` with generated notes.
- CI / release workflows pin **`actions/checkout`**, **`actions/setup-node`**, and **`pnpm/action-setup`** to full commit SHAs. npm publish sets **`NPM_CONFIG_PROVENANCE=true`**.
- CLI `--version` reads from `packages/cli/package.json`.
- npm publish metadata: `files`, `publishConfig.access`, `repository`, `engines` on publishable packages.

### Fixed

- Tests build Stripe/Twilio-shaped strings via **template concatenation** so GitHub push protection does not block commits that contained contiguous `sk_live_*` / `sk_test_*` / `AC…` literals in fixtures.
- Jest resolves `@vaultcompass/vault-guard-core` from source in the CLI package so tests run without a prior `core` build.

## [1.0.0] - 2026-04-11

Initial published-line baseline (secret scan, pre-commit hook, token helpers).
