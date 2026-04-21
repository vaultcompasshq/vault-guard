# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `@vaultcompass/vault-guard-mcp` — stdio MCP server (`scan_workspace`, `scan_file`, `scan_text`, `report_token_usage`, `record_session_event`); plus **`vault-guard statusline`** and VS Code extension package **`vault-guard-vscode`** (inline diagnostics, status bar, allow-list snippet command). See **`docs/MCP.md`**.
- `@vaultcompass/vault-guard-telemetry` — local `~/.vault-guard/usage.sqlite` store, **`vault-guard suggest-model`** heuristic, and **`vault-guard proxy --listen`** (Anthropic `/v1/messages` forwarder MVP with `usage` logging for non-stream JSON).
- `SecretScanner.scanContent()` and shared **`formatJson` / `formatSarif`** in `@vaultcompass/vault-guard-core`.
- **`vault-guard scan --staged`** — scans only git-indexed (staged) files.
- Pre-commit hook respects `core.hooksPath` (local + global), installs `vault-guard scan --staged` with `set -e`, TTY re-attach, and `--no-verify` hint; optional **`--manager`** `native` | `husky` | `lefthook` | `precommit`.
- Git utilities in core: `getGitStagedFilePaths`, `isInsideGitWorkTree`.
- Repo hygiene: `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, Dependabot, CodeQL and OpenSSF Scorecard workflows, issue + PR templates.
- Distribution: root **`action.yml`** composite action, **`docker/`** image recipe, **`packaging/homebrew/README.md`**, **`docs/GITHUB_ACTION.md`**.

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
