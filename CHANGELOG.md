# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-06-02

### Fixed (false positives)

- **Expanded test/fixture path detection for path-aware severity downgrades.** Go
  `*_test.go`, Python `test_*.py` / `*_test.py`, `examples/` (and
  `example`/`samples`/`sample`), Celery-style `t/unit/` and `t/integration/`
  trees, directory segments ending in `test` (`caddytest/`, `integrationtest/`
  — excluding `contest/` and `latest/`), and `.env.example` / `.env.sample`
  templates are now treated as test/fixture paths. Generic patterns, DSNs, and
  SSH/JWT shapes downgrade to `low` instead of `high`/`critical` in these
  locations. Addresses OSS sweep noise on Terraform, Celery, Caddy, Strapi, and
  Gatsby example configs.
- **Documentation-site false positives.** Algolia search-only keys (32-char hex)
  and similar `api-key-generic` matches in `docs/`, `website/`, and doc config
  files (`algolia.js`, `docusaurus.config.js`) are suppressed. Generic patterns
  in documentation paths downgrade to `low` severity.
- **Docstring demo passwords.** Pydantic-style documentation literals such as
  `password='IAmSensitive'` are suppressed via the aggressive placeholder tier.

### Added

- Bench fixtures for Algolia docs config and docstring demo passwords.
- CLI startup warning when Node.js is below 22.

## [1.0.0] - 2026-06-05

### Fixed

- **`config.ignore.paths` / `config.ignore.patterns` now actually work.** These
  fields were declared in the config schema and type but were never consumed by
  the scan pipeline — a silent no-op since the feature was first added. Both
  fields now accept gitignore-style glob patterns and are applied uniformly to
  directory scans (`vault-guard scan <path>`) and staged-file scans
  (`vault-guard scan --staged`). Patterns are matched relative to the scanned
  root so that e.g. `packages/**/__tests__/**` works as expected from the repo
  root. `buildConfigIgnoreFilter` is exported from
  `@vaultcompass/vault-guard-core` for use in custom tooling.
- Added repo-root `.vault-guard.json` so `vault-guard` dogfoods its own ignore
  config on this repo (excludes `packages/**/__tests__/**` and `fixtures/**`
  from scans, preventing the pre-commit hook from blocking on synthetic test
  fixtures).

### Fixed (false positives)

- **Placeholder / example-value suppression.** Matched values that are obvious
  documentation samples or test fixtures are now dropped. A *standard* tier
  (markers such as `EXAMPLE`, `changeme`, `your_token_here`, plus pure
  character-repetition padding) applies to every pattern — this suppresses
  AWS's documented `AKIAIOSFODNN7EXAMPLE` key, for example. An *aggressive* tier
  (`test`, `sample`, `password`, …) applies only to the low-precision generic /
  password-assignment patterns so vendor-anchored keys keep full recall.
  Exposed as `isPlaceholderSecret()` from `@vaultcompass/vault-guard-core`.
- **Vendored / generated trees skipped by default.** File discovery now ignores
  `.yarn`, `vendor`, `.venv`/`venv`, `__pycache__`, `.mypy_cache`,
  `.pytest_cache`, `.gradle`, and `.svelte-kit` directories, plus minified /
  bundled single-file artifacts (`*.min.{js,mjs,cjs,css}`, `*.bundle.{js,mjs,cjs}`,
  `*.map`, `.pnp.cjs`, `.pnp.loader.mjs`). These are never hand-authored and were
  a major false-positive source (broad key shapes occur by chance inside large
  minified blobs). On a real `strapi` checkout this cut findings from 72 to 20
  with no loss of true positives.
- **Local / dev / example connection strings no longer flagged.** Database and
  Redis DSN patterns (`postgresql-url`, `mysql-url`, `mongodb-url`, `redis-url`)
  now suppress matches whose host is local/non-routable (`localhost`,
  `127.0.0.1`, a bare docker-compose service name like `mysql`, or a reserved
  TLD such as `.local`/`.test`), or whose password is an obvious
  placeholder/default (`pass`, `PASSWORD`, `root:root`, `${DB_PASSWORD}`, …).
  A real remote host with a real password is still flagged. This was the single
  largest real-world FP source: on a `prisma` checkout it cut findings from
  **147 (146 critical)** to **4**, all `low`. Exposed as
  `isNonSecretConnectionString()`.
- **Canonical jwt.io sample token suppressed.** The ubiquitous RFC 7519 / jwt.io
  example JWT (decodes to `sub: "1234567890"`, `name: "John Doe"`,
  `iat: 1516239022`) that appears in countless API docs is no longer reported.
  Real JWTs are unaffected. Exposed as `isSampleJwt()`.
- **Path-aware severity for credential-shaped strings in test/fixture paths.**
  Findings from generic-assignment, connection-string, and key/token patterns
  (`password-in-code`, `postgresql-url`, `ssh-private-key`, `jwt-token`, …) are
  downgraded to `low` severity — not suppressed — when the file lives in a test
  or fixture path (`__tests__/`, `tests/`, `*.test.ts`, `fixtures/`, `spec/`,
  …). Hard vendor-anchored API-key patterns (Anthropic, AWS, Stripe, GitHub, …)
  keep full severity everywhere. Previously this only applied to files over
  10 MB; it now applies on the normal scan path too. Exposed as
  `applyPathAwareSeverity()` / `isTestFilePath()`.
- **`password-in-code` no longer fires on compound identifiers.** A negative
  lookbehind prevents matching when `password` is the suffix of a larger key
  name (e.g. `email-reset-password: "…"` in i18n files). Only standalone
  `password = …` / `password: …` assignments match.
- **Generic-assignment patterns no longer flag function-call results.** The
  generic assignment patterns (`secret-generic`, `api-key-generic`,
  `password-in-code`) stop their value capture at `(`, so an unquoted value
  immediately followed by `(` is a callee identifier, not a literal secret.
  These are now suppressed — e.g. Django's
  `csrf_secret = _add_new_csrf_cookie(request)` was reported as a `high`
  hardcoded secret. The heuristic is scoped to those three patterns only;
  vendor- and context-anchored detectors (including the critical
  `aws-secret-context`) are explicitly excluded and keep full recall. Verified
  on Django/Flask/Gin/Caddy checkouts: cleared all remaining Python
  `secret-generic` false positives with no loss of recall.

### Added

- **`bench/` precision/recall harness.** A labeled fixture corpus (real-world
  true positives + false-positive candidates) plus `node bench/run.cjs`
  (`pnpm bench`) reporting Precision / Recall / F1 / Grade, with an optional
  `--gitleaks` side-by-side. Current score on the corpus: **100% / 100% / A**.

### Changed (BREAKING)

- **`engines.node` raised to `>=20.0.0`** on all publishable packages and the
  workspace root. CI matrix narrowed to Node **20.x / 22.x**. Reason:
  `better-sqlite3@12` (telemetry store) stopped shipping prebuilt binaries for
  Node 18 on Linux x64, leaving CI / installs broken without a build toolchain.

### Fixed

- **CI green again.** `pnpm/action-setup@v6` errors when both `with: version`
  and `package.json` `packageManager` are set; dropped `with.version: 9` from
  every workflow step. Also corrected a malformed
  `softprops/action-gh-release` SHA comment in `release.yml`.

### Added

- **`engines.npm` / `engines.pnpm`** (`>=9`) on all publishable packages
  (`@vaultcompass/vault-guard-core`, `@vaultcompass/vault-guard`,
  `@vaultcompass/vault-guard-mcp`, `@vaultcompass/vault-guard-telemetry`)
  alongside existing `engines.node` (`>=18`).
- **Release workflow smoke job** — after a tag publish, installs
  `@vaultcompass/vault-guard@<version>` from the public registry (with retry),
  runs `vault-guard scan` on `fixtures/release-smoke/`, and asserts a non-zero
  exit and `summary.secrets > 0` in JSON output.
- **Telemetry `cwd` privacy** — `usage_events.cwd` and `session_events.cwd`
  now store **HMAC-SHA256** digests (hex) using a per-machine key in
  `~/.vault-guard/salt` (mode `0600`). One-time migration rewrites legacy
  plaintext paths when the SQLite `user_version` pragma is below `2`.
- **Telemetry retention** — deletes rows older than **`VG_TELEMETRY_RETENTION_DAYS`**
  (default **90**; set to **`0`** to disable). Purge is throttled to at most
  once per hour per process; tests can set **`VG_TELEMETRY_RETENTION_TEST_NO_THROTTLE=1`**
  to disable the throttle.
- **`ignore` (npm) for `.gitignore` handling** in `@vaultcompass/vault-guard-core`
  — replaces the hand-rolled regex compiler in `file-utils.ts`. Nested
  ignore files are merged relative to the Git work tree (or filesystem root
  when no `.git/` is present). Cache entries are LRU-bounded and invalidated
  when any contributing `.gitignore` mtime changes; `clearGitignoreCache()` is
  exported for tests and long-lived hosts.
- **`scanTextFileAsync` / `scanTextFileSync`** — async scans stream UTF-8
  line-by-line when a file exceeds the size threshold so multi‑MB text files
  are not fully buffered (multi-line secrets may be missed in streaming mode).
  CLI and MCP use the async helper; sync returns empty matches for oversized
  files with a `file.too_large` diagnostic.
- **`SecretScanner.mergeChunkedMatches`** — dedupe helper for streamed scans.
- **`vault-guard data` command group** for managing the local telemetry
  database at `~/.vault-guard/usage.sqlite`:
  - `data status` — privacy-respecting summary (file path/size, row counts,
    distinct-value *counts*; never raw `cwd` strings). `--json` for
    machine-readable output.
  - `data reset` — deletes the SQLite database and its WAL/SHM/journal
    sidecars. Interactive `y/N` prompt by default; `--yes` for
    non-interactive use; `--dry-run` to preview. Refuses to proceed when
    stdin is not a TTY and `--yes` was not passed.
  - `data export` — dumps `usage_events` and `session_events` to a JSON or
    JSONL file with mode `0o600` (user-only).
- **Scan run metadata** — JSON and SARIF include optional `run` (`duration_ms`,
  `files_scanned`, `bytes_scanned`, `patterns_active`, `diagnostics_count`,
  optional `baseline_suppressed`); SARIF mirrors this under
  `runs[0].properties.vault_guard_run`. MCP scan tools emit the same fields.
- **`SecretScanner#getActivePatternCount()`** — reports how many built-in +
  extra patterns are active after `severity_overrides` / rejections.
- **Baseline file** — optional `.vault-guard.baseline.json` (version `1`,
  `fingerprints[]`) discovered with the same directory walk as config; JSON
  output includes a per-match **`fingerprint`** (SHA-256 of path + rule +
  span; no raw secret) for populating the baseline.
- **`vault-guard config validate`** — structural validation plus
  `SecretScanner` construction (fails if any `extra_patterns` are rejected).
- **`schemas/vault-guard-config.json`** — JSON Schema for `.vault-guard.json`.
- **`docs/PRODUCT_SCOPE.md`** — in-scope vs out-of-scope; README links and
  “compose with Gitleaks / TruffleHog” guidance.
- **`vault-guard proxy --max-rpm`** — optional rolling 60s cap; returns HTTP 429
  when exceeded.
- **CLI integration tests (`json-output`)** — contract coverage for `--format json`:
  invoking the built `packages/cli/dist/cli-entry.js`, stdout must be a single
  parseable JSON object for `fixtures/release-smoke/` (findings) and for a clean
  temporary directory (no findings).

### Documentation

- **README** — scripting / CI: stable JSON via `node packages/cli/dist/cli-entry.js`,
  `pnpm exec` variant, avoiding mixed global vs workspace CLI versions, and
  guidance when many matches remain after manual audits (baseline / ignore).

### Security

- **`action.yml` input validation.** All four GitHub Action inputs
  (`version`, `path`, `format`, `sarif-output`) are now passed through
  `env:` (which the shell expands at runtime) instead of `${{ ... }}`
  template substitution (which happens before the shell parses, defeating
  any amount of quoting). A dedicated validation step regex-checks each
  value before the `npx` invocation, rejects path-traversal (`..`) and
  absolute paths, and `--` separates `npx`'s flags from package args.
  Tracked threat: shell injection / npm dist-tag injection via attacker-
  controlled workflow inputs.
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

## [0.1.0] - 2026-04-11

Initial development baseline (secret scan, pre-commit hook, token helpers).
