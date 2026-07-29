# Backlog

## Audit suggestions — Jul 16, 2026

**Status:** Published OSS CLI/MCP/Action; CHANGELOG at 1.2.3+. Dogfood notes live in `docs/DOGFOOD.md`.

- [x] **P0** Publish VS Code/Cursor extension to marketplace — packaging ready; maintainer `vsce publish` (see `packages/vscode-extension/README.md`)
- [x] **P0** Optional Windows `pre-commit.cmd` companion (docs: Git runs POSIX `pre-commit` via sh)
- [x] **P0** `scan --staged` reads git index blobs (covers AD / partial stage)
- [x] **P1** Short “recommended stack” section: compose with history scanners (see README)
- [ ] **P1** Harden Homebrew tap path beyond optional (`packaging/homebrew/`)
- [x] **P1** Expand `vault-guard init` conflict-resolution guidance for existing hook managers
- [ ] **P2** FAQ: Anthropic-only proxy/telemetry limits so adopters do not expect multi-provider
- [ ] **P2** MCP deny-gate / `scan_patch` (callable tools ≠ forced on every edit)
- [ ] **P2** Action Marketplace listing, Docker SBOM/signing, optional `--verify`

## Product audit — Jul 29, 2026

The premise held up. Gating at the point of the AI edit is a real gap that
history miners do not serve. What needed work was coverage and whether the gate
was usable day to day, not distribution. Shipped in 1.4.0:

- [x] **P0** `--fail-on` / `fail_on`, defaulting to `medium`. The `low`
      downgrades were decorative while any match exited 1.
- [x] **P0** Rules for the AI providers people use now (Groq, OpenRouter, xAI,
      Perplexity, Mistral, DeepSeek, Together, Fireworks, LangSmith). 16 of 17
      current key formats went undetected before this.
- [x] **P0** Backend and SaaS rules: Supabase, Vercel Blob, PlanetScale,
      Doppler, Databricks, Cloudflare, Notion, Airtable, Figma, Sentry DSN.
- [x] **P0** PKCS#8 private keys (`-----BEGIN PRIVATE KEY-----`) were never
      matched at all. Caught by dogfooding against public repos.
- [x] **P0** False positives: hyphenated `your-*` placeholders, unquoted
      variable references, password hashes, bare PEM headers, translation
      catalogues, `test-data` directories.
- [x] **P0** `bench/run.cjs` scored gitleaks at 0% recall because of a missing
      `--report-path`. Fixed, and the corpus is now labelled for what it is.
- [x] **P1** CI on Node 22/24/25; `better-sqlite3` to ^13 so Node 25 works.

### Still open

- [ ] **P1** Measure precision against a third-party corpus rather than our own
      fixtures. The dogfood run against ~82k files of public code is the start
      of this; it should be a repeatable script, not a one-off.
- [ ] **P1** Someone needs to own rule freshness on a schedule. Vendor key
      formats moved on and nothing caught it for about two years. Without a
      recurring review, 1.4.0's coverage decays exactly the same way.
- [ ] **P2** The `stripe` rule id also matches Clerk keys. Splitting it would
      invalidate existing baseline fingerprints, so it waits for a major.
- [ ] **P2** Surface `blocking_matches` in the GitHub Action summary so the
      threshold is visible in the PR check instead of buried in JSON.
- [ ] **P2** Decide whether the Anthropic-only token telemetry and proxy still
      earn their keep. They are the only native dependency in the tree, they
      caused the Node 25 breakage, and they sit well outside the scanning wedge.
