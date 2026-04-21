# Vault Guard — Production Readiness Plan

_Last updated: 2026-04-21_

**Milestone status (in-repo):** **M0–M7 (marketing collateral + ops templates in-repo)** — same M2–M6 scope as before, plus **M7**: static **`marketing/index.html`** landing, **`docs/SCREENCAST.md`** storyboard, **`docs/AWESOME_LISTS.md`**, **`docs/DESIGN_PARTNERS.md`** (five-slot partner calendar template), **`docs/ISSUE_TRIAGE.md`**, and README “Adoption & marketing” links. **Still operator-owned:** publishing the site URL, recording/hosting the screencast, submitting awesome-list PRs, and booking five real partner calls. OpenSSF Scorecard **numeric** grade (≥ 8.5) is only meaningful after Scorecard has run on the default branch; M4 “three external repos using the Action” remains adoption work outside this repo._

This plan turns Vault Guard from “a working secret-scanner CLI” into a **production-ready, A/A+ across the board**, AI-coding-aware security & observability tool — with a credible path to GitHub popularity.

---

## 1. Audit summary — what it claims vs what it does

### Honest score (today)

| Category                          | Grade | Notes |
|-----------------------------------|:----:|-------|
| Secret detection (true positives) | **B+** | Catches the obvious (Anthropic, OpenAI, Stripe, GitHub, AWS access key, Slack/Discord webhooks, DB URLs, JWT, SSH private key, SendGrid, GCP). |
| Secret detection (false positives)| **D**  | Several patterns are catastrophically broad (see § 2). |
| Pre-commit hook                   | **C-** | Installs to `.git/hooks/pre-commit`, **silently no-ops** when `git config core.hooksPath` is set globally (real-world common). |
| Token tracking                    | **C-** | Estimates tokens of files on disk; **does not** track real AI tool usage (Cursor, Claude Code, etc.). Cost math hardcoded. |
| `monitor` command                 | **F**  | Stub: prints “coming soon.” |
| AI-tool integrations              | **F**  | None. README and tagline imply otherwise. |
| Distribution                      | **C**  | npm only; no Homebrew, no GitHub Action, no Docker, no MCP, no VS Code/Cursor extension. |
| Tests                             | **B+** | 93 tests, ts-jest, coverage thresholds set. After fixes in this PR, all pass. |
| CI / release                      | **B**  | Builds before tests; uses `softprops/action-gh-release@v2`; `pnpm publish -r --access public --no-git-checks`; `pnpm audit --audit-level high`. |
| Docs                              | **B-** | README + ARCHITECTURE; missing: roadmap, threat model, false-positive policy, CHANGELOG (added in this PR), governance, security policy. |
| Repo hygiene                      | **C+** | Missing: `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue/PR templates, Dependabot, CodeQL, `npm provenance`. |
| Brand / marketing                 | **C**  | Public name claims “AI-native” but product is mostly a generic regex secret scanner. |

### Concrete results from the live test fixture

Test fixture: `~/Desktop/Projects/vault-guard-test` — seeded **real-shaped fake** secrets in `src/api.ts`, `src/jwt.ts`, `.env`, `config/keys.json`, plus a deliberate **false-positive bait** file `src/safe.ts` (public GA IDs, public SSH key, git SHA, MD5 hash, Twilio Account SID, base64-shaped string, doc URL with auth).

Findings on `vault-guard scan .`:

- **Caught** every seeded real-shape secret (Anthropic, OpenAI, GitHub PAT, Stripe live + test, AWS access key, SendGrid, Slack, Discord, HuggingFace, all DB URLs, JWT, SSH private key, GCP service-account marker, Azure storage, inline password).
- **Reported 101 “secrets”** total — heavily inflated by **duplicate detections of the same string** across overlapping patterns and **broad regex false positives**.
- `src/safe.ts`, which had **zero** real secrets, was flagged repeatedly:
  - **GA IDs** `UA-12345678-1` and `G-ABCDEF1234` are **public**, not secrets.
  - **`ssh-ed25519 AAAA…`** public key flagged as `ssh-ed25519-public` (severity: medium) — public keys are not secrets.
  - **Git commit SHA** matched `cohere`, `aws-secret`, `circleci-token`, `jenkins-token`.
  - **MD5 hash** matched `jenkins-token`.
  - **Twilio Account SID** (publishable) flagged as `twilio-account` critical.
  - **Random 40-char base64-ish string** matched `cohere`, `aws-secret`, `circleci-token`.
  - **Doc URL with `user:pass@`** matched `elasticsearch-url` because the regex matches *any* `https://x:y@host:port`.
- **Pre-commit hook**: `install-hook` reported success but the hook **never ran** because the user has `core.hooksPath = ~/.git-hooks` set globally. A different unrelated global hook intercepted the commit. This is a **silent failure mode** that needs to be fixed.

### Patterns that need to change (root cause of the false-positive cliff)

In `packages/core/src/scanners/secret-scanner.ts`:

| Pattern key                | Regex (today)                                | Problem |
|----------------------------|-----------------------------------------------|---------|
| `cohere`                   | `[a-zA-Z0-9]{40}\b`                            | Matches **any** 40-char alphanumeric string (git SHAs, hashes). |
| `aws-secret`               | `[a-zA-Z0-9/+]{40}\b`                          | Matches **any** 40-char base64-ish string. |
| `circleci-token`           | `[a-zA-Z0-9_-]{40}`                            | Same — matches everywhere. |
| `jenkins-token`            | `[a-zA-Z0-9]{32}`                              | Matches **any** 32-char string (MD5, etc.). |
| `kubernetes-token`         | `eyJ…\.…\.…`                                   | Duplicate of `jwt-token`. |
| `elasticsearch-url`        | `https?://[^:]+:[^@]+@[^:]+:\d+`               | Catches **all** `user:pass@host:port` URLs, not specifically Elasticsearch. |
| `ssh-rsa-public` / `ssh-ed25519-public` | public key regex, severity `medium` | Public keys are **not secrets**. |
| `google-analytics` / `…-4` | `UA-…`, `G-…`                                  | Public publishable IDs. |
| `bearer-token` / `password-in-code` | broad assignment regex                | High false-positive rate; need entropy + context. |

---

## 2. What needs to change for A/A+

This is the prioritized plan. Each item lists exit criteria.

### A. Detection quality (P0 — biggest credibility win)

1. **Replace generic patterns with vendor-specific ones.**
   - Use the canonical [GitHub secret-scanning partner pattern list](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partners) as a source of truth.
   - Drop or rewrite: `cohere`, `aws-secret`, `circleci-token`, `jenkins-token`, `kubernetes-token`, `elasticsearch-url`.
   - Keep the curated list version-pinned in `packages/core/src/patterns/v1.ts`.
   - **Exit:** zero matches on `vault-guard-test/src/safe.ts`; ≥ 95 % recall on the seeded fixture.
2. **Add Shannon-entropy filter** for any "generic / catch-all" pattern (`api-key-generic`, `bearer-token`, `secret-generic`, `password-in-code`).
   - Threshold ≈ 3.5 bits/char for the matched substring; below → drop.
3. **De-duplicate overlapping matches** at the same `(file, lineRange)` — keep highest-severity / most-specific.
4. **Allow-list / suppress** with inline comments and a config file:
   - `// vault-guard: ignore-line` and `// vault-guard: ignore-next-line`.
   - `.vault-guard.yml` with `paths`, `patterns`, `entropy`, `severity-overrides`, `extra-patterns`.
5. **Demote / remove non-secret patterns**: `ssh-*-public`, `google-analytics*`. These either move to an opt-in **“public identifier hygiene”** lint or are deleted.
6. **Add `--format json|sarif`** so output integrates with GitHub Code Scanning, Code Climate, etc.
7. **Truffle-style verification** (optional, off by default): for keys we _can_ test (Stripe test, SendGrid, GitHub), add an opt-in `--verify` flag that pings the issuer’s `/me` style endpoint to confirm the key is **active**, then mark severity `confirmed`. Document the network egress.

### B. Pre-commit hook reliability (P0)

1. Detect `git config --get core.hooksPath` during `install-hook`. If set, **install into that path** (or refuse and tell the user how to add the snippet to their existing hook).
2. Support **Husky / Lefthook / pre-commit.com** out of the box: `vault-guard install-hook --manager husky|lefthook|precommit|native`.
3. Switch the default scan from `vault-guard scan` (entire workspace) to `vault-guard scan --staged` so the hook is fast and targeted.
4. Hook script template should `set -e`, `exec </dev/tty`, and provide a one-line bypass instruction (e.g. `git commit --no-verify`).

### C. AI-tool integration (P0 — the actual differentiator)

The current product ships nothing AI-specific even though the brand promises it. Add:

1. **MCP server** (`@vaultcompass/vault-guard-mcp`) exposing tools:
   - `scan_workspace`, `scan_file`, `scan_text` (returns SARIF-shaped JSON).
   - `report_token_usage`, `record_session_event`.
   - Make it work with **Cursor**, **Claude Code**, and **Claude Desktop** out of the box (single `npx @vaultcompass/vault-guard-mcp` line in their MCP config).
2. **Cursor / VS Code extension** (`vault-guard-vscode`)
   - Inline diagnostics for matched secrets.
   - Status-bar item: today’s **token spend** + **secrets blocked**.
   - One-click “add to `.vault-guard.yml` allow-list.”
3. **Statusline plugin** (`vault-guard statusline --json`)
   - Cursor CLI / Claude Code statusline support: emits `{ secrets_today, tokens_today_input, tokens_today_output, est_cost_usd, model }`.
   - Configurable as a CLI status-line per the editor’s docs.
4. **Token telemetry — real, not estimated**
   - Wrap `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` HTTP calls with an **opt-in** local proxy (`vault-guard proxy --listen 127.0.0.1:11434`) that records `model`, `input_tokens`, `output_tokens`, `cost`, and tags by `cwd`/repo.
   - Persist in `~/.vault-guard/usage.sqlite`. Pure local; never phones home.
5. **Coding-tool accuracy tracking**
   - Track per-session metrics: `acceptance_rate` (lines accepted / lines suggested), `revert_rate` (lines reverted within N minutes), `tests_passing_after_apply`.
   - Hook into Cursor / Claude Code via MCP `record_session_event`.
   - Show a weekly summary: “Sonnet 4.6 → 78 % accept, 9 % revert; Composer → 65 % / 22 %.”
6. **Model recommender**
   - Given the working file’s language, size, and recent revert rate, suggest which configured model to use (e.g. “Switch to Sonnet — your last 5 Composer attempts on `*.tsx` had 30 % revert rate”).

### D. Packaging & distribution (P1)

1. **Homebrew tap**: `brew install vaultcompasshq/tap/vault-guard`. Build static Node binary with [`@yao-pkg/pkg`](https://github.com/yao-pkg/pkg) or [Bun compile](https://bun.sh/docs/bundler/executables) for users who don’t want Node.
2. **GitHub Action**: `vaultcompasshq/vault-guard-action@v1` — drop-in for any repo:
   ```yaml
   - uses: vaultcompasshq/vault-guard-action@v1
     with:
       fail-on: critical,high
       sarif: vault-guard.sarif
   - uses: github/codeql-action/upload-sarif@v3
     with: { sarif_file: vault-guard.sarif }
   ```
3. **Docker image** `ghcr.io/vaultcompasshq/vault-guard:latest` (multi-arch).
4. **npm provenance** on publish (`pnpm publish --provenance`) for supply-chain trust.
5. **Reproducible builds** + **Sigstore / cosign** signing for binaries and Docker.

### E. Repo hygiene & security posture (P1)

1. Add `LICENSE` (MIT — already declared in `package.json`, but no `LICENSE` file exists at repo root).
2. Add `SECURITY.md` (responsible disclosure, contact, PGP key, scope).
3. Add `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
4. Add **issue templates** (`bug_report.yml`, `false_positive.yml`, `false_negative.yml`, `feature_request.yml`) and **PR template**.
5. Add `.github/dependabot.yml` (npm + actions).
6. Add **CodeQL** workflow (`github/codeql-action`).
7. Add **OpenSSF Scorecard** badge + workflow.
8. Add **branch protection** + `CODEOWNERS`.
9. Pin all third-party Actions to **commit SHAs**, not floating tags.

### F. Quality bar (P1)

1. **Coverage thresholds**: keep 80 % global, raise `secret-scanner.ts` to 95 %.
2. **Mutation testing** (Stryker) for the scanner.
3. **Benchmarks**: `vault-guard bench` with golden corpora (e.g. [`Yelp/detect-secrets`](https://github.com/Yelp/detect-secrets) test files); publish precision/recall/F1 in README and per release.
4. **Fuzzing** of pattern engine with `jazzer.js`.
5. **Performance budget**: scan a 100k-LOC repo in <2 s on M-series Macs (single-threaded Node 20). Add CI gate.

### G. Docs & community (P2)

1. Rewrite README around _one promise_: “the security & spend layer for AI-assisted coding.”
2. Add `docs/THREAT_MODEL.md`, `docs/FALSE_POSITIVES.md`, `docs/INTEGRATIONS.md`, `docs/ROADMAP.md`.
3. Landing page on `vaultcompass.io/vault-guard` with a 60-second screencast.
4. Comparison table vs `gitleaks`, `trufflehog`, `detect-secrets` — be honest, list what each does better.

---

## 3. Distribution & “tokens” questions you asked

- **Do you need to set up npm / pnpm tokens to install Vault Guard?** **No.** Anyone can `npm i -g @vaultcompass/vault-guard` once it’s published — npm install does not need authentication for public packages.
- **You only need an `NPM_TOKEN` to publish.** Steps:
  1. `npm login` (or create an **automation** access token in your npm account → Access Tokens → “Granular access token” scoped to the `@vaultcompass` scope, write).
  2. Add it as a repository secret in GitHub: **Settings → Secrets and variables → Actions → `NPM_TOKEN`**.
  3. Tag a release: `git tag v1.0.1 && git push --tags`. The `release.yml` workflow runs `pnpm publish -r --access public --no-git-checks` with `NODE_AUTH_TOKEN=${{ secrets.NPM_TOKEN }}`.
  4. (Recommended) Enable **`--provenance`** so the published package shows a verified GitHub Actions provenance link on npmjs.com.
- **Local pnpm doesn’t need a token.** It only needs one if you publish manually via `pnpm publish` from your laptop.

---

## 4. What problem does Vault Guard actually solve?

There are three jobs-to-be-done. Pick the one that becomes the wedge:

1. **“Don’t let me ship a secret an AI assistant pasted into my repo.”**  
   _Wedge: pre-commit + MCP scan-on-edit + diff-aware scanning._ This is where the AI-coding angle becomes real instead of cosmetic.
2. **“Tell me what my AI coding tools cost me and how good they are.”**  
   _Wedge: opt-in proxy + statusline + per-model accept/revert/cost dashboard._ Nobody owns this clearly today.
3. **“Give me a single place to enforce safe AI-assistant behavior in my repo.”**  
   _Wedge: `.vault-guard.yml` policies (e.g. “block commits that touch `.env`”, “warn when AI suggests adding a new dependency”), MCP tool-call audit log._

The **strongest** positioning is **(1) + (2) bundled**: _security AND spend visibility for AI-assisted coding_, because no existing tool occupies that combined slot.

---

## 5. Path to GitHub popularity

Concrete, in priority order:

1. **Publish a real benchmark** — “Vault Guard catches X / Y secrets vs gitleaks Y / Y on the [secret-scanning corpus]” with reproducible script in `bench/`. Most security tools get popular because the README has a credible chart.
2. **Ship the GitHub Action** with one-line install. SAST/secret tools snowball when CI integration is one copy-paste.
3. **Ship the MCP server** and submit it to:
   - Anthropic’s [MCP servers list](https://github.com/modelcontextprotocol/servers).
   - Cursor’s MCP catalog.
   - `awesome-mcp` lists.
4. **Get on `awesome-*` lists**: `awesome-security`, `awesome-pre-commit`, `awesome-claude`, `awesome-cursor`.
5. **Show, don’t tell**: a 90-second Loom titled “I asked Claude to add Stripe — Vault Guard caught it before commit.” Pin it to the README.
6. **Find the first 5 design partners** in the AI-coding influencer set (Latent Space, Theo, Fireship, …) — give them a personalized 20-minute walkthrough; ask only for an honest tweet if they like it.
7. **Triage every issue within 24 h** for the first 90 days. Velocity is the most undervalued growth channel for OSS dev tools.
8. **License + governance clarity** (MIT + `SECURITY.md` + `CODE_OF_CONDUCT.md`) so corporate users are comfortable adopting it.

---

## 6. Implementation milestones

| Milestone | Scope                                                                                                  | Target  | Exit criteria                                         |
|-----------|--------------------------------------------------------------------------------------------------------|---------|-------------------------------------------------------|
| **M0**    | This PR — workspace rename, CI/release fixes, Jest module-mapping, CHANGELOG, README polish.           | done    | green CI; `pnpm lint && build && test && audit` clean |
| **M1**    | § 2.A — pattern overhaul + entropy + dedupe + ignore directives + SARIF.                                | 1 week  | `vault-guard scan vault-guard-test` reports 0 false positives in `safe.ts`, ≥ 95 % recall elsewhere |
| **M2**    | § 2.B — `install-hook` respects `core.hooksPath`, supports husky/lefthook/precommit, `--staged` default | **done (impl)** | Jest coverage for native + managers; consumers must still validate Husky/Lefthook in real repos. |
| **M3**    | § 2.E + § 2.F — repo hygiene, CodeQL, Dependabot, Scorecard, npm provenance, benchmarks                 | **done (impl)** | Benchmarks / Scorecard **number** still optional follow-ups. |
| **M4**    | § 2.D — GitHub Action + Homebrew tap + Docker image                                                     | **done (impl)** | Root `action.yml` + `docker/` + tap **docs**; external adoption + `ghcr.io` publish still optional. |
| **M5**    | § 2.C — MCP server, Cursor extension MVP, statusline JSON                                               | 2 weeks | works in Cursor and Claude Code with one config line  |
| **M6**    | § 2.C — opt-in token proxy, accuracy tracking, model recommender                                        | 2 weeks | local `usage.sqlite` populated; weekly digest command |
| **M7**    | § 5 — landing page, screencast, awesome-list submissions, design-partner outreach                       | **done (in-repo)** | **In repo:** `marketing/index.html`, `docs/SCREENCAST.md`, `docs/AWESOME_LISTS.md`, `docs/DESIGN_PARTNERS.md` (5-row calendar template), `docs/ISSUE_TRIAGE.md`, README links. **You still:** deploy landing + link screencast + open list PRs + book 5 calls. |

---

## 7. Which model to use to implement this

You asked specifically: _“since it’s a free repo, can I make Composer implement what you recommend or do I need Sonnet?”_

| Milestone surface                                                          | Recommended model               | Why |
|----------------------------------------------------------------------------|---------------------------------|-----|
| **M0** (this PR) — config & metadata edits                                 | **Composer** is fine            | Mechanical, well-scoped. |
| **M1** Pattern overhaul + entropy + dedupe + ignore directives + SARIF      | **Sonnet 4.6 (Lead Developer)** | Cross-file refactor, regex correctness matters; Composer tends to leave broad patterns. |
| **M2** Hook reliability across husky/lefthook/precommit                     | **Sonnet 4.6**                  | Edge cases (`core.hooksPath`, Windows shells); needs careful design. |
| **M3** Repo hygiene (CodeQL, Dependabot, Scorecard, provenance, benchmarks) | **Composer** with checklist     | Boilerplate-heavy; verify with `act` locally. |
| **M4** GitHub Action / Homebrew / Docker                                    | **Composer**                    | Templates; let Sonnet review the final YAML. |
| **M5** MCP server + Cursor/VS Code extension                                | **Sonnet 4.6**, escalate hairy parts to **Opus 4.6 (Senior Security Architect)** | Protocol correctness + security boundary design. |
| **M6** Opt-in token proxy + accuracy tracking                               | **Opus 4.6**                    | Local privacy + threat model is the whole product; do not cut corners. |
| **M7** Landing/marketing                                                    | Any                             | Mostly content. |

**Bottom line:** ~70 % of this plan can be implemented by **Composer** with you reviewing diffs; the **detection-quality** work (M1) and the **AI-integration / proxy / threat-model** work (M5–M6) is where you should pay for **Sonnet 4.6** or **Opus 4.6**. Cheap models on broad regexes is exactly how the current false-positive cliff was created in the first place.

---

## 8. Open questions to decide before starting M1

1. Are we OK adding **`micromatch`** (or rolling our own) for `.vault-guard.yml` glob patterns? (Adds ~30 KB, justified.)
2. Are we OK on a small **runtime dep** to `chalk` for the CLI but **zero deps** for `core`? (Today: yes. Keep it.)
3. Should `--verify` (active-key probing) require `--explicitly-online` or is opt-in via flag enough?
4. How do we want to brand the **AI proxy** so users trust running it? (Open source, local-only by default, signed binary.)
5. Naming: keep `@vaultcompass/vault-guard` or rename now (e.g. `@vaultcompass/guard`) **before** the package gets adoption.
