# External audit handoff — vault-guard (2026-06-11)

**Audience:** Future you, a new agent, or an outside reviewer picking up cold.  
**Snapshot:** `@vaultcompass/vault-guard@1.1.0` (all four published packages lockstep).  
**Repo:** `vaultcompasshq/vault-guard` · branch `main` · tag `v1.1.0` published.

## How to resume (owner preference)

No chat paste required. Each session:

1. `git pull origin main` in `vault-guard`
2. Read this file + `TODO.local.md` (gitignored personal backlog)
3. **Verify what's still relevant** against live state:
   - `npm view @vaultcompass/vault-guard version` (all four packages)
   - `gh pr list` (dependabot / open work)
   - `git log --oneline -10` (what landed since this snapshot)
   - `CHANGELOG.md` `[Unreleased]` (unshipped commits on main)
4. Treat sections below as **historical context** until step 3 confirms otherwise

---

## Verdict (outside looking in)

The engineering is **above average for a v1 security tool** and materially improved over the Jun 7–11 sprint. The headline audit defects that would embarrass a launch (broken streaming telemetry, npm tarball hygiene, version churn) are **closed**. What remains is **competitive parity** (git history, active verification) and **moat features** (MCP deny-gate, AI-config artifact rules) — multi-day items, not hygiene fixes.

**Safe to pause this week.** Next meaningful work is backlog-driven, not firefighting.

---

## Published state

| Package | npm version | Notes |
|---------|-------------|-------|
| `@vaultcompass/vault-guard` | 1.1.0 | CLI + proxy |
| `@vaultcompass/vault-guard-core` | 1.1.0 | Scanner engine |
| `@vaultcompass/vault-guard-mcp` | 1.1.0 | MCP server (esbuild bundle) |
| `@vaultcompass/vault-guard-telemetry` | 1.1.0 | SQLite telemetry (`better-sqlite3`) |

Release workflow (`release.yml`) green on `v1.1.0`: `check:pack` → publish → smoke test.

**Unreleased on `main` (post-tag):** `cf1aec9` — comment-only hardening in `secret-scanner.ts` warning not to re-add bare `sk-<N>` OpenAI pattern without entropy gate + bench FP guard. Rides next train per `CONTRIBUTING.md`.

---

## Original external audit — disposition

| # | Sev | Finding | Status |
|---|-----|---------|--------|
| 1 | High | Proxy records 0 tokens for streaming SSE | **Fixed** `v1.1.0` — `proxy-sse.ts`, bounded tee, `proxy-stream` / `proxy-stream-overflow` |
| 2 | Med | Source maps shipped to npm | **Fixed** `v1.0.6` — `sourceMap`/`declarationMap` false + `check:pack` |
| 3 | Med | Test helper in production tarball | **Fixed** `v1.0.6` — exclude `**/__tests__/**` |
| 4 | Med | Premature 1.0 + churn (7 versions in a week) | **Mitigated** `v1.1.0` — changesets, lockstep `fixed` group, `CONTRIBUTING.md` train |
| 5 | Low | OpenAI `/sk-[48]/` misses current formats | **Fixed** `v1.1.0` — `T3BlbkFJ` watermark rules for proj/svcacct/admin/legacy |
| 6 | Low | ReDoS static-only for `extra_patterns` | **Acknowledged** — needs `re2` phase; documented in `regex-safety.ts` |

### Deliberate trade-off (OpenAI #5)

Pre-2023 bare `sk-<48 alphanumerics>` keys **without** the `T3BlbkFJ` watermark are **intentionally not matched**. Matches gitleaks/trufflehog consensus: bare `sk-` floods false positives; watermark is the discriminator. Documented in `packages/core/src/scanners/secret-scanner.ts` (commit `cf1aec9`).

---

## What actually shipped Jun 7–11 (version ladder)

| Version | Theme |
|---------|-------|
| 1.0.3 | README on all 4 npm packages; value props |
| 1.0.4 | MCP survives missing `better-sqlite3`; integration tests (6 total) |
| 1.0.5 | `resend-api` FP fix; bench fixtures |
| 1.0.6 | Publish hygiene; `scripts/check-pack.cjs` in CI + release |
| 1.1.0 | Streaming telemetry + OpenAI recall + release train (single minor, not more patches) |

Also merged: dependabot #48 (codeql-action), #45 (@types/node), #47 (esbuild 0.28).

---

## CI / quality gates (required on `main`)

- `test (22.x)` — full suite (~352 tests across packages)
- `lint` — ESLint
- `CodeQL`
- `bench` — `node bench/run.cjs --assert` (precision/recall floors; corpus 29 files, 100% P/R at 1.1.0)
- `check:pack` — no `.map`, `__tests__`, test helpers in tarballs

Local gate before push:

```bash
pnpm build && pnpm check:pack && pnpm lint && pnpm test && node bench/run.cjs --assert
```

---

## Operational gotchas (not obvious from README)

1. **Pre-commit hook** runs `vault-guard scan --staged`. Needs global binary on `PATH`; after `pnpm build`, run `chmod +x packages/cli/dist/cli-entry.js` if hook says command not found. Never `--no-verify` for real commits.

2. **`.vault-guard.json`** excludes `fixtures/**`, `bench/fixtures/**`, `**/__tests__/**` from scans — test/fixture files contain intentional secret-shaped strings.

3. **GitHub push protection** blocks committing contiguous `T3BlbkFJ` OpenAI-shaped strings. Release smoke fixture (`fixtures/release-smoke/leaked.ts`) uses **Anthropic** `sk-ant-` shape instead; still exercises detection in CI smoke.

4. **Bench secrets** are generated at runtime (`bench/generate-fixtures.cjs`) with fragmented literals so committed generator source is not flagged.

5. **Proxy cost** for streaming: `recordUsage` omits `estCostUsd`; `TelemetryStore` auto-computes via `calculateCost` when undefined (`store.ts` ~409–417). Old stream path incorrectly passed `estCostUsd: 0`, which suppressed that.

6. **TypeScript 6** upgrade attempted and reverted — `@types/node` resolution under pnpm breaks. Stay on TS 5.x until revisited.

---

## Competitive position (honest)

**Weak vs incumbents on:** git history depth (gitleaks), active key verification (truffleHog), npm distribution scale (secretlint/husky).

**Uncontested wedge:** edit-time / AI-agent scanning — MCP server, AI-key-first patterns, local proxy. Position as "secret guard for AI coding," not "another scanner."

**Do not market proxy/telemetry cost tracking** without verifying streaming rows in `~/.vault-guard/usage.sqlite` — that was the #1 bug and is now fixed, but worth a sanity check after any proxy change.

---

## Open backlog (prioritized)

*Relevance check 2026-06-11 after `git pull`: still accurate unless noted.*

### Done since this snapshot was written

- Root `CHANGELOG.md` synced for 1.1.0 (`d83fe49`)
- Dependabot **#48** codeql-action, **#45** @types/node, **#47** esbuild — merged

### Still relevant — soon

- Re-run OSS + Projects corpus scan against **@1.1.0** (last full report @1.0.2: `~/vg-oss-broad/scan-v102-npm.txt`)
- Ship or batch **`cf1aec9`** (OpenAI pattern comment-only; in `[Unreleased]` on main)
- Dependabot **#46** `ignore` 5→7 — runtime, two majors; read changelog + gitignore tests before merge (CI green ≠ safe)

### Still relevant — deferred dependabot

- **#28** ESLint 10 — lint fails on PR
- **#27** TypeScript 6 — known pnpm breakage
- Chalk v5 / ESM — no CVE on v4

### Quality / parity (own plans)

- OSS regression CI (pin 5–8 repos from `~/vg-oss-broad/`)
- Gitleaks parity gate (`pnpm bench --gitleaks`)
- ReDoS runtime bounding (`re2`) for user `extra_patterns`
- `ai-venture-studio` scan timeout (~93s)
- Test-file FP downgrades (named repos in `TODO.local.md`)

### Moat (owner sign-off each — see plan out-of-scope)

- Git history scan (`--since-commit`) — **strategy fork:** README says compose with gitleaks vs build
- Active AI-key `--verify` (cheap read-only vendor ping)
- MCP deny-gate + `.cursorrules` snippet
- `.claude/` `.cursor/` `.continue/` artifact detection
- `npx @vaultcompass/vault-guard init` autowire
- GitHub Action Marketplace listing

---

## Key files map

| Topic | Path |
|-------|------|
| Release process | `CONTRIBUTING.md` |
| Implementation plan (1.1.0, now shipped) | `docs/plans/2026-06-11-audit-remediation-1.1.0.md` |
| Detection rules (generated) | `docs/RULES.md` |
| SSE parser | `packages/cli/src/commands/proxy-sse.ts` |
| OpenAI patterns | `packages/core/src/scanners/secret-scanner.ts` |
| Pack guard | `scripts/check-pack.cjs` |
| Changesets config | `.changeset/config.json` |
| Personal backlog | `TODO.local.md` (gitignored) |

---

## Suggested agent behavior

Pull latest, read this file, diff against live `npm` / `gh pr list` / `git log`, then work only what is **still relevant**. Do not replay completed audit remediation or re-merge closed dependabot PRs.
