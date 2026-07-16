# Dogfood checklist — ship with Vault Guard

**Purpose:** Use Vault Guard on the machines where you build and release product repos, so secret scanning, MCP guardrails, and optional token telemetry are real before tagging a release.

**Audience:** Maintainers dogfooding Vault Guard against their own private product workspaces. This doc stays generic — no product codenames.

---

## Why

Market pressure on AI coding is shifting from “adopt agents” to **attribution**, **eval discipline**, and **boundaries**. Vault Guard’s job:

1. Block secrets before commit / before agent paste (false-approve = secret that should have been blocked).
2. Give MCP clients local scan tools before edits apply.
3. Optionally record Anthropic API token usage locally (`~/.vault-guard/usage.sqlite`) — never sent to Vault & Compass servers.

---

## Checklist

### A. Install on a ship machine

- [ ] Node.js 22+ available
- [ ] `npm install -g @vaultcompass/vault-guard` (or workspace `pnpm` link from a local clone)
- [ ] From a product repo root: `vault-guard init` (or `--dry-run` first)
- [ ] Confirm `.vault-guard.json`, pre-commit hook, and agent guardrail files under `.vault-guard/` exist
- [ ] Confirm init did not overwrite files you already customize

### B. MCP

- [ ] Follow [`docs/MCP.md`](MCP.md) for Cursor / Claude Code client config
- [ ] Smoke: propose an edit containing a fake API-key-shaped string → MCP scan reports a finding
- [ ] Smoke: clean markdown / docs → no false positive on committed `fixtures/clean`-style content

### C. Pre-commit

- [ ] Stage a file with a synthetic secret-shaped string → commit **blocked**
- [ ] Stage a clean file → commit allowed
- [ ] Hook works under your manager (native / Husky / Lefthook / pre-commit)

### D. Token telemetry (opt-in)

- [ ] Read [`packages/telemetry/README.md`](../packages/telemetry/README.md)
- [ ] Enable local proxy / telemetry only if you want Anthropic API cost visibility
- [ ] Tag sessions by repo or task id in your own notes (editor statusline payload is local-only)
- [ ] Confirm nothing is uploaded to a remote Vault & Compass endpoint

### E. Bench before release tags

From this repo:

```bash
pnpm build
pnpm bench
# or:
node bench/run.cjs --assert
```

- [ ] Precision / recall floors pass (`bench/README.md`)
- [ ] If adding fixtures: prefer generated secrets under `fixtures/secrets/` (gitignored); keep `fixtures/clean/` free of false positives
- [ ] Expand “false approve” cases when a real leak pattern slips past — treat as a product bug

### F. npm / Action release hygiene

- [ ] Before publish: run workspace publish guardrails (no accidental `.map` / full `src/` in tarball) — see org infra notes for the shared script
- [ ] GitHub Action / SARIF path verified per [`docs/GITHUB_ACTION.md`](GITHUB_ACTION.md)
- [ ] Version tags follow your normal release process (`CHANGELOG` / changesets as applicable)

---

## Session habit (lightweight)

After a day of agent-assisted work on a product repo:

1. Note which repo / task burned the most tokens (if telemetry on).
2. Note any secret blocks (good) or misses (file as bench fixture).
3. Do **not** let agents own production secret paste, live payment flips, or unattended prod migrations — human gate those.

---

## Related

- [`README.md`](../README.md) — quickstart
- [`docs/MCP.md`](MCP.md)
- [`docs/PRODUCT_SCOPE.md`](PRODUCT_SCOPE.md)
- [`bench/README.md`](../bench/README.md)

## Related backlog

See `docs/BACKLOG.md` for Jul 16, 2026 audit suggestions (marketplace extension, Windows companion, Homebrew, init conflict guidance).
