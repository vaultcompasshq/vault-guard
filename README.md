# Vault Guard

**The security layer for AI-assisted coding.** Stop secrets from landing in your repo, whether you typed them or an AI agent pasted them.

```bash
npm install -g @vaultcompass/vault-guard
```

---

## Why Vault Guard

AI coding agents (Cursor, Claude Code, Copilot, …) are fast, and they routinely paste API keys, connection strings, and tokens directly into your editor. Vault Guard catches them before they reach a commit or a prompt:

- **MCP server**: gives Cursor, Claude Code, and other MCP clients local tools to scan proposed edits, files, and workspaces before changes are applied.
- **Pre-commit hook**: blocks staged files containing secrets across all hook managers (native, Husky, Lefthook, pre-commit).
- **GitHub Action**: integrates with Code Scanning via SARIF; one workflow step.

---

## Quickstart

### 0. One-command setup (recommended)

From your repository root:

```bash
vault-guard init
```

Creates `.vault-guard.json`, a GitHub Actions workflow, local agent guardrail files under
`.vault-guard/`, and a pre-commit hook. Preview changes first:

```bash
vault-guard init --dry-run
```

Init never overwrites existing files — resolve conflicts manually. To undo:

```bash
vault-guard init --revert
```

Merge `.vault-guard/mcp-snippet.json` into your editor MCP config (see step 1).

### 1. Protect your AI editor (MCP)

Add to your MCP config (`~/.cursor/mcp.json`, `claude_desktop_config.json`, etc.):

```json
{
  "mcpServers": {
    "vault-guard": {
      "command": "npx",
      "args": ["-y", "@vaultcompass/vault-guard-mcp"]
    }
  }
}
```

Vault Guard exposes `scan_text`, `scan_file`, and `scan_workspace` tools. Your AI agent can call them before applying any edit that touches secrets.

See **[docs/MCP.md](./docs/MCP.md)** for the full tool reference.

### 2. Block secrets at commit time

```bash
vault-guard install-hook
```

Installs a hook that runs `vault-guard scan --staged` before every commit. Honors `core.hooksPath` (including globally-configured hook paths). Supports all major managers:

```bash
vault-guard install-hook --manager native     # default: Git hooks / hooksPath
vault-guard install-hook --manager husky      # .husky/pre-commit
vault-guard install-hook --manager lefthook   # lefthook-local.yml
vault-guard install-hook --manager precommit  # .pre-commit-config.yaml (only if absent)
```

**Windows:** `scan`, `check`, MCP, and CI workflows are supported on Windows.
Native hook install writes a POSIX `pre-commit` script (Git for Windows runs it
via `sh`, same as Git Bash) plus an optional `pre-commit.cmd` for clients that
call `.cmd` hooks directly — `git.exe` does not use the `.cmd` file.
Husky/Lefthook/pre-commit managers still use their own runners. CI runs
`pnpm test:windows` (core + CLI unit tests, excluding hook/proxy integration).

Emergency bypass (discouraged): `git commit --no-verify`.

### 3. Scan a repo or file

```bash
vault-guard scan .
vault-guard scan --staged          # staged files only (fast, for CI / hooks)
vault-guard check src/api.ts       # single file
```

**Machine-readable output** (SARIF for GitHub Code Scanning, or JSON):

```bash
vault-guard scan . --format sarif
vault-guard scan . --format json
```

### What fails the build

Findings at or above the **`--fail-on` threshold** produce exit code 1. Everything
below it is still reported (text, JSON, SARIF) but does not break the gate.

```bash
vault-guard scan .                      # default: fail on medium and above
vault-guard scan . --fail-on critical   # only criticals block
vault-guard scan . --fail-on low        # block on anything (pre-1.4.0 behaviour)
vault-guard scan . --fail-on none       # advisory mode: report, never fail
```

The default is `medium` because the scanner deliberately downgrades findings to
`low` where they are usually not real leaks: generic patterns inside
`__tests__/`, `docs/`, `*.example` files, and public identifiers such as GCP
OAuth client IDs and Sentry DSNs. Set `"fail_on"` in `.vault-guard.json` to
change it repo-wide. The JSON `run` block reports both `fail_on` and
`blocking_matches`; gate on `blocking_matches`, not `summary.secrets`.

Structured output includes a `run` block (timing, files/bytes scanned, active pattern count, diagnostics). See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

---

## What it detects

- AI/ML API keys (Anthropic, OpenAI, Groq, OpenRouter, xAI, Perplexity, Mistral, DeepSeek, Together, Fireworks, LangSmith, HuggingFace, Replicate)
- Backend platforms (Supabase, Vercel Blob, PlanetScale, Doppler, Databricks, Cloudflare)
- Payment processors (Stripe live + test, PayPal)
- Cloud providers (AWS access keys, context-anchored AWS secret keys, GCP, Azure storage)
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Version control tokens (GitHub classic + fine-grained PATs, GitLab, Bitbucket)
- Communication (Slack webhooks + tokens, Discord webhooks)
- SaaS tokens (Notion, Airtable, Figma)
- SSH private keys, JWTs, and entropy-gated generic `api_key` / `secret` assignments

Full rule reference with severities: **[docs/RULES.md](./docs/RULES.md)**.

Note: `sk_live_` / `sk_test_` are used by both Stripe and Clerk and there is no
reliable discriminator in the key body, so a Clerk secret key is reported under
the `stripe` rule id. The finding is correct; only the vendor label may be off.

---

## How it compares

Vault Guard is **not** a history miner. It targets fast working-tree checks (the IDE, pre-commit gate, and CI on the checkout) and is designed to be composed with dedicated history scanners, not to replace them.

| Feature | Vault Guard | Gitleaks | TruffleHog | detect-secrets | GitHub Secret Protection | GitGuardian |
|---|---|---|---|---|---|---|
| Working-tree / staged-file scan | Yes | Yes | Yes | Yes | Push/PR focused | Yes |
| Git history mining | No | Yes | Yes | No | Hosted scanning | Yes |
| MCP / AI-agent scanning | Local MCP | No | No | No | Yes | Yes |
| GitHub Action (SARIF output) | Yes | Yes | No | No | Native platform | Yes |
| Pre-commit hook installer | Yes | Partial | No | Yes | No | Yes |
| Entropy gating on generic patterns | Yes | Partial | Yes | Yes | Provider-pattern focused | Yes |
| Config ignore paths / baselines | Yes | Yes | No | Yes | Platform-managed | Yes |
| Opt-in local token telemetry (Anthropic) | Yes | No | No | No | No | No |
| Local-only / no account required | Yes | Yes | Yes | Yes | No | No |

For credentials in Git history use **[Gitleaks](https://github.com/gitleaks/gitleaks)** or **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** alongside Vault Guard. They are complementary, not competing.


---

## Recommended stack

Use Vault Guard as the **local AI-edit firewall**, then compose with history scanners:

| Layer | Tool | Role |
|---|---|---|
| AI edits + staged files + CI checkout | **Vault Guard** (MCP, pre-commit, Action) | Fast working-tree gate; no account |
| Git history / deep local scan | [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline history + strong pre-commit rules |
| Verified / live-key audit | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Confirm credentials still work |

Vault Guard does **not** mine Git history — see [docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md). Pairing with Gitleaks/TruffleHog is the recommended production setup, not a competing choice.


---

## CI: GitHub Action

```yaml
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: vaultcompasshq/vault-guard@v1.0.0
        with:
          version: latest
          path: .
          format: sarif
          sarif-output: vault-guard-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vault-guard-results.sarif
```

Details: **[docs/GITHUB_ACTION.md](./docs/GITHUB_ACTION.md)**. Branch protection setup: **[docs/GITHUB_BRANCH_PROTECTION.md](./docs/GITHUB_BRANCH_PROTECTION.md)**.

---

## Configuration

Create `.vault-guard.json` at your repo root:

```json
{
  "fail_on": "medium",
  "ignore": {
    "paths": ["**/__tests__/**", "fixtures/**"]
  },
  "severity_overrides": {
    "jwt-token": "low"
  },
  "extra_patterns": [
    { "id": "my-internal-key", "regex": "INT-[A-Z0-9]{32}", "severity": "critical" }
  ]
}
```

JSON Schema for editor autocomplete: **[schemas/vault-guard-config.json](./schemas/vault-guard-config.json)**.

**Baseline**: fingerprint accepted findings so new issues still fail the gate:

```json
{ "version": 1, "fingerprints": ["<sha256 hex from scan JSON>", "…"] }
```

Each `--format json` match includes a `fingerprint` field. Copy values you accept into `.vault-guard.baseline.json`. See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

**Inline suppression:**

```ts
const key = "sk-ant-..."; // vault-guard: ignore-line
// vault-guard: ignore-next-line
const alsoFine = "...";
```

---

## Opt-in token telemetry (Anthropic only)

Vault Guard can log Anthropic token usage locally; useful if you want to see what the proxy costs day-to-day.

```bash
vault-guard proxy --listen 127.0.0.1:8765
```

Forwards `POST /v1/messages` to `api.anthropic.com` and logs `model`, `input_tokens`, `output_tokens`, and estimated cost to **`~/.vault-guard/usage.sqlite`** (local only; nothing is sent to Vault & Compass servers).

Set `ANTHROPIC_BASE_URL=http://127.0.0.1:8765` to route a client through it. See **[docs/PRIVACY.md](./docs/PRIVACY.md)** for the full schema, opt-out steps, and data retention policy.

**Note:** this feature is Anthropic-specific. Token usage from Cursor's built-in models, Copilot, and other providers is not captured.

Inspect or wipe the local data:

```bash
vault-guard data status             # counts only; no raw paths
vault-guard data export -o out.json
vault-guard data reset              # interactive prompt
vault-guard data reset --yes        # non-interactive (CI)
```

Statusline JSON (for custom editor status bars):

```bash
vault-guard statusline --json
# { secrets_today, tokens_today_input, tokens_today_output, est_cost_usd, model }
```

Model hint from recent telemetry:

```bash
vault-guard suggest-model --json
```

---

## VS Code / Cursor extension

Inline diagnostics for open files (uses `@vaultcompass/vault-guard-core`). Package lives in
`packages/vscode-extension`.

**Local tryout:** `pnpm --filter vault-guard-vscode build`, then **Run Extension** from VS Code.

**Marketplace:** packaging is ready (`vsce package` / `vsce publish`) — see
[packages/vscode-extension/README.md](./packages/vscode-extension/README.md). Publishing
requires the `vaultcompass` publisher token (maintainers only).

---

## Scripting & CI (stable JSON output)

`--format json` prints one JSON object on stdout (diagnostics on stderr; parse stdout only):

```bash
node packages/cli/dist/cli-entry.js scan /path/to/project --format json
```

Parse `summary.secrets`, `results`, and `run` as documented in **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

**If you are building a pass/fail gate, read `run.blocking_matches`, not `summary.secrets`.**
`summary.secrets` is a raw count of every finding in `results`, including ones below the
`--fail-on` threshold; it does not reflect the gate. `run.blocking_matches` is the count of
findings at or above the effective `fail_on` threshold and is exactly what drives vault-guard's
own exit code. An integrator gating on `summary.secrets` will fail builds that vault-guard itself
considers passing.

---

## Docker & Homebrew

- **Docker:** `docker/README.md`, image installs the published npm CLI.
- **Homebrew:** `packaging/homebrew/README.md`, optional tap workflow (npm remains canonical).

---

## Maintainer dogfood

Before tagging a release, run through **[docs/DOGFOOD.md](./docs/DOGFOOD.md)** — install on a ship machine, MCP + pre-commit smoke, optional telemetry, and `pnpm bench` / `node bench/run.cjs --assert`.

## Development

Requires **Node.js 22+** and **pnpm 9+**. (Node 20 reached EOL April 2026.)

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install
pnpm build
pnpm test
pnpm lint
```

Published packages: **`@vaultcompass/vault-guard`** (CLI), **`@vaultcompass/vault-guard-core`**, **`@vaultcompass/vault-guard-mcp`**, **`@vaultcompass/vault-guard-telemetry`**.

Run the precision/recall benchmark against the labeled fixture corpus:

```bash
node bench/run.cjs
```

---

## License

MIT, built and maintained by [Vault & Compass](https://vaultcompass.io)
