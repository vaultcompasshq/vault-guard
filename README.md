# Vault Guard

Security and optimization layer for AI-native coding. Stop committing secrets, track token usage, and code safer with AI tools.

## Install

```bash
npm install -g @vaultcompass/vault-guard
```

## Usage

### Scan for secrets

```bash
vault-guard scan .
```

Scans your codebase for API keys, tokens, and other secrets.

**Staged files only** (fast, matches what you are about to commit):

```bash
vault-guard scan --staged
```

**Machine-readable output** (SARIF for GitHub Code Scanning, or JSON):

```bash
vault-guard scan . --format sarif
vault-guard scan . --format json
```

Structured JSON/SARIF includes a **`run`** block (timing, files/bytes scanned, active pattern count, optional baseline suppression counts). See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)** for what Vault Guard is meant to do versus dedicated history scanners.

#### Scripting & CI (stable JSON output)

For pipelines and scripts, **`--format json`** prints **one JSON object on stdout** (diagnostics may appear on stderr—parse stdout only). After `pnpm build`, invoke the **built** CLI so you always hit this workspace’s binary:

```bash
node packages/cli/dist/cli-entry.js scan /path/to/project --format json
```

From the monorepo root you can also use:

```bash
pnpm --filter @vaultcompass/vault-guard exec vault-guard -- scan /path/to/project --format json
```

If you use a **global** install (`npm install -g …`) *and* hack on this repo, check **`vault-guard --version`** — an older global binary can look like a formatting bug when stdout isn’t pure JSON.

Parse **`summary.secrets`**, **`results`**, and **`run`** as documented in **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

#### Many findings after an audit?

Vault Guard matches **credential-shaped strings** everywhere in the tree (including docs and `.example` files). A clean security review doesn’t always mean zero matches. Reduce intentional noise with **baseline fingerprints** (below), **`ignore`** in `.vault-guard.json`, and **[schemas/vault-guard-config.json](./schemas/vault-guard-config.json)**.

### Validate config

Structure plus `extra_patterns` compile / safety checks:

```bash
vault-guard config validate
```

JSON Schema for editors and external validators: **[schemas/vault-guard-config.json](./schemas/vault-guard-config.json)**.

**Baseline** (fingerprinted accepted findings — optional `.vault-guard.baseline.json` next to config):

```json
{ "version": 1, "fingerprints": ["<64-char sha256 hex from scan JSON>", "…"] }
```

Each `--format json` match includes a **`fingerprint`** field (SHA-256 of path + rule + location span; no raw secret). Copy values you accept into `fingerprints` to grandfather known findings while still failing on new ones.

### Compose with dedicated secret scanners

Vault Guard targets **fast working-tree** checks (IDE, pre-commit, CI on the checkout). For **credentials in Git history**, **verified** leaks, or **deeper** repos, run **[Gitleaks](https://github.com/gitleaks/gitleaks)** or **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** (or both) in the same pipeline — Vault Guard complements them; it does not replace them.

### Install pre-commit hook

```bash
vault-guard install-hook
```

Installs a Git hook that runs **`vault-guard scan --staged`** before each commit. Honors
`core.hooksPath` (including global `hooksPath` on your machine) so the hook lands where Git
actually executes it.

**Managers** (optional):

```bash
vault-guard install-hook --manager native     # default: Git hooks / hooksPath
vault-guard install-hook --manager husky      # .husky/pre-commit
vault-guard install-hook --manager lefthook   # lefthook-local.yml
vault-guard install-hook --manager precommit  # .pre-commit-config.yaml (only if absent)
```

Emergency bypass (discouraged): `git commit --no-verify`.

### Check token usage

```bash
vault-guard tokens
```

See how many tokens you're using and estimate costs.

### Quick check

```bash
vault-guard check src/api.ts
```

Check specific files for secrets.

### Statusline JSON

For Cursor CLI / custom status lines:

```bash
vault-guard statusline --json
```

Emits `secrets_today`, token totals, estimated spend, and last model from **local** `~/.vault-guard/usage.sqlite`.

### Model hint

```bash
vault-guard suggest-model --json
```

Uses recent local telemetry to suggest a model label (heuristic).

### Inspect / wipe local telemetry

```bash
vault-guard data status            # human-readable summary (no raw cwd values)
vault-guard data status --json     # same, machine-readable
vault-guard data reset             # interactive y/N prompt, then deletes the DB + WAL/SHM
vault-guard data reset --yes       # non-interactive (CI / scripts)
vault-guard data reset --dry-run   # preview without touching the filesystem
vault-guard data export -o ./my-telemetry.json
```

`status` reports counts only — never raw `cwd` strings. `export` writes a
mode-`0600` file. See **[docs/PRIVACY.md](./docs/PRIVACY.md)**.

### Anthropic proxy (opt-in)

```bash
vault-guard proxy --listen 127.0.0.1:8765
# optional: cap sustained POST /v1/messages to N requests per rolling 60s window
vault-guard proxy --listen 127.0.0.1:8765 --max-rpm 120
```

Forwards **`POST /v1/messages`** to `api.anthropic.com` and logs **`usage`** for non-stream JSON responses into the local SQLite DB. Point clients at `ANTHROPIC_BASE_URL=http://127.0.0.1:8765` when you explicitly want this behavior.

### MCP server

See **[docs/MCP.md](./docs/MCP.md)**. Run: `npx -y @vaultcompass/vault-guard-mcp` (stdio).

### VS Code / Cursor extension (Developer build)

Workspace package **`packages/vscode-extension`**: `pnpm --filter vault-guard-vscode build`, then **Run Extension** from VS Code for local tryout. This extension is currently a developer-only build and is not published to the marketplace.

## What it detects

- AI/ML API keys (Anthropic, OpenAI, HuggingFace, Replicate, `sk-proj-*`)
- Payment processors (Stripe, PayPal)
- Cloud providers (AWS access keys, context-anchored AWS secret keys, GCP, Azure storage)
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Version control tokens (GitHub classic + fine-grained PATs, GitLab, Bitbucket)
- Communication (Slack, Discord webhooks)
- SSH private keys, JWTs, and entropy-gated generic `api_key` / `secret` assignments

## GitHub Action

This repository ships a **composite action** at the repo root (`action.yml`). In your workflow:

```yaml
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: vaultcompasshq/vault-guard@v1.0.0 # or main / a tag you trust
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

Details: **`docs/GITHUB_ACTION.md`**. Branch protection and org checklist: **`docs/GITHUB_BRANCH_PROTECTION.md`**.

## Docker & Homebrew

- **Docker:** `docker/README.md` — image installs the published npm CLI.
- **Homebrew:** `packaging/homebrew/README.md` — optional tap workflow (npm remains canonical).

## Development

Requires **Node.js 20+** and **pnpm 9+** (see root `package.json` `engines`). Node 18 was dropped after `better-sqlite3@12` (used by the optional telemetry store) stopped shipping prebuilt binaries for it.

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install
pnpm build
pnpm test
pnpm lint
```

The workspace root is **`@vaultcompass/vault-guard-monorepo`** (private). Published npm packages include **`@vaultcompass/vault-guard`** (CLI), **`@vaultcompass/vault-guard-core`**, **`@vaultcompass/vault-guard-mcp`**, and **`@vaultcompass/vault-guard-telemetry`** under `packages/`. The VS Code extension package **`vault-guard-vscode`** is built from source for local or marketplace packaging.

## License

MIT

---

Vault Guard is built and maintained by [Vault & Compass](https://vaultcompass.io)
