# Contributing to vault-guard

## Public repository hygiene

This repo is **public**. Never commit names, paths, or context from other Vault &
Compass products, private monorepos, or internal portfolio work.

**Do not put in committed files** (including tests, fixtures, changelogs, comments):

- Other product or venture codenames (e.g. internal app/repo names)
- Paths like `/Users/.../Projects/<private-app>/` or workspace scan notes
- Session handoffs, AVS control state, or `ai-venture-studio` venture metadata
- References to "portfolio" fixes tied to a specific private repo

**Use instead:** generic placeholders (`example-app/`, `my-service/`, `acme-corp/`)
and describe the *pattern* (e.g. "multi-env `.example` templates"), not the source repo.

Local-only notes belong in gitignored paths: `TODO.local.md`, `.local/`, `audit.md`,
`docs/sessions/`, `docs/plans/`.

Before opening a PR, search the diff for private product names and internal paths.
CI runs `pnpm check:private-names` on every PR.

## Release train

All four published packages (`@vaultcompass/vault-guard`, `-core`, `-mcp`,
`-telemetry`) are versioned in lockstep via [changesets](https://github.com/changesets/changesets).

### Rules

- One **minor** release every 2-4 weeks.
- **Patches** only for security fixes or correctness regressions — not features.
- No ad-hoc edits to `version` in `package.json`. Use the train.
- **Do not reset to 0.x.** Stability comes from cadence, not renumbering.

### Every change needs a changeset

```bash
pnpm changeset   # interactive; picks minor/patch + writes a .changeset/*.md
```

Use Conventional Commit-style summaries: `fix(proxy): ...`, `feat(core): ...`.

### Cutting a release

```bash
# 1. Accumulate changesets from all merged work, then:
pnpm version-packages    # bumps all 4 packages + writes CHANGELOG entries
git add -A && git commit -m "chore(release): vX.Y.Z"
git tag -a vX.Y.Z -m "vX.Y.Z: <one-line summary>"
git push origin main && git push origin vX.Y.Z
# The release.yml workflow publishes @latest automatically.
```

### Soaking risky work on @next

```bash
pnpm release:next   # publishes to @next dist-tag; does not touch @latest
```

Promote to `@latest` by tagging once the soak passes.

## Pre-commit hook

The project installs a `vault-guard` pre-commit hook that scans staged files.
It requires the global `vault-guard` binary:

```bash
npm i -g @vaultcompass/vault-guard
```

If a clean rebuild drops the exec bit, run:

```bash
chmod +x packages/cli/dist/cli-entry.js
```

Never bypass with `--no-verify`.

## CI gates (must pass before merge)

- `test (22.x)` — full test suite + coverage
- `lint` — ESLint
- `bench` — precision/recall regression gate (`node bench/run.cjs --assert`)
- `check:pack` — no source maps or test artifacts in any tarball

Run the full suite locally before pushing:

```bash
pnpm install && pnpm build && pnpm check:pack
node scripts/gen-rules-doc.cjs && git diff --exit-code docs/RULES.md
pnpm lint && pnpm test && node bench/run.cjs --assert
```

## Out of scope (separate plans)

Do not start these without a dedicated plan signed off by the repo owner:

- Git history scanning
- Active AI-key verification (`--verify`)
- MCP deny-gate
- `.claude/` `.cursor/` artifact detection rule
- `vault-guard init` one-command repo setup (see README Quickstart §0)
- GitHub Action Marketplace listing
- TypeScript 6 upgrade
