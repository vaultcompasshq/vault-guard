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
