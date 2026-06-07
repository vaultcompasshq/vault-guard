# Vault Guard: product scope

Vault Guard is a **local-first guardrail** for AI-assisted development: catch high-signal secrets before commit, estimate token usage from disk, optional local telemetry, and an opt-in Anthropic HTTP forwarder. It is **not** a full replacement for dedicated secret scanners that mine Git history, dependency graphs, or binary artifacts at scale.

## In scope

- **Working-tree secret patterns**: regex + entropy heuristics on files you scan (CLI, pre-commit, MCP, GitHub Action on checked-out trees).
- **Structured output**: JSON and SARIF with run metadata (`duration_ms`, `files_scanned`, `bytes_scanned`, `patterns_active`, diagnostics) for CI and Code Scanning.
- **Repository config**: `.vault-guard.json` (validated via `vault-guard config validate` and `schemas/vault-guard-config.json`).
- **Baseline / grandfather list**: `.vault-guard.baseline.json` stores **fingerprints** of accepted findings (same SHA-256 as each JSON match’s `fingerprint` field: path + rule + span; no raw secret material) so known noise can be suppressed while new issues still fail the gate.
- **Pre-commit ergonomics**: staged-file scan, hook installers, clear exit codes.
- **Compose, don’t compete**: pair with tools that specialize in history, blobs, and dependency provenance (see README “Compose with dedicated secret scanners”).

## Explicitly out of scope (use specialized tools)

- **Full Git history mining**: no `git log -p` / object-store secret archaeology; use [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog), or similar.
- **Dependency / supply-chain secret scanning**: no `package-lock.json` marketplace or npm tarball introspection as a first-class engine.
- **Generic malware / trust scoring**: not an antivirus or “is this package malicious?” product.
- **Hosted SaaS backend** for scanning (the OSS packages are local Node tooling).

## Baseline security note

Baseline entries are **intentional acknowledgements** of detector output at a location. They do not embed secrets, but they do weaken the guarantee for that (path, rule, span) until removed. Rotate baselines when files move or rules change materially.
