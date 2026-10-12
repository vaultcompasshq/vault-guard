# Vault Guard: product scope

Vault Guard is a **local-first guardrail** for AI-assisted development: catch high-signal secrets before commit, estimate token usage from disk, optional local telemetry, and an opt-in Anthropic HTTP forwarder. It is **not** a full replacement for dedicated secret scanners that mine Git history, dependency graphs, or binary artifacts at scale.

## In scope

- **Working-tree secret patterns**: regex + entropy heuristics on files you scan (CLI, pre-commit, MCP, GitHub Action on checked-out trees).
- **Structured output**: JSON and SARIF with run metadata (`duration_ms`, `files_scanned`, `bytes_scanned`, `patterns_active`, diagnostics) for CI and Code Scanning. Integrators deciding pass/fail must read `run.blocking_matches` (findings at or above the effective `fail_on` threshold; this is what sets vault-guard's own exit code). `summary.secrets` is only a total finding count across the whole run, threshold or no threshold, and is not a pass/fail signal. `run.unscannable_files` (present when non-zero) counts files the run should have scanned and did not vouch for (unreadable, over the 32 MiB limit, over the per-file time budget, a tracked file missing on disk, a path named to `check` that does not exist), and `run.unscannable` lists them; while it is set the run exits 2 and a clean `blocking_matches` covers only the files that were actually examined. `run.config_ignored_files`, `run.binary_files_skipped` and, on a directory or pull-request scan, `run.type_filtered_files` count what the run declined to open, every run, even at zero. `run.baseline_suppressed` and `run.inline_suppressed` report how many findings were hidden by the baseline and by inline `vault-guard: ignore-line` / `ignore-next-line` directives; `inline_suppressed` is emitted every run (even at zero), and each file that suppressed a finding inline also carries a `suppression.inline` diagnostic naming the line numbers, because a suppression is the user's decision and must stay visible.
- **Repository config**: `.vault-guard.json` (validated via `vault-guard config validate` and `schemas/vault-guard-config.json`).
- **Baseline / grandfather list**: `.vault-guard.baseline.json`, written only by `vault-guard baseline --write`, stores accepted findings so known noise can be suppressed while new issues still fail the gate. Its `entries` list (read by 1.10.0 and later) keys each finding on its path from the repository root, its rule and a SHA-256 of the matched text (each JSON match's `content_fingerprint`), with a count and a severity bound; rules that match only a fixed marker are bound to a SHA-256 of the whole file's raw bytes instead. Its `fingerprints` list is the positional key 1.9.x reads (each JSON match's `fingerprint` field: path + rule + span). No raw secret material is stored.
- **Pre-commit ergonomics**: staged-file scan, hook installers, clear exit codes.
- **Compose, don’t compete**: pair with tools that specialize in history, blobs, and dependency provenance (see README “Compose with dedicated secret scanners”).

## Explicitly out of scope (use specialized tools)

- **Full Git history mining**: no `git log -p` / object-store secret archaeology; use [Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog), or similar.
- **Dependency / supply-chain secret scanning**: no `package-lock.json` marketplace or npm tarball introspection as a first-class engine.
- **Generic malware / trust scoring**: not an antivirus or “is this package malicious?” product.
- **Hosted SaaS backend** for scanning (the OSS packages are local Node tooling).

## Baseline security note

Baseline entries are **intentional acknowledgements** of detector output. They do not embed secrets, but they do weaken the guarantee for that finding until removed. A content entry stores a digest of the matched text, which lets someone confirm a guessed low-entropy secret; the plaintext is already in the same repository and its history, so the added exposure is an entry that outlives a history rewrite. Re-run `vault-guard baseline --write` after a rotation or a history rewrite: it drops entries that are no longer found.
