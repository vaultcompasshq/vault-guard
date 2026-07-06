# Vault Guard: Threat Model

This document states what Vault Guard is designed to defend against, what it is
explicitly **not** designed to defend against, and the trust boundaries of each
component. Publishing it honestly is itself a defence; security tools that
overstate their scope create a false sense of safety that is worse than no
tool at all.

For the per-flag security justification of `vault-guard proxy`, see
[`SECURITY.md`](../SECURITY.md). For local telemetry data flow, see
[`PRIVACY.md`](./PRIVACY.md).

---

## In scope

Vault Guard is a **regex- and entropy-based detection layer**. It is meant to
catch the high-frequency, low-sophistication leakage modes that account for
the majority of real-world incidents:

1. **Secret leakage in commits.** A pre-commit hook (`vault-guard scan
   --staged`) that blocks commits containing recognised credential shapes
   (API keys, database URLs, JWTs, SSH private keys, etc.).
2. **Secret leakage in CI.** SARIF output uploadable to GitHub Code Scanning,
   so detections appear inline on PRs without re-scanning.
3. **Secret leakage in editor / AI prompts.** Optional MCP server exposes
   `scan_text`, `scan_file`, and `scan_workspace` so an LLM client can
   pre-scan content before sending or applying it.
4. **Pre-commit hook reliability across managers.** Native git hooks, husky,
   lefthook, and `pre-commit` framework integrations are tested and
   first-class.
5. **Local-first telemetry.** Token usage and model-suggestion data live in a
   local SQLite database; nothing is uploaded.

## Out of scope

Vault Guard does not, and will not, claim to defend against:

- **Static application security testing (SAST).** Use CodeQL, Semgrep, or a
  language-specific SAST tool. We integrate (CodeQL runs in our own CI) but
  we do not reimplement.
- **Runtime exfiltration.** A malicious dependency that ships a credential to
  an attacker server at runtime is invisible to a pre-commit scanner.
- **Malicious dependencies that pass naïve checks.** A planned cooling-off
  feature (`vault-guard supply-chain --min-age 7d`) raises the bar but is not
  a substitute for code review.
- **Determined ReDoS authors.** The `extra_patterns` ReDoS guard is a
  conservative static heuristic (length cap, quantifier-density cap, nested-
  and alternation-quantifier shape detection). It catches the academic
  pathological shapes; it does not catch every pattern an attacker can
  construct. Real execution-time bounds require a regex engine like `re2`
  (planned).
- **Generic regex false positives.** Report as a normal issue. Improving
  signal/noise is product work, not security work.
- **Third-party dependency vulnerabilities.** Report to the upstream
  maintainer. We welcome a coordinated notification.

## Trust boundaries

### `vault-guard scan` (CLI)

| Input source            | Threat                                              | Mitigation                                                                   |
|-------------------------|-----------------------------------------------------|------------------------------------------------------------------------------|
| Files on disk           | Pathological filenames, symlink loops               | `realpathSync` for symlink resolution; `seen` set; binary-file skip.          |
| `.vault-guard.json`     | ReDoS via `extra_patterns`                          | `validateRegexSafety` (length cap 256, quantifier-density cap, shape check). |
| `.vault-guard.json`     | Cross-trust load from a parent directory            | `loadConfig` walks only between `startDir` and the nearest `.git` root.       |
| `.vault-guard.json`     | Silent default fallback on parse error              | `loadConfig` throws `ConfigError`; CLI exits non-zero with the parser message. |
| File contents (matched) | Token-leak surface on output                        | `maskValue` reduces to 4-char prefix + length tag; SARIF message omits value. |

### `vault-guard install-hook`

| Input source     | Threat                                                | Mitigation                                                  |
|------------------|-------------------------------------------------------|-------------------------------------------------------------|
| Existing hook    | Overwriting a user's existing pre-commit              | Detect existing hooks and merge an idempotent snippet.       |
| Repo discovery   | Operating outside a git work tree                     | `isInsideGitWorkTree` short-circuit before any FS write.     |

### `vault-guard proxy`

| Threat                                       | Default behaviour                                        | Opt-in escape hatch         |
|----------------------------------------------|----------------------------------------------------------|------------------------------|
| Confused-deputy via env-key fallback         | `401 missing_api_key` if caller omits `x-api-key`        | `--allow-env-fallback`       |
| Network exposure via non-loopback bind       | Refuses to start on anything other than loopback         | `--allow-public`             |
| OOM via non-streaming response buffering     | Wire is piped; usage tee capped at 1 MB; overflow drops | (none; this is the policy)  |
| Inbound payload DoS                          | Request body capped at 32 MB                             | (none; this is the policy)  |
| Lifecycle leak (DB rows lost on signal)      | `SIGINT`/`SIGTERM` runs `wal_checkpoint(TRUNCATE)`       | (none; this is the policy)  |
| Open-proxy abuse                             | Hostname pinned to `api.anthropic.com`; no path rewrite  | (none; this is the policy)  |

### `vault-guard mcp` (MCP server)

The MCP server runs as a stdio child of the editor / agent host. The trust
boundary is the editor process.

| Input source       | Threat                                                | Mitigation                                                       |
|--------------------|-------------------------------------------------------|------------------------------------------------------------------|
| Tool arguments     | Path traversal via `scan_file`                        | Resolved against the project root; refuses paths outside.         |
| Tool arguments     | Arbitrary regex via `scan_text` (none today)          | No user-supplied regex on this surface; only the built-in set.    |
| `report_token_usage`| Untrusted token counts inflate local SQLite           | Counts are local-only and not used for any access-control choice. |

### Local telemetry (SQLite)

| Threat                                                | Mitigation                                                          |
|-------------------------------------------------------|---------------------------------------------------------------------|
| Sensitive context in `cwd` column (PII)               | HMAC-SHA256 digest with local salt; see [`PRIVACY.md`](./PRIVACY.md). |
| Unbounded growth                                      | 90-day retention by default (`VG_TELEMETRY_RETENTION_DAYS`).          |
| Loss of recent rows on crash                          | WAL mode; `closeAndCheckpoint()` runs on SIGINT/SIGTERM.             |

## Known limits

- **Regex-based detection ≠ semantic.** A novel credential format with no
  vendor prefix and entropy below the threshold will not be caught.
- **Pre-commit hooks can be bypassed** with `git commit --no-verify`. CI
  scanning is the second layer.
- **Entropy thresholds are tuned conservatively** to keep false positives
  manageable. Lowering them in `.vault-guard.json` (`entropy_threshold`) is
  supported but will increase noise.
- **Git history is not scanned.** Use `git-secrets`, `gitleaks`, or
  `trufflehog` for retro scans of `.git/objects/`.

## Reporting

See [`SECURITY.md`](../SECURITY.md). Vulnerability reports go to
**security@vaultcompass.io**, not the public issue tracker.
