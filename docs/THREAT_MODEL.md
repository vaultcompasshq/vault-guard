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
  (planned). The **built-in** patterns are a separate matter. In 1.6.0 all 59
  were swept against adversarial input and timed at two input sizes to compare
  growth. The six that grew quadratically (`gcp-oauth`, `jwt-token`, and the
  four DSN rules) were bounded, `ssh-private-key`'s ambiguous repeat was
  rewritten, and every remaining rule measured linear. The claim is exactly
  that and no more: **measured linear on the adversarial inputs we
  constructed**, not a proof of linearity for all inputs. A future pattern edit
  can reintroduce the shape, which is why each bound carries a timing test (with
  one documented exception: the `jwt-token` segment bound is guarded
  structurally, because with its token-boundary lookbehind in place the bound is
  a constant factor rather than an asymptotic one and no practical input makes
  it cross a time budget). The sweep is a maintained, checked-in harness with a
  recorded baseline and a self-test that must detect the six
  historically-quadratic forms. It is a manual pre-release check rather than a
  CI gate, because timing on shared runners is noisy and a flaky security gate
  gets disabled. See [`REDOS_SWEEP.md`](./REDOS_SWEEP.md).

  The per-file budget is **not** an execution-time bound, and must not be read
  as one. Node's regex engine is **synchronous** and cannot be interrupted, so
  the budget is a **post-hoc** detector: it compares elapsed time *after* the
  scan of a file has already returned. It cannot abandon, preempt, or otherwise
  time-bound a runaway scan; a catastrophic pattern still runs to completion and
  still blocks the process for as long as it takes. What the budget does is
  refuse to call that result trustworthy, turning an over-budget file into a
  fail-closed verdict on the staged path and a diagnostic on a directory scan.
  **The regex bounds are what bound time.**
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
| File contents (built-in)| ReDoS via a catastrophic built-in pattern shape     | Every built-in repeat is bounded; all 59 rules measured linear on adversarial input (1.6.0 sweep), each bound guarded by a timing test. The per-file budget does **not** bound time: Node regexes are synchronous, so it is a **post-hoc** check that turns an over-budget file into a fail-closed verdict (staged) or a diagnostic (directory scan). |
| `.vault-guard.json`     | Cross-trust load from a parent directory            | `loadConfig` walks only between `startDir` and the nearest `.git` root.       |
| `.vault-guard.json`     | Silent default fallback on parse error              | `loadConfig` throws `ConfigError`; CLI exits non-zero with the parser message. |
| `.vault-guard.json`     | A schema-invalid key silently dropped               | The schema check that used to run only in `config validate` runs on every load, on every path (CLI, MCP, editor extension). |
| Control inputs, on a pull request | A pull request mutes the scanner in the same commit that carries the secret: `ignore: ["**"]`, `severity_overrides` off, `fail_on: none`, a head-added `.vault-guard.local.json`, a rewritten baseline, a `.gitignore` over the committed file, or the key under a `vendor/` directory | `--trust-base <ref>`: config and baseline read from the base ref, head tree scanned, tracked-file set instead of the gitignore tester, vendored names anchored to the scan root. A changed control input is reported and not applied. Unresolvable ref, a ref equal to HEAD's commit, and a ref carrying HEAD's tree are all exit 2. |
| The workflow file itself | A pull request edits or deletes the job that runs the gate | Not solvable inside the tool: on a same-repo `pull_request` event GitHub runs the workflow from the head. Required-check branch protection, or a reusable workflow on a protected ref. Documented in the README and `GITHUB_ACTION.md`. |
| Repository git config   | `diff.relative` shrinks the staged file list        | Config forced off per invocation (`git -c diff.relative=false ...`); staged paths resolved against the worktree root, never the caller's cwd. |
| Git index               | A staged blob the scanner cannot read               | Counted in `run.unscannable_files`; `--staged` exits **2** and prints no success line (see "Fail-closed behaviour"). |
| File contents (matched) | Token-leak surface on output                        | `maskValue` reduces to 4-char prefix + length tag; SARIF message omits value. |

#### Fail-closed behaviour

`vault-guard scan --staged` is the pre-commit gate, and its file list is a
closed enumeration of exactly what is about to be committed. If any staged
file cannot be examined, the run is **incomplete**, not clean:

- exit code **2** (the same "cannot vouch for this result" code used when
  `git diff --cached` itself fails), never 0, and in preference to the
  exit 1 that findings alone would have produced;
- no `✅ SUCCESS` line in text output;
- `run.unscannable_files` in JSON and in the SARIF run properties, alongside
  an error-severity `file.read_error` diagnostic (a SARIF driver
  notification at level `error`) naming the file and the reason;
- the installed pre-commit hooks report exit 2 as an incomplete scan rather
  than a detection, and deliberately omit the `--no-verify` hint they give
  for a real finding: the check did not run, so bypassing it is not the
  remedy.

A staged **submodule** pointer is not an unreadable file. Its index entry is
a gitlink with no blob behind it, so `--ignore-submodules=all` excludes it
from the staged listing; the submodule's own contents are that repository's
own gate to run.

#### A staged run is anchored at the repository root

A staged run resolves **everything** from the repository root, not from the
directory it was invoked in: the `.vault-guard.json` it loads, the
`.vault-guard.baseline.json` it consults, the `ignore` patterns it matches,
the fingerprints it computes, and every path it prints or serializes. Two
consequences follow, and both are intended:

- The same index gives the same verdict from any directory. A hook invoked
  from a subdirectory cannot publish absolute machine paths, cannot apply an
  `ignore` rule the root-level run would not have applied, and cannot
  produce a baseline fingerprint that only matches on one machine's layout.
- **A config or baseline that lives only in a subdirectory is not consulted
  on a staged run.** Only the repository root and above are searched. This
  is deliberate: the staged file set is repository-wide, so the rules
  applied to it must be repository-wide too. A per-directory config cannot
  govern files outside its own directory, and loading one that then matched
  against the root would make `ignore.paths: ["fixtures/**"]` mean
  `<root>/fixtures/` to the matcher and `sub/fixtures/` to whoever wrote it,
  silently exempting staged files nobody exempted.

A **directory** scan is unaffected and still loads its config from the
directory it was pointed at, which is also the tree it walks.

A **directory** scan deliberately does not fail on the same condition. Its
file set is discovered by walking a tree rather than declared by git, and
unreadable entries in it are ordinary on a real machine (root-owned caches,
sockets, other users' files). It reports them the same way (the diagnostic
and the `unscannable_files` count are emitted identically) but the exit code
still reflects findings only. Making a directory walk unrunnable for reasons
the user cannot fix would push people to stop running it, which protects
nothing. Integrators who want the stricter rule on a directory scan can gate
on `run.unscannable_files` themselves.

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
| Tool arguments     | Path traversal via `scan_file` / `scan_workspace`     | Resolved against the project root; refuses traversal and symlink escapes. |
| Tool arguments     | Path walks via `report_token_usage`                   | Each requested path is workspace-bounded before traversal.        |
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
