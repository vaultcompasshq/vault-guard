# Vault Guard Benchmark

Precision / recall / F1 harness for the `vault-guard` secret scanner, measured against a labeled fixture corpus.

## Read this before quoting a number

**This is a regression suite, not a generalization benchmark.** Nearly every
fixture under `fixtures/clean/` was added in reaction to a specific false
positive that was then fixed. A perfect score therefore means "no known bug
came back" and says nothing about accuracy on code the scanner has never seen.

Two consequences, both learned the hard way in the 1.4.0 audit:

1. **Do not publish the score as a headline accuracy metric.** Scanning real
   third-party repositories found both a missing-coverage class and two
   false-positive classes while this corpus read 100% / Grade A.
2. **Do not read the `--gitleaks` comparison as a fair head-to-head.** The
   corpus is chosen to exercise Vault Guard's rules and suppressions, which is
   home-field advantage and systematically understates any other tool. (Before
   1.4.0 the harness also passed `--report-format json` with no
   `--report-path`, so gitleaks' findings were never parsed at all and it was
   scored at a flat 0% recall. That was a harness bug, not a result.)

The right use of this harness is a CI gate against regressions
(`node bench/run.cjs --assert`), plus a place to park every real-world false
positive you find so it can never come back.

## Run

```bash
# Build first so the harness uses the local binary
pnpm build

# Basic run (Vault Guard only)
node bench/run.cjs

# Verbose: show per-file TP/FP/FN/TN
node bench/run.cjs --verbose

# CI gate: exit non-zero if precision/recall fall below floors
node bench/run.cjs --assert
node bench/run.cjs --assert --min-precision 1.0 --min-recall 0.95

# Side-by-side with Gitleaks (must be installed: brew install gitleaks)
node bench/run.cjs --gitleaks --verbose
```

Or via the monorepo root:

```bash
pnpm bench
```

## Fixture corpus

| Directory | Purpose |
|---|---|
| `fixtures/secrets/` | Files that **should** trigger at least one finding (TP candidates); **gitignored, generated at runtime** |
| `fixtures/clean/` | Files that **should not** trigger any findings (FP candidates); committed |

`fixtures/secrets/` is gitignored because committing contiguous secret-shaped strings (even synthetic ones) is blocked by GitHub push protection and vault-guard's own pre-commit hook. Instead, `generate-fixtures.cjs` stores each secret as joined string fragments and writes the files at runtime. `run.cjs` calls the generator automatically before scanning.

Each fixture is registered in `labels.json` with `shouldDetect: true/false` and a short note.

## Metrics

| Metric | Formula |
|---|---|
| Precision | TP / (TP + FP); "when it flags, is it right?" |
| Recall | TP / (TP + FN); "does it catch all the real ones?" |
| F1 | 2 × P × R / (P + R); harmonic mean |

**Grades:** A ≥ 90% F1 + Precision · B ≥ 80% · C ≥ 70% · D ≥ 55% · F < 55%

The grade is an internal health signal for this corpus only. It is not a
product claim, and it does not belong in the README, release notes, or any
comparison table.

## Adding fixtures

**TP fixtures (must trigger):** add an entry to `generate-fixtures.cjs`; store the value as joined fragments (`['sk_live_', 'AbCd…'].join('')`) then add the file to `labels.json`.

**FP fixtures (must not trigger):** create the file under `fixtures/clean/`, then add to `labels.json`:

```json
"fixtures/clean/my-fixture.ts": { "shouldDetect": false, "note": "Why this should stay clean" }
```

## Notes

- The harness measures **file-level** detection (did any finding occur in a file expected to contain a secret?), not individual-finding accuracy. This matches the primary user-facing guarantee: "no secrets slip through undetected."
- `fixtures/clean/test-passwords.ts` is a `.ts` file in a non-test path to stress the generic `password-in-code` pattern. The path-aware severity downgrade applies only to files inside `__tests__/`, `tests/`, `fixtures/`, etc.), not this benchmark's `clean/` directory. If this file triggers, that is a FP the scanner needs to address.
