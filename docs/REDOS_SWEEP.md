# ReDoS timing sweep

`scripts/redos-sweep.cjs` measures every built-in detection pattern against
adversarial input at two sizes and compares growth. Roughly 2x per doubling is
linear. Roughly 4x is quadratic, which is a real ReDoS.

```bash
pnpm build                        # the sweep reads packages/core/dist
pnpm redos:sweep                  # sweep + compare to the recorded baseline
pnpm redos:sweep:self-test        # prove the harness can detect quadratics
pnpm redos:sweep:update-baseline  # re-record after an intentional change
```

## Read this before quoting a result

**A pass means: measured linear on the adversarial inputs this harness
constructs.** It is not a proof of linearity, and it says nothing about input
shapes nobody thought to build. Regex cost depends entirely on the shape of the
input, so an unmeasured shape is an unknown, not a safe one. Treat a clean sweep
as "no known-bad shape is present in the table", never as "this table cannot be
attacked". Real execution-time bounds require a different engine (`re2`); see
[`THREAT_MODEL.md`](./THREAT_MODEL.md).

This is the same caution the fixture corpus carries in
[`bench/README.md`](../bench/README.md), for the same reason: a suite graded
against artifacts we wrote cannot find a class we never imagined. Six built-in
rules were quadratic in 1.5.0 and every one of them passed the full unit suite.

## Why the self-test is the important part

`--self-test` replays the six historically-quadratic forms (the pre-1.6.0
`gcp-oauth`, `jwt-token`, and the four DSN rules) and **requires the harness to
flag all six**. A clean sweep is only meaningful if the harness can detect a
dirty one.

This is not theoretical. An early version of the sweep extracted only a leading
literal prefix and stopped at the parenthesis in `postgres(?:ql)?`, so it never
built a many-start input for three of the four DSN rules and reported them clean
**while they were quadratic**. The self-test is what exposed that. Run it
whenever you change the harness.

A second false-positive class was found the same way: ratio alone is too noisy
to stand on its own, because a rule costing 3ms and 14ms reports a 4.6x ratio
from jitter. A rule must now be both super-linear in growth **and** slow in
absolute terms (>= 100ms at 200k) to be flagged. The six real quadratics
measured 2,180ms to 16,593ms; every bounded rule sits under ~35ms.

## Baseline

`scripts/redos-sweep-baseline.json` records each rule's verdict and indicative
ratio. `pnpm redos:sweep` diffs against it and fails on a **verdict** change or
a rule appearing/disappearing. It deliberately does not compare timings: those
move with the machine, so only the verdict is portable.

Re-record with `pnpm redos:sweep:update-baseline` when you intentionally add or
change a pattern, and say so in the pull request.

## Not a CI gate

Deliberately not wired into CI for this release. Timing on shared runners is
noisy (cold caches, neighbouring jobs), and a flaky security gate gets disabled,
which is worse than no gate at all. Run it:

- before a release, as a manual pre-release check;
- whenever a detection pattern is added or edited;
- whenever the harness itself changes (with `--self-test`).

Adversarial inputs are generated at runtime (filler runs and repeated scheme
literals), never committed credential-shaped literals.
