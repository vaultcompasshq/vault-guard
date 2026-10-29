# Real-repository validation

`2026-10-12-1.10.0.json` is the release check that section 8 of
`docs/design/2026-10-12-blob-reads-baseline-symlinks-locale-basenames.md`
requires. It compares three builds on four public repositories: the
published 1.9.1, `main` at adc39e5 (the 2026-10-11 file-set design), and the
1.10.0 implementation branch.

## Method

1. Each repository (facebook/react, urllib3/urllib3, gitleaks/gitleaks,
   Yelp/detect-secrets) is cloned at depth 1 and its `origin` removed. The
   commit is recorded as `clone_head`.
2. An untracked `vg-bench-marker.txt` is placed in each clone.
   `run.cjs` commits it on a `vg-bench` branch (`bench_branch_head`), so a
   pull-request run has a parent commit to read its controls from.
3. For each build, `run.cjs` runs `scan . --format json` and
   `scan . --trust-base <clone_head> --format json` three times each, and
   records the median wall time, the run counts (`files_scanned`,
   `file_set`, `content_source`, `worktree_copies_scanned`, the tracked
   counts from the 2026-10-11 design) and every finding as rule, file, line,
   severity, source, positional fingerprint and content fingerprint. Never the
   value.
4. The branch build's findings are stored in full. For the other builds the
   record holds the count, a SHA-256 over the sorted finding keys, and how
   many findings differ from the branch. 1.9.1 emits no content fingerprint
   and no source, so its hash differs even when its findings match.
5. `transform_attribute_counts` counts tracked files carrying a
   `working-tree-encoding`, `eol` or `text`, or `filter` attribute, from
   `git check-attr`, so a fingerprint difference can be traced to a
   transform.

To regenerate, with the three CLIs built or installed:

```
node bench/real-repos/run.cjs <dir-with-the-four-clones> \
  bench/real-repos/2026-10-12-1.10.0.json \
  <1.9.1 cli-entry.js> <adc39e5 cli-entry.js> <branch cli-entry.js>
```

## Release blockers

`release_blocker_summary` states the four conditions from the design, each
comparing adc39e5 with the branch:

- a file adc39e5 scanned that the branch does not (compared by
  `files_scanned`, because the JSON output does not list every scanned
  file);
- a finding lost that no transform or two-letter basename explains;
- a fingerprint change on a file with no transform (per-file multisets of
  rule, positional and content fingerprint);
- React wall time over 1.5 times adc39e5's, plain scan, median of three.

React declares `text=auto` for every file, so for React the untransformed
check has nothing to compare; its finding sets for adc39e5 and the branch
are still identical (`same_findings_as_branch`).

The two private dogfood groups the 2026-10-11 design names are run by the
operator and are not recorded here.

## 1.11.0: binary skips by content agreement

`2026-10-17-1.11.0.json` is the release check that section 10 of
`docs/design/2026-10-17-media-skip-budget-retime-upgrade-note.md` requires.
It compares the published 1.10.0 with the implementation branch on eight
public repositories: the four above at the commits the 1.10.0 run used, plus
mdn/learning-area (committed video, audio and images), FortAwesome/Font-Awesome
(web fonts), goldfire/howler.js (audio in its examples) and github/explore (an
image-heavy tree with no video, where the head-read cost lands hardest).

Method, as for 1.10.0, with these additions:

1. Each clone is at depth 1 with `origin` removed; `clone_head` is recorded.
   The four 1.10.0 repositories are fetched at their recorded 1.10.0 commits.
2. `per_extension_tracked` counts the tracked files per extension of the
   design's family table, from `git ls-files` at the clone head.
3. `expected_sets` gives the sets section 10 defines (M, T, I, B, X), found by
   applying the branch's own classifier to the first 4096 bytes of each tracked
   file (the clones are clean, so the disk copy is the blob). `checks` compares
   the counts each build reported with what those sets predict, and lists every
   finding one build has and the other does not, with whether it falls in the
   set that explains it.
4. Plain scans run from the bench directory with the clone passed as an
   absolute path; `--trust-base` runs from inside the clone, because
   pull-request mode refuses a target outside the repository its base ref
   lives in. The two builds are interleaved run by run, three runs each,
   median wall time.
5. `head_read_bytes` is the total body bytes piped through `cat-file` for head
   reads in a programmatic plain scan with the branch build (a counter on the
   content source, not an output field).
6. The load run repeats the plain scan of the three media repositories with
   twice as many busy processes (`busy.cjs`) as the machine has cores, and
   records the `scan_budget` entries per build.
7. The machine's load average is recorded at the start and the end, since
   wall time on a shared machine moves with it.

To regenerate, with both CLIs built or installed:

```
node bench/real-repos/run.cjs --design-2026-10-17 <dir-with-the-eight-clones> \
  bench/real-repos/2026-10-17-1.11.0.json <1.10.0 cli-entry.js> <branch cli-entry.js>
```

`expected_sets` is computed with the branch's own classifier, so
`counts_as_expected` proves only that the run's accounting is consistent with
that classifier, not that the classifier is right. The independent evidence is
`mismatch_explanations`: every file the branch scanned as a type mismatch,
with what its bytes actually are, read by hand from the file at the clone
head (a regenerated record does not carry it; it is added after reading the
files). In the recorded run those are seven files: in github/explore, five
JPEGs and one WebP named `.png`; in mdn/learning-area, `Cicle_Fina.ttf`, an
OpenType CFF font whose first bytes are `OTTO`, which the `.ttf` row of the
design table does not accept.

Ruling (coordinator, 2026-10-17): the `.ttf` row keeps the designed
signatures in 1.11.0, so a CFF font named `.ttf` is scanned as text;
accepting `OTTO` under `.ttf` is a follow-up.

The 1.15x wall-time gate is rerun on a quiet machine during release prep; that
is a release step, not part of this record.

`release_blocker_summary` states the section 10 blockers: a lost finding
outside M and I, a new finding outside X, fewer files scanned than M explains,
counts that differ from the expected sets, any `scan_budget` entry for the
branch in the load run, and plain-scan wall time over 1.15 times 1.10.0's on
the four 1.10.0 repositories or on github/explore.

## 1.12.0: encoded-payload demotion and grouped repeats

`2026-10-17-1.12.0.json` is the release check that section 9 of
`docs/design/2026-10-17-data-file-false-positives.md` requires. It compares
the published 1.11.0 with the implementation branch on eleven public
repositories: the four 1.10.0 repositories at the commits the 1.11.0 run
used; jakevdp/PythonDataScienceHandbook and fastai/fastbook (notebooks whose
outputs hold bare base64 PNG runs), plus ageron/handson-ml as the section 9.1
fallback for fastbook; fivethirtyeight/data (hundreds of CSV files in varied
dialects); and four chosen by GitHub code search, whose queries the record
names: Sunbird-Ed/sunbird-perf-tests and
jcarloshg/BuyingTickets-DistributedRateLimiter (CSV files with a column of
JWT-shaped values) and tinylibs/tinyspy (an SVG with a `data:image/png`
payload over 100 KB).

Method, as for 1.11.0, with these additions:

1. `census` applies the branch's own `dataShape` and run sweep to every
   tracked text file at the clone head: files called delimited (by
   delimiter) or long-line, and `R_media`, the characters of runs of 1024 or
   more that decode to binary media, by reason (`data:` payload or bare run)
   and alphabet. `expected_gcp_coincidences` is section 1.2's rate applied
   to it (standard alphabet `1.96e-8` per character, URL-safe `5.96e-8`).
2. `checks` applies the section 9.3 formulas per mode: findings lost or
   added (keyed by rule, file, line, offset, source and both fingerprints),
   the restorations (`restored_log`) and copy swaps (`swap_log`) that explain
   an addition, any severity change outside the demoted set D, every entry
   of D against 1.11.0's severity, the blocking count formula under the
   default gate, and the run counts.
3. `planted` runs the two planted cases of section 9.4 (P1, a key in one cell
   of a 1000-row CSV beside a JWT column; P2, keys in a `data:text/html` URI
   and pasted raw into a `data:application/json;base64` payload) in plain,
   `--trust-base` and `--staged`, built at run time in their own
   repositories. Through MCP `scan_workspace` the same cases are a test in
   `packages/mcp`.
4. `bench/run.cjs --assert` compares every positively labelled fixture's
   findings and severities with `bench/severities-1.11.0.json`, written from
   the published 1.11.0 with `--cli <cli-entry.js> --write-severities`.

To regenerate, with both CLIs built or installed:

```
node bench/real-repos/run.cjs --design-2026-10-17-data-files <dir-with-the-eleven-clones> \
  bench/real-repos/2026-10-17-1.12.0.json <1.11.0 cli-entry.js> <branch cli-entry.js>
```

In the recorded run (the eleven repositories above: handson-ml stands in
for fastbook, whose bare-run R_media is 5.84 MB, and
BuyingTickets-DistributedRateLimiter was a second JWT-column search because
sunbird-perf-tests holds only two-line token CSVs; both of the replaced
repositories stay in the record), every section 9.4 blocker is clear: no
finding added or lost, no severity change, D empty everywhere (E at most
0.31), blocking counts unchanged, the planted cases critical in every mode,
and plain-scan wall time between 0.97 and 1.03 times 1.11.0's on the gated
repositories. The machine was not quiet: the recorded load average was 8.46
at the start on 8 cores (4.08 at the end), and the two builds were
interleaved run by run, three runs each, so the load fell on both alike. One
group forms, the JWT column of `login-results.csv` (63 members). The
record's `demotion_explanations`, `group_explanations` and
`fallbacks_and_choices` hold the hand checks.

The census and the checks use the branch's own code, so they prove
consistency, not correctness. The independent evidence is
`demotion_explanations` (each demoted run decoded outside vault-guard with
`base64 -d` and identified with `file -`) and `group_explanations` (each
grouped file read by hand), added after reading the files.

## 1.12.1: drift check for a release that did not change detection

`2026-10-28-1.12.1.json` compares the published 1.12.0 with 1.12.1 built
from source (plus a trust-base report change that does not touch
detection) on three public repositories: Yelp/detect-secrets and
gitleaks/gitleaks at the commits the 1.12.0 run used, and urllib3/urllib3 at
its 1.12.0 commit. 1.12.1 changed the pull-request file set and the
fingerprint keying for linked paths; `git diff v1.12.0 v1.12.1` over the
scanner, placeholder, entropy and data-shape code is empty. So the
expected result is no difference at all, and `--release-drift` explains
nothing away: it lists every finding one build has and the other does not,
keyed by rule, file, line, offset, severity, source and both fingerprints,
and compares exit code, files scanned, blocking, demoted, grouped and
unscannable counts, plain and `--trust-base`.

To regenerate, with both CLIs built or installed and each clone prepared as
above:

```
node bench/real-repos/run.cjs --release-drift <dir-with-the-clones> \
  bench/real-repos/2026-10-28-1.12.1.json 1.12.0 <1.12.0 cli-entry.js> <branch cli-entry.js> \
  detect-secrets=Yelp/detect-secrets gitleaks=gitleaks/gitleaks urllib3=urllib3/urllib3
```

The `builds` labels and `hand_checks` are filled in by hand after the run.

In the recorded run nothing moved: no finding added or lost and every
count equal in both modes on all three, and the plain-scan counts equal the
1.12.0 record's (detect-secrets 213 files, 73 findings, 38 blocking;
gitleaks 450, 414, 389; urllib3 170, 2, 2). Every finding sits in test data,
test sources, a committed baseline, a rule config or a test server's
certificates, as `hand_checks.false_positives` says. Wall time is not a
measurement here: the load average was 21 to 34 on 8 cores throughout.
