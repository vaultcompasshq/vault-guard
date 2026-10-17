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
