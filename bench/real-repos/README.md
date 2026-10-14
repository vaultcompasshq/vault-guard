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
