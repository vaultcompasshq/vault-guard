---
'@vaultcompass/vault-guard': patch
'@vaultcompass/vault-guard-core': patch
'@vaultcompass/vault-guard-mcp': patch
'@vaultcompass/vault-guard-telemetry': patch
---

Fix SARIF artifactLocation.uri leaking absolute local paths when the scan
target sits outside the current working directory.

The SARIF emitter relativized every uri against the process cwd, and kept
a path absolute whenever relativizing would have produced a `..`
traversal. That is the right instinct for the traversal problem and the
wrong base to measure it from: running `vault-guard scan /some/other/tree`
from anywhere else meant every finding in that tree was outside the cwd,
so every uri stayed absolute and the resulting file published the
developer's home directory and OS username to whoever reads the upload.
For a document whose entire purpose is to be handed to GitHub Code
Scanning, that is a leak on the normal path, not an edge case.

`formatSarif` now takes an optional `scanRoot`, the directory the scan
actually walked, and relativizes against that instead. A file outside the
cwd but inside the scan root gets a proper relative uri under
`%SRCROOT%`. When no `scanRoot` is passed the base falls back to the cwd,
so existing callers behave exactly as before.

A file genuinely outside the scan root still stays absolute. SARIF
resolves relative references against `%SRCROOT%`, so a traversal out of it
is not a legal uri and there is no other root to express such a path
against; the code now says so rather than leaving the reader to infer it.
In practice this only arises for a path a caller injected from outside the
scan, since every file the scanner itself walks is under the target it was
given.

The CLI derives the scan root from a single scan target, or from the
repository root under `--staged`, where the paths come out of the git
index already rooted at the checkout. With several targets given at once
it keeps using the cwd, deliberately: the only directory containing all of
them is a common ancestor that is frequently the filesystem root or the
user's home, and a "relative" uri rooted there would spell out the machine
layout just as plainly as the absolute path did.

JSON output is unchanged. Its `file` paths stay cwd-relative because the
terminal output and the baseline fingerprints are keyed on them, and
moving that base would silently invalidate every existing baseline entry.

Covered by unit tests for both halves of the new rule (inside the scan
root but outside the cwd becomes relative; outside the scan root stays
absolute) and by an end-to-end test that scans an out-of-tree directory
from the repository root and asserts no absolute path appears anywhere in
the emitted document.
