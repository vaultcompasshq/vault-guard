# Plain-scan file set inside git, and a baseline writer

Status: implemented on `feat/plain-scan-file-set-and-baseline`, not yet
released. Target: 1.10.0, all four packages in lockstep. What the
implementation found that this design did not say is in section 8. Covers two items from the 2026-10-11 dogfood run of 1.9.1 against
24 real repositories:

- **File set.** A plain scan inside git skips tracked files that `.gitignore`
  matches; pull-request mode (`--trust-base`) scans them. On two repositories
  a committed `.env` was clean in a full run and blocking in a pull-request run.
- **Baseline.** Pull-request mode scans the whole head tree, so findings that
  predate a pull request block every unrelated pull request (24 to 48 blocking
  findings on two repositories). A baseline mechanism exists, but nothing
  writes it and nothing points at it.

**Decided before this doc, not reopened:** inside a git repository the
plain-scan file set is tracked files plus untracked files that are not
ignored, so a tracked-but-ignored file is scanned in every mode. Outside git
the current walk stays. This is a fail-closed change: existing adopters will
see new findings.

Line citations are against `main` at the commit this branch was cut from.

---

## 1. Current behaviour

### 1.1 Plain directory scan

`scanCommand` sends a directory target to `scanFilesAsync`
(`packages/cli/src/commands/scan.ts:407-420`), which calls
`getFilesToScanAsync` (`packages/cli/src/utils/scan-utils.ts:658-664`;
`packages/core/src/utils/file-utils.ts:414-434`). That function does three
things:

1. **Filesystem walk** (`file-utils.ts:255-332`). It does not follow symlinks
   (`:291-293`). It skips a directory named in `shouldIgnoreDirectory`
   (`:616-638`: `node_modules`, `dist`, `build`, `vendor`, `venv`,
   `__pycache__` and others) **at any depth** (`:295`). The type filter
   (`:654-692`) drops some extensions, the lockfile names and minified
   artifacts, and counts what it drops (`:299-301`).
2. **Gitignore tester** (`:197-250`). It reads every `.gitignore` from the
   nearest `.git` (`:74-84`) down to the scan root (`:126-152`), and every
   `.gitignore` below the scan root (`:162-195`). It matches them with the
   `ignore` npm package, which emulates git's rules. It never asks git
   whether a file is tracked, and it reads neither `.git/info/exclude` nor
   `core.excludesFile`.
3. **Filter** (`:425-432`). A file the tester matches is dropped at `:426`
   through `shouldIgnoreFile` (`:687-689`). **No count goes up**, unlike the
   config `ignore` drop next to it (`:427-430`). That makes the gap silent.

The MCP workspace scan calls the same function
(`packages/mcp/src/workspace-scan.ts:62`). The sync `getFilesToScan`
(`file-utils.ts:454-466`) is reached only through `scanFiles`
(`scan-utils.ts:793-826`), and only tests call `scanFiles`.

### 1.2 Pull-request mode

`loadTrustedControls` (`packages/core/src/trust-base.ts:613-685`) returns the
base ref's config and baseline. It also returns `headTreeFiles`
(`:587-600`): `git ls-tree -r -z HEAD`, regular-file blobs only, so symlinks
and submodule gitlinks never enter the list (`:579-580`). `scanFilesAsync`
passes those to `getPullRequestFilesToScan` (`scan-utils.ts:651-657`;
`file-utils.ts:539-614`), which:

- does **not** use the gitignore tester (`:577-582`);
- skips vendored names **only as a direct child of the scan root**
  (`:570-574`);
- applies and counts the type filter (`:579-582`), and applies and counts the
  base ref's config `ignore` (`:587-590`);
- `lstat`s each path. A tracked file it cannot examine on disk is unreadable
  (`:592-603`), and the run exits 2 (`scan-utils.ts:672-692`).

### 1.3 Why they differ

The difference is deliberate for pull-request mode and was never revisited
for plain mode. The docblock at `file-utils.ts:513-521` says a head-side
`.gitignore` could mute the file carrying the key, and that "`.gitignore`
governs what git will ADD and says nothing about a file already committed".
It then keeps the tester for plain scans, "where it is doing an honest job".
For tracked files that is false in plain mode too. The vendored-name
anchoring (`:522-529`) is a second, separate difference.

### 1.4 The dogfood claim against the code

- **Group A, a large monorepo:** confirmed. The full run scanned 1691 files
  and did not report the `.env`; pull-request mode scanned 1693 and blocked
  on `.env:4` and `.env:16`. The tracked `.env` is matched by `.gitignore`
  and dropped at `:426`. The second extra file was not identified: either
  another tracked-ignored file or a tracked file under a nested vendored
  name.
- **Group C, a Flask service, 50 files against 310:** consistent with
  `.gitignore` as the main cause, but **not verified**. The group report
  counts 261 tracked files under a gitignored `.pip-cache/`, and the
  arithmetic does not settle the rest. The plain run's 50 can include
  untracked, unignored files that pull-request mode never sees, so 49 tracked
  files plus 261 fits as well as any reading of 50 + 261 = 311. The binary
  filter is not a type filter that "drops in both modes": it runs later, in
  `scanFilesAsync`, and only for files that reach it, so a cached binary would
  be counted under `binary_files_skipped` in pull-request mode only. Nothing
  in the evidence points to a size limit. The secret hits in that cache are
  cache-artifact false positives, and after this change they will show up in
  plain runs too (6.2). The real-repository validation in section 5 records
  the actual per-mode file lists for this repository.
- **A latent second cause the dogfood did not isolate:** a tracked file
  under `src/vendor/`, `app/build/` and similar paths is skipped by the plain
  walk and scanned in pull-request mode. Section 2 closes it.

---

## 2. New file-set rule

### 2.1 Rule

| Directory target | File set |
|---|---|
| `--trust-base` | Unchanged: head tree, through `getPullRequestFilesToScan`. |
| Plain, inside a git work tree | **New:** tracked plus untracked-not-ignored, from git. |
| Plain, outside git | Unchanged: walk plus gitignore tester. |

```
git -c core.quotePath=false ls-files -z --cached -- <target>
git -c core.quotePath=false ls-files -z --others --exclude-per-directory=.gitignore -- <target>
```

**Deciding "inside git" fails closed.** `isInsideGitWorkTree`
(`packages/core/src/utils/git-utils.ts:319-330`) returns false on any git
error, so it cannot be the switch. A missing git binary, a `safe.directory`
"dubious ownership" refusal or a corrupt `.git` would otherwise route the run
to the walk and bring the F05 gap back without a word. Instead, the presence
of a `.git` directory or file found by `findGitRoot`
(`file-utils.ts:74-84`), starting from the target's directory, decides it.
Once a `.git` is found, any failure of `rev-parse --show-toplevel` or of
either `ls-files` call is exit 2, with git's stderr quoted. There is no
fallback to the walk.

Both commands run at the root that `git rev-parse --show-toplevel` returns
for the target's directory, not for the cwd. `<target>` is passed
root-relative with a `:(literal)` prefix, so a path is never read as a magic
pathspec. The target and the toplevel are both canonicalised with
`realpath` before `path.relative`. git reports the physical toplevel, so a
target reached through a symlink (macOS `/var/folders` against
`/private/var/folders`) would otherwise relativise to a bogus `../` path;
`canonicalDir` at `git-utils.ts:31-35` documents the same bug.

`ls-files --cached` lists a conflicted path once per stage during a merge,
so the list is de-duplicated before filtering.

- **Tracked part** (`--cached`): the paths go through
  `getPullRequestFilesToScan` unchanged. That means root-anchored vendored
  names, the counted type filter, the counted config `ignore` (from the
  working tree, as plain mode does today), and `lstat`/`isFile`. The tracked
  half of a plain scan is now built by the same function as pull-request
  mode, which is the point of the change.
- **Untracked part** (`--others`, not ignored): the walk's own filtering.
  Vendored names apply **at any depth**, so an untracked, unignored
  `packages/x/node_modules` stays out as it does today. The type filter and
  config `ignore` also apply.

The index is the right source, not `HEAD`. Plain mode judges the working
tree, and on a CI checkout the two are the same. The `HEAD` versus index
argument at `trust-base.ts:567-577` is about judging a ref, which plain mode
does not do.

`--exclude-per-directory=.gitignore` reads exactly what the tester reads
today. `--exclude-standard` would also read `.git/info/exclude` and the
user's global excludes file. The file set would then depend on per-machine
configuration, and an untracked `.env` listed only in a global ignore file,
which is scanned today, would drop out. See open question 1.

### 2.2 Edge cases

- **Symlinks.** Tracked (mode 120000) or untracked, `lstat`/`isFile` drops
  them. They are never followed, as in the walk and pull-request mode.
- **Submodules.** A gitlink is a directory on disk, so `isFile` drops it. But
  today's walk descends into a checked-out submodule (the tester stops at the
  nearest `.git`). To avoid a silent coverage cut, the builder recurses: for
  each gitlink with a checked-out work tree, it applies the same rule inside
  it. Pull-request mode scans no submodule contents today and is unchanged
  (open question 6).
- **Nested repositories that are not submodules.** `--others` lists one
  `dir/` entry and stops there. If that directory contains a `.git`, the
  builder recurses into it, the same as for a submodule. A nested repository
  the outer `.gitignore` ignores is not listed and not scanned, as today.
- **No commits.** `--cached` reads the index and `--others` needs no `HEAD`,
  so a fresh `git init` works. A scan that resolves to zero files still exits
  2 (`scan.ts:452-462`).
- **A tracked path whose `lstat` fails** is split in two:
  - it is counted in `run.tracked_files_missing` (and a text line when
    non-zero), not exit 2, **only** when git says it is not in the work tree
    (listed by `git ls-files -z --deleted`, or tagged `S`, skip-worktree, by
    `git ls-files -t`) **and** the `lstat` errno is ENOENT or ENOTDIR:
    deleted locally, or left out by a sparse checkout. `--deleted` alone is
    not enough in either direction (section 8). The walk never saw these
    files either, so this is not a regression, but a sparse CI checkout is a
    known soft spot and the count is what makes it visible;
  - every other `lstat` failure is exit 2, exactly as pull-request mode does
    today (`scan-utils.ts:672-692`). That includes a directory that cannot
    be entered, and a non-UTF-8 file name that git's output, decoded as
    UTF-8 (`trust-base.ts:91`), turns into a path that does not exist.
- **Size limit, budget and binary skips** still apply afterwards in
  `scanFilesAsync`, unchanged. An explicit file target is unchanged. A target
  that is itself an ignored directory gives zero files and exits 2, both
  before and after this change.
- **git fails** after a `.git` was found: exit 2, quoting the error (2.1).
- **MCP workspace scan.** It calls `getFilesToScanAsync`
  (`packages/mcp/src/workspace-scan.ts:62`). The change is made inside that
  function, so MCP gets the new file set too, and an editor and CI agree on
  what was scanned.

### 2.3 Reporting

Two counts are computed, each intersected with the files actually scanned:

- tracked files that `.gitignore` would hide, from
  `git ls-files -z --cached --ignored --exclude-per-directory=.gitignore`;
- tracked files under a nested vendored name.

Text shows a count only when it is non-zero, because the plain summary is
pinned byte for byte (`scan.ts:673-678`):

```
Tracked files that .gitignore would hide, scanned: 261
Tracked files under nested vendored directories, scanned: 3
```

New `run` fields, all additive: `file_set` (`git`, `walk`, `head-tree` or
`index`), `tracked_ignored_files_scanned`, `tracked_nested_vendored_scanned`
and `tracked_files_missing`. Pull-request mode fills the first two as well,
since it already scans those files and does not say so.

Plain runs keep their existing counts. The type-filter and config-ignore
drops in the tracked half, which `getPullRequestFilesToScan` records in
`PullRequestSkips`, are added into the plain run's `skips`, so
`type_filtered_files` and `config_ignored_files` stay complete. A plain run
inside git also reports `vendored_dirs_skipped` and the text line
`Vendored directories skipped: N (names)` when non-zero, as pull-request mode
does (`scan.ts:641-646`), since root-level vendored names still mute by
design.

### 2.4 `--staged`

No change. The file list comes from `git diff --cached` (`git-utils.ts:154`)
and the content is read from the index. It never consulted the tester or the
vendored names (`scan.ts:336-338`), so a force-added ignored file is already
scanned at commit time. `file_set` is `index`.

---

## 3. Baseline

### 3.1 What exists

- **File:** `.vault-guard.baseline.json`, in the form
  `{ "version": 1, "fingerprints": [...] }`
  (`packages/core/src/baseline.ts:9-14`). It is found by the config walk,
  from the cwd up to the repository root (`baseline.ts:68-90`;
  `config.ts:92-95`). A malformed file suppresses nothing and warns
  (`baseline.ts:33-62`; `scan.ts:478-491`).
- **Fingerprint:** `sha256(relpath|rule|line|offset|matchLength)`, with the
  path relative to the run's anchor
  (`packages/core/src/match-fingerprint.ts:17-21`). It depends only on
  location, which has two consequences:
  - an edit above a finding expires its entry;
  - a **different** secret with the same length and rule at the same
    position is suppressed.

  conductor labels this fingerprint `positional` (conductor
  `src/normalize.ts:386-393`).
- **Pull-request mode:** the baseline comes from the base ref
  (`trust-base.ts:621-631`). A head-side change is a proposal and is not
  applied (`:645-668`; `scan.ts:467-477`).
- **Writer:** none. The README says to copy fingerprints from JSON by hand
  (`README.md:549-555`).

### 3.2 Content-derived key

```
content_fingerprint = sha256("vg-fp-v2" NUL relpath NUL rule NUL sha256(raw match))
```

- **`relpath`** is relative to the repository root inside git, and to the
  scan anchor outside it. A baseline written from a subdirectory therefore
  still matches a root scan.
- **The raw digest** is computed in the scanner and carried on `SecretMatch`.
  Today only the masked value leaves the scanner (`types.ts:4-5`), and the
  raw value still never does.
- **What changes a key and what does not** (value-bearing rules only, see
  below):
  - moving a finding to another line keeps its key;
  - a rename, a copy into another file, or a different value is a new
    finding.
- **Header-only rules never get a content entry.** Some rules match only a
  fixed marker, not the secret: `ssh-private-key` matches the PEM header
  line that opens a private key
  (`packages/core/src/scanners/secret-scanner.ts:210`), and
  `gcp-service-account` matches the JSON type field that names a service
  account (`:113`). Their
  match text is the same for every key, so a content entry for one would
  suppress any replacement key in that file, up to its count. The set is
  **derived from the rule table, not from a hand list.** `PatternEntry`
  (`secret-scanner.ts:21`) gains a required `valueBearing: boolean`, with no
  default, so the type checker forces a decision on every built-in rule and
  on every rule added later. User `extra_patterns` are treated as not
  value-bearing, since vault-guard cannot know what they capture. Today the
  table marks exactly the two rules above as false.

  For a rule that is not value-bearing, the entry falls back to the
  positional fingerprint **plus a SHA-256 digest of the whole file**
  (`file_digest`). It suppresses only when both match. The digest is over
  the file's **raw bytes**, with no line-ending or encoding normalisation, so
  converting LF to CRLF alone makes the entry stop matching: fail closed.
  The positional key in such an entry takes its path relative to the same
  root as a content key (section 8).

  **The reader picks an entry's matching kind from the CURRENT rule table's
  `valueBearing`, never from the entry's shape.** A match from a
  value-bearing rule is looked up by its content key; a match from a rule
  that is not value-bearing is looked up by its positional key and needs a
  `file_digest` equal to the file's digest now. An entry without
  `file_digest` therefore suppresses no header-only finding, whatever its
  fingerprint. This goes slightly
  beyond "fall back to positional". Positional alone would keep suppressing
  a swapped key body: the header stays at the same line, offset and length,
  so the positional fingerprint does not change. The file digest is what
  makes test T17 go red on a body swap. The cost is that any edit to the
  file re-surfaces the finding. For a committed private key or service
  account file that is the right cost.
- **Disclosure:** a committed digest lets someone confirm a guessed
  low-entropy secret. The plaintext already sits in the same repository and
  its history, so the only added exposure is an entry that outlives a
  history rewrite. `--write` regenerates the file and drops stale entries.
- **`count`:** an entry suppresses at most `count` matches with its key, so
  a pasted second copy surfaces.
- **`severity`:** an entry suppresses a match only if the match's current
  severity is no higher than the severity recorded when the entry was
  written. A rule that is raised later surfaces again.

### 3.3 File format and compatibility

`--write` writes `version: 1` with both lists:

```json
{
  "version": 1,
  "fingerprints": ["<positional sha256>"],
  "entries": [
    { "fingerprint": "<content sha256>", "rule": "jwt-token",
      "file": "data/rows.csv", "line": 7187, "severity": "high", "count": 1 }
  ]
}
```

- **1.9.x readers** read only `version` and `fingerprints`
  (`baseline.ts:42-57`), so they keep working with today's semantics. That
  matters because conductor's action pin and local hooks lag the release.
- **Header-only findings stay out of `fingerprints`.** `--write` puts a
  positional key in `fingerprints` only for value-bearing findings. A
  header-only finding gets only its `entries` item (positional key plus
  `file_digest`), so a pinned 1.9.x runner, which reads only `fingerprints`,
  keeps showing it rather than suppressing it with no file digest at all.
- **The written file carries a `comment` string** saying it was written by
  `baseline --write`, which list each version reads, and that `file_digest`
  is a SHA-256 over the file's raw bytes. Readers ignore it.
- **1.10 readers**, when `entries` is present, match **only** on `entries`
  and never fall back to positional matching. A file without `entries` is
  matched positionally, as today.
- **A malformed `entries` list** (not an array, an entry without a string
  `fingerprint`, or a non-positive `count`) suppresses **nothing** and
  raises the existing `baseline.invalid` warning. It does not fall back to
  `fingerprints`, because a fallback would let one broken key quietly
  restore the weaker positional matching. An individual entry whose
  `severity` is missing or not one of the four known levels suppresses
  nothing, and the warning names it.
- **What 1.9.x does not apply.** A 1.9.x reader of the same file uses the
  positional list only. It applies neither `count` nor the severity bound,
  nor the `file_digest` of a header-only entry. That is today's protection,
  not a regression, and it ends when the runner is upgraded.
- **The positional list is anchored at the cwd** (`match-fingerprint.ts:5-11`,
  relative to the run's anchor). A 1.9.x Action or conductor run computes it
  from the repository root, so `--write` must produce root-relative
  positional keys. Decision: inside git, `--write` **refuses to run unless
  the cwd is the repository root** (exit 2, naming the root). The other
  option was to anchor to the git root from anywhere. It was rejected
  because the baseline file must also live at the root to be found by a
  root-anchored run (the config walk only ascends, `config.ts:92-95`).
  Writing from a subdirectory would therefore need two silent relocations,
  of the keys and of the file, and a refusal states the requirement
  instead. A subdirectory **target** run from the root (`baseline sub/`) is
  fine.
- **`rule`, `file` and `line`** are for the reviewer reading the baseline
  diff and are not used for matching. The trust-base proposal summary
  (`trust-base.ts:517-528`) counts `entries` when they are present.
- **JSON output:** `matches[].fingerprint` stays positional, and
  `matches[].content_fingerprint` is added.
- **SARIF:** keeps `partialFingerprints["vault-guard/v1"]` and adds
  `"vault-guard/v2"` (`scan-output.ts:357`, `:417-420`).

### 3.4 Command

```
vault-guard baseline [path]                          # dry run, writes nothing
vault-guard baseline [path] --write
vault-guard baseline [path] --write --include-critical
```

- **What is accepted.** It runs the same plain scan as `scan [path]`: the
  section 2 file set, the working-tree config and the effective `fail_on`.
  It accepts **every finding that would block** (open question 4), **in
  tracked files only**. A value-bearing finding gets a content entry and a
  positional key in `fingerprints`; a header-only finding gets only a
  positional-plus-`file_digest` entry and stays out of `fingerprints` (3.3).
  Outside git there is no tracked set and every file counts (section 8). A finding in an untracked file is never written:
  no digest and no file name enters the baseline. Untracked files are not
  part of the history the baseline describes, and naming one would commit
  a path the author never committed. The command prints only
  `untracked files with findings: N (not accepted; commit or remove them)`.
- **What it prints.** One line per accepted fingerprint, with `file:line`,
  rule and severity. Then
  `kept N, added N, dropped N (no longer found)`, plus `converted N` when it
  upgrades a positional-only file.
- **Critical findings are refused** without `--include-critical`. They are
  listed as "not accepted: critical, rotate and remove instead". The rest is
  still written, and the command exits 1 (open question 5). This guards the
  writer only. The reader trusts the file, because the file's protection is
  review on the base branch.
- **Refusals.** `--trust-base` and `--staged` are refused with exit 2. An
  incomplete scan (anything that makes `scan` exit 2) writes nothing and
  exits 2.
- **Location.** Inside git it always writes `.vault-guard.baseline.json` at
  the repository root and refuses from any other cwd (3.3). Outside git it
  writes the file in the cwd, which is that run's anchor.
- **Exit codes:** 0 written or dry run, 1 written with critical findings
  refused, 2 could not run.
- **Never implicit.** `scan`, `check`, `init`, the hook and the Action never
  write the file. `vault-guard init` prints a one-line hint and nothing more.

### 3.5 Trust boundary

**Can a pull request baseline its own new finding?** Not under
`--trust-base`, and that is already true today:

- the baseline comes from the base ref (`trust-base.ts:621`, `:630-631`);
- `scanCommand` uses it in place of `loadBaseline(outputBase)`
  (`scan.ts:471-477`);
- a head that adds an entry for its own secret produces the proposal line
  `baseline changed in this pull request (1 baseline entry added)`
  (`trust-base.ts:79`, `:526`), and the run still blocks (T11).

**What this does not claim.** A pull request can still mute its own finding
in two ways, and this design leaves both as they are:

1. **Inline directives.** A `vault-guard: ignore-line` or
   `ignore-next-line` the head adds next to its own key is honoured in every
   mode. It is counted and reported, never hidden: `inline_suppressed`,
   with a separate count for critical vendor-anchored findings
   (`scan.ts:330-333`, `:517-518`). It is visible in the diff and in the
   report, but it does not block.
2. **A job run without `--trust-base`.** A CI job that scans a pull request
   in plain mode reads the working-tree baseline (`scan.ts:477`), which is
   the head's. The Action passes `--trust-base` on pull-request events. A
   hand-written workflow that omits it gets no boundary.

**What content keys change.** A base entry now matches the same value, same
rule and same path at any line, up to its count, with header-only rules
bound to the whole file (3.2). A pull request still cannot create a match
for which the base has no entry.

**Costs to document:**

1. **The baseline pull request is itself red.** Its baseline is only a
   proposal. Land it while the gate is advisory (conductor adoption ramp,
   plan item 1.7), or merge it knowingly. No flag lets a head-side baseline
   apply.
2. **Push runs on the default branch use the working-tree baseline**
   (`scan.ts:477`). That is the merged and reviewed file; the README already
   suggests a CODEOWNERS line for it (`README.md:473`).

---

## 4. Interaction with conductor

conductor needs no change in this release, and vault-guard does not come to
depend on it. Contract from 1.10.0:

- **Exit codes keep their meaning:** 0 clean, 1 blocking, 2 could not run.
  A plain scan has two new ways to reach exit 2: a git failure after a
  `.git` was found (2.1), and a tracked path that cannot be examined and is
  not listed by `--deleted` (2.2).
- **JSON is additive only.** The new `run` fields from 2.3 are added, along
  with `run.baseline_entries` (entries loaded, 0 when there are none) and
  `matches[].content_fingerprint`. `matches[].fingerprint` keeps its
  positional meaning, so conductor's `stability: 'positional'` label stays
  correct. conductor can later read `content_fingerprint` and label it
  `content`.
- **The conductor init line for vault-guard** (conductor's change; conductor
  never runs it and never writes the file):

  > secrets (vault-guard): findings already on your default branch block
  > every pull request until accepted. On the default branch run
  > `vault-guard baseline`, review the list, then `vault-guard baseline
  > --write` and commit `.vault-guard.baseline.json` through review. Critical
  > findings are not accepted by default: rotate them.

- **Optional:** conductor may print the same line once when vault-guard
  blocks in pull-request mode and `run.baseline_entries` is 0.
- **Pin timing:** conductor's action pin moves to 1.10.0 in a later conductor
  patch. The dual-list file (3.3) is what keeps a pinned 1.9.1 working in the
  meantime.

---

## 5. Test plan

Each fixture is a temp git repository under `os.tmpdir()`, built with real
commits and driven through the built CLI. Every row names the mutation it
must kill; the implementer applies each mutation once and records the red
run.

| id | Test | Mutation killed |
|---|---|---|
| T1 | Tracked, gitignored `.env` with a key: plain scan exits 1, finds it, `tracked_ignored_files_scanned: 1`, text line printed. | Tester re-applied to the tracked part, or `--cached` dropped. |
| T2 | Untracked, ignored `out/app.js` with a key: not scanned, exit 0. Untracked, unignored `notes.txt` with a key: found. | Exclude option dropped (T2a); `--others` dropped (T2b). |
| T3 | Same committed tree: plain and `--trust-base` scan the same path set. Includes tracked `src/vendor/k.js`, found by both. | Any-depth vendored rule used for tracked files. |
| T4 | Untracked, unignored `pkg/node_modules/x.js` with a key: not scanned. | Anchored rule used for untracked files. |
| T5 | Outside git: existing walk and `.gitignore` tests pass unedited. | Non-git target routed through `ls-files`. |
| T6 | `git init`, no commits, one staged and one untracked key file: both found. | Tracked part built from `ls-tree HEAD`. |
| T7 | Key in a checked-out submodule: found. Tracked symlink to a key file outside the repository: not scanned. | Gitlinks dropped without recursion (T7a); `stat` used instead of `lstat` (T7b). |
| T8 | Untracked nested repository with a key: found. The same repository gitignored: not scanned. | `dir/` entry dropped. |
| T9 | A directory with a `.git` and a key in a tracked file, with `PATH` pointing at a stub `git` that prints a "detected dubious ownership" message and exits 128: plain scan exits 2 and quotes the message. The same stub with no `.git` present: the walk runs, exit 1. | "Inside git" decided by `isInsideGitWorkTree` (T9a, silent walk); git errors caught and routed to the walk (T9b). |
| T10 | One critical and one high finding: `--write` writes the high only, lists the critical, exits 1. With `--include-critical`: both, exit 0. `scan` never creates the file. | Severity check removed (T10a); writer called from `scan` (T10b). |
| T11 | Base has T10's baseline. Head adds a new key and reruns `--write`. `scan --trust-base base` exits 1, the new key blocks, and stdout contains `Proposed, not applied: baseline changed in this pull request (1 baseline entry added)` (`trust-base.ts:79`, `:526`). | Head baseline read in pull-request mode. |
| T12 | Three lines inserted above a baselined finding: suppressed, exit 0. Value replaced by a different one of equal length at the same position: blocking. Run both in plain mode **and** under `--trust-base`, with the baseline committed on the base, so the base-ref load path (`trust-base.ts:541`, `:675`, today a positional `Set`) is covered too. | Line in the content key (T12a); value digest dropped from it (T12b); base-ref path left on the positional `Set` (T12c, red only in the `--trust-base` half). |
| T13 | Baselined line duplicated in the same file: 1 blocking, 1 suppressed. | `count` ignored. |
| T14 | `entries` lacks finding X while `fingerprints` has it: X blocks. A positional-only v1 file still suppresses. Both run in plain mode and under `--trust-base` with the file on the base. | Lists unioned (T14a); positional-only files ignored (T14b); either, on the base-ref path only (T14c). |
| T15 | Entry recorded as `medium`, rule raised to `high` by `severity_overrides`: blocking. | Severity comparison dropped. |
| T16 | `--write` with an unreadable tracked file: exit 2, no file written. `baseline --trust-base x`: exit 2. | Write before the completeness check. |
| T17 | Header-only swap. A tracked PEM file (`ssh-private-key`) is baselined, then its body is replaced with a different key while the header line is unchanged: blocking, in plain mode and under `--trust-base`. The same for a `gcp-service-account` JSON whose `private_key` changes. A unit test also asserts that every rule-table entry declares `valueBearing`, and that exactly these two are false today. The written file's `fingerprints` list does not contain the PEM finding's positional key. A third case baselines the PEM with LF line endings and converts it to CRLF: blocking (raw-byte digest). | Content entry written for a header-only rule (T17a); fallback to positional without `file_digest` (T17b); header-only finding written into `fingerprints` (T17c); digest over line-ending-normalised text (T17d). |
| T18 | Tracked file deleted in the work tree (`rm`, not `git rm`): `tracked_files_missing: 1`, exit per findings. A file left out by `git sparse-checkout set keep`: `tracked_files_missing: 1`, exit per findings. A tracked file under a directory made unreadable (`chmod 000`): exit 2. | Every `lstat` failure counted as missing (T18a); every one treated as exit 2 (T18b); skip-worktree tag ignored, `--deleted` alone (T18c, red on the sparse case only). |
| T19 | Subdirectory target `scan 'sub/[x]'` where `sub/[x]/k.env` is tracked and `sub/x/` also exists: only the literal directory is scanned. A target directory named `:x`: its key is found. | `:(literal)` prefix dropped (red on the `:x` case; see section 8 for why the bracket case alone cannot go red). |
| T20 | `baseline --write` run from `sub/`: exit 2, names the root, writes nothing. `baseline sub/` run from the root, then `scan .` from the root: the finding is suppressed. | Write from any cwd (T20a); keys made relative to the target instead of the root (T20b). |
| T21 | Malformed `entries`: a string in place of the array, then one entry with `"severity": "urgent"`. Nothing is suppressed by the first; the second entry suppresses nothing while its siblings still work; `baseline.invalid` is raised each time. A header-only finding whose entry carries the right positional fingerprint but no `file_digest`: blocking. | Fallback to `fingerprints` on a bad `entries` (T21a); unknown severity treated as `low` (T21b); matching kind taken from the entry's shape, so an entry without `file_digest` matches on its fingerprint alone (T21c). |
| T22 | Tracked `app/build/k.js` and `src/vendor/k.js`: `tracked_nested_vendored_scanned: 2`. A tracked root `vendor/k.js`: skipped, and `Vendored directories skipped: 1 (vendor)` printed in plain mode. | Nested count not computed (T22a); vendored line limited to pull-request mode (T22b). |
| T23 | Merge conflict on a tracked key file (stages 1 to 3): the file is scanned once and the finding reported once. Target reached through a symlinked parent directory: the same file set as through the physical path. | No de-duplication (T23a); no `realpath` before `path.relative` (T23b). |
| T24 | An untracked file with a key in the tree when `baseline --write` runs: the written file contains neither its name nor any digest from it, and stdout shows `untracked files with findings: 1`. | Writer fed the full plain file set. |

**Real-repository validation** (detection-tooling rule): run 1.9.1 and the
candidate over dogfood groups A and C, plus two public repositories that
have committed-but-ignored files and submodules. Record per repository:
`files_scanned`, `file_set`, the new counts, and the blocking findings.
Check the result in under `bench/` as a baseline to diff against. Expected:
the group A `.env` and the group C cache are found by plain runs. A file that
1.9.1 scanned and the candidate does not is a release blocker.

---

## 6. Release shape

### 6.1 Version

1.10.0, minor, on all four packages, with the Action default and tag. A
plain run that was green on 1.9.1 can be red on 1.10.0, and 1.10.0 adds a
command and output fields. Both items ship together: the file-set change
creates the backlog, and the writer is how adopters clear it.

### 6.2 CHANGELOG draft (consumer-cost paragraph)

> **A plain scan inside a git repository now scans tracked files that
> `.gitignore` matches, so a green run can turn red.** Until 1.9.1 a
> directory scan skipped any file `.gitignore` matched, even one already
> committed, while pull-request mode (`--trust-base`) scanned it. A committed
> `.env` was therefore clean on push and blocking on pull requests. Both modes
> now agree. Inside git the file set is the tracked files plus untracked files
> that are not ignored. Tracked files under a nested `vendor`, `build`, `dist`,
> `__pycache__` or similar directory are now scanned too, as pull-request mode
> already did. The run states how many of each it scanned. Outside git
> nothing changes. To clear a new finding, do one of three things:
>
> - rotate the secret and `git rm --cached` the file;
> - declare the path in `ignore.paths`, which is counted on every run;
> - accept the finding with the new `vault-guard baseline --write`. It prints
>   every finding it accepts and refuses critical findings unless
>   `--include-critical` is passed.
>
> Commit the baseline through review. Under `--trust-base` its own pull
> request stays red, because a pull request cannot accept its own findings.
> Land it while the gate is advisory, or merge it knowingly. Run
> `baseline --write` from the repository root; it refuses anywhere else.
> Baselines written by 1.10.0 keep working on 1.9.x, which reads the
> positional list stored in the same file but applies neither the
> per-entry count nor the severity bound. Inline `ignore-line` directives
> are still honoured in pull requests; they are counted in every report.

### 6.3 README and invariants

- **README "Baseline" section** (`README.md:549-555`): rewrite it to cover
  the command (dry run first), the critical refusal, where the file is
  written, and the note that the baseline pull request is red.
- **README pull-request section** (`:416-419`): add that plain scans inside
  git now use the same tracked set.
- **README additions:** a four-row file-set table (outside git, plain inside
  git, `--staged`, `--trust-base`) and the new JSON fields.
- **`docs/INVARIANTS.md`** gains three entries, each naming its test:
  - tracked files are scanned regardless of `.gitignore` in every mode (T1,
    T3);
  - a pull-request run never takes its baseline from the head (T11);
  - only `baseline --write` writes the baseline (T10b).

---

## 7. Design questions (all seven recommendations accepted in review)

1. **Exclude source for untracked files.** Use `.gitignore` only, or
   `--exclude-standard`, which adds `.git/info/exclude` and the user's global
   excludes file? *Recommend `.gitignore` only:* the result is the same on
   every machine, and it is what the tester reads today.
2. **Anchoring vendored names for tracked files in plain mode.** This goes
   beyond the operator's ruling. *Recommend yes:* it closes the same
   disagreement for `src/vendor/` and only adds coverage.
3. **Baseline format.** A dual-list `version: 1`, or a clean `version: 2`
   that older readers reject? A rejected baseline suppresses nothing, so
   every finding blocks. *Recommend the dual list for 1.10.x, and dropping
   `fingerprints` at the next major:* a `version: 2` file would turn every
   pull request red on any runner pinned to 1.9.x.
4. **What `--write` accepts.** Blocking findings only, or all of them?
   *Recommend blocking only:* lower findings stay visible, and lowering
   `fail_on` later surfaces them.
5. **When critical findings are refused.** Write the rest and exit 1, or
   write nothing? *Recommend writing the rest and exiting 1.*
6. **Submodules.** Plain mode keeps scanning checked-out submodules and
   pull-request mode scans none. *Recommend leaving both as they are, and
   recording the pull-request gap in `docs/INVARIANTS.md`:* scanning a
   submodule under `--trust-base` raises its own question of which base ref
   applies.
7. **Severity-bounded suppression.** *Recommend shipping it:* without it, a
   rule raised to critical stays hidden by an entry accepted at a lower
   severity.

---

## 8. Deviations found during implementation

Each of these is a point where the text above and the code or git disagreed,
or where the text was silent, and the fail-closed option was taken.

1. **`git ls-files --deleted` is not enough to call a tracked file missing,
   in either direction.** Probed on git 2.39.3 in temporary repositories:
   - it **omits** skip-worktree entries. After `git sparse-checkout set keep`,
     `ls-files -t --deleted` printed nothing while `ls-files -t --cached`
     tagged the left-out file `S`. The reviewer's recollection is correct.
     With `--deleted` alone, every plain run on a sparse checkout exits 2.
     The builder reads `ls-files -z -s -t --cached` and treats an `S` tag as
     "not in the work tree" too (T18 sparse case; mutation T18c).
   - it **includes** a file under a directory that cannot be entered
     (`chmod 000`): git treats the EACCES from its own `lstat` as deleted.
     With `--deleted` alone, T18a's file is counted as missing and the run
     exits 0. The builder therefore also requires the `lstat` errno to be
     ENOENT or ENOTDIR; any other failure is exit 2 (T18a went red for the
     variant "git's listing alone decides").
2. **A header-only entry's positional key is root-relative.** 3.2 says the
   entry "falls back to the positional fingerprint". The positional
   fingerprint in `fingerprints` is relative to the run's anchor (the cwd).
   An `entries` item sits beside content keys, which are root-relative, so
   its positional key is computed with the path relative to the same content
   root. Inside git `--write` runs at the root, where the two are equal, so
   this only changes what a later run from a subdirectory reads: it matches
   rather than re-surfacing every header-only finding.
3. **Outside git, `baseline` treats every file as tracked.** 3.4 limits the
   writer to tracked files and says nothing about runs outside git, where
   nothing is tracked. Refusing everything there would make the command
   useless outside git; accepting every scanned file matches what the walk
   already scans. Inside git the tracked filter applies exactly as written.
4. **Pull-request mode's `tracked_ignored_files_scanned` asks git, and a git
   failure there is exit 2.** 4 lists two new exit-2 routes, both for plain
   scans. Filling the count in pull-request mode (2.3) needs
   `git ls-files --cached --ignored --exclude-per-directory=.gitignore` at the
   repository root. If that fails the run exits 2 rather than reporting a
   count it did not establish. Pull-request mode has already run git several
   times by then, so this route is unlikely, but it is a third one.
5. **T19 as written cannot kill its mutation.** Without `:(literal)`, git
   matches a pathspec as a literal leading-directory prefix before globbing,
   so `sub/[x]` still lists `sub/[x]/k.env` and does not list `sub/x/...`
   (probed); and the builder drops any path outside the target in any case.
   The bracket case stayed green under the mutation. A second case, a
   directory named `:x` (which git reads as short-form pathspec magic for
   `x`), goes red without the prefix and is what kills the mutation.
6. **T9 runs the built CLI as a subprocess.** jest gives each test file its
   own copy of `process.env`, so a stub `git` put on `PATH` in-process never
   reaches the git that `child_process` starts. Every other row runs
   `scanCommand` or `baselineCommand` in-process, which is the code the CLI's
   action handler calls; one T16 case also drives the built CLI to cover the
   command wiring.
7. **The T10b mutation was run by the reviewer, not the implementer.**
   Calling the writer from `scan` was refused by the implementing session's
   permission classifier and was not worked around; the independent reviewer
   applied it (writer called at the top of `scanCommand`) and T10b went red.

Fix round after independent review:

8. **The writer's "tracked" means the OUTER repository's index (B1).** A
   file of an untracked nested repository was being treated as tracked
   because the builder recursed into it and added its index to the tracked
   set, so `--write` named it in the outer baseline. `collectGitPaths` now
   keeps the outer repository's own `--cached` entries apart
   (`outerTracked`), and only those reach `trackedFiles`. **Submodule files
   are excluded too:** they are scanned, but they are the submodule's
   history, and a pinned submodule commit can change under the outer
   repository without a reviewable diff of the file. They are reported under
   `untracked files with findings` like any other file the baseline will not
   name. T24 gains a nested-repository case.
9. **Location follows the target (N1).** "Inside git" for `baseline` is
   decided from the target's directory as well as the cwd. A target inside a
   repository is keyed and written against that repository's root, and
   `--write` refuses unless the cwd is that root, which covers a cwd outside
   git with a target inside a repository. A cwd inside a repository with a
   target outside it is refused. When neither is in git the command says
   `not a git repository` and writes in the cwd.
10. **A scoped `--write` merges (N2).** `baseline sub/ --write` keeps every
    previous entry whose `file` is outside `sub/` untouched and prints
    `N entries outside the scanned path kept`; kept, added and dropped count
    only entries inside the scope. Merge was chosen over refusing a path
    argument because the reader is unaffected (entries carry their own file
    and are matched independently). The cost is the positional list: its keys
    cannot be attributed to a path, so a scoped write keeps every previous
    positional key, and a stale one inside the scope can survive until the
    next whole-tree `--write`. Only 1.9.x reads that list.
11. **git's stderr on a zero exit is a diagnostic (N3).** git exits 0 over an
    untracked directory it cannot open and says so only on stderr; the walk
    used to report that as `fs.permission_denied`. Each stderr line of a
    successful file-set git call is now a warning diagnostic,
    `fs.permission_denied` when it says permission denied and `git.warning`
    (a new code) otherwise.
12. **Under `--staged` the file digest is over the index blob (N5).** The
    reader's header-only `file_digest` comparison read the working tree even
    when the scanned content came from the index, so a staged key body swap
    with the old bytes restored in the working tree was suppressed. A
    `--staged` run now passes `readGitIndexBytes` as the byte source.

Mutation log (each applied once, the named test run, then restored): T1
(tester on the tracked half; `--cached` dropped), T2a, T2b, T3, T4, T5 (the
walk-mode suites in `directory-pr-fail-closed.test.ts` and the MCP
`workspace-scan.test.ts` went red; the core `file-utils-ignore.test.ts` drives
the sync walker, which this change does not touch, and stayed green), T6, T7a,
T7b, T8, T9a, T9b, T10a, T11, T12a, T12b, T12c (red only in the
`--trust-base` half, as planned; T14c falls out of the same mutation), T13,
T14a, T14b, T15, T16, T17a, T17b, T17c, T17d, T18a, T18b, T18c, T19 (the `:x`
case), T20a, T20b, T21a, T21b, T21c, T22a, T22b, T23a, T23b, T24: all red for
the stated reason. T10b: red, run by the reviewer (item 7). Fix round: the
nested-repository T24 case (every listed tracked path put back into
`trackedFiles`), the `--staged` digest case (working-tree byte source
restored), and the untracked unenterable-directory warning (stderr lines
dropped): all red, then restored.
