# Tracked content from git, no links on control paths, and the locale rule

Status: design, revised after an independent design review (four blocking
spec defects fixed: disk-copy decoding, files git is told not to look at,
`config validate` and dangling links, the `--staged` environment). Section
13 was ruled in scope 2026-10-12. Target: 1.10.0, all four packages in
lockstep, together with the file-set and baseline work already on `main`
(`docs/design/2026-10-11-plain-scan-file-set-and-baseline.md`, "the 10-11
design" below). This doc extends that one. It covers three merge-blocking
findings and one non-blocking finding from an independent audit on
2026-10-12:

- **MB1.** A head-side `.gitattributes` line (`working-tree-encoding`) makes
  the checkout write a tracked file as BOM-less UTF-16, which the scanner
  reads as UTF-8 and passes. It mutes pull-request mode and plain mode.
- **MB2.** `vault-guard baseline --write` follows a committed symlink at the
  baseline path and overwrites a file outside the repository. The reader
  follows it too and echoes the start of the target in a parse warning.
- **MB3.** Any two-letter file name (`db.ts`, `ci.yml`, `sa.json`) is treated
  as a translation catalogue, which downgrades DSNs, private keys and JWTs to
  `low`, exit 0.
- **N1.** File-set git calls inherit a hook's `GIT_INDEX_FILE`, so submodule
  recursion reads the wrong index.

**Decided before this doc, not reopened** (operator rulings):

1. MB1, option A: in pull-request mode, and in plain mode inside a git
   repository, tracked files are read from the git blob, not the working
   tree. Untracked files are read from disk. Reads are batched.
2. `.gitattributes` (root and nested) becomes a pull-request control file.
3. MB2: the baseline path is `lstat`-checked on read and on write; a symlink
   is refused with exit 2 naming the path. JSON parse error text is never
   echoed.
4. MB3: the locale basename rule fires only with a locale directory on the
   path, and the DSN rules, `ssh-private-key` and `jwt-token` are never
   downgraded by the locale rule.
5. N1: file-set git calls run with a clean git environment.
6. Everything ships in 1.10.0, a minor. Findings may newly appear.

Line citations are against `main` at adc39e5, the commit the audit read and
this branch was cut from. Each was checked against the code; section 1.5
lists where the audit's citations did not match.

---

## 1. Current behaviour

### 1.1 MB1: content is read from the working tree

Pull-request mode builds its file set from the HEAD tree
(`listHeadTreeFiles`, `packages/core/src/trust-base.ts:603-616`, `git ls-tree
-r -z HEAD`) and filters it in `getPullRequestFilesToScan`
(`packages/core/src/utils/file-utils.ts:635-716`). Plain mode inside git
builds its tracked half from `git ls-files -z -s -t --cached`
(`collectGitPaths`, `file-utils.ts:806`, the listing at `:832`) and sends it
through the same function. Both then hand bare paths to `scanFilesAsync`
(`packages/cli/src/utils/scan-utils.ts:635-824`), which calls
`scanner.scan(file)` (`scan-utils.ts:765`), which reads the working tree:
`decodeTextBuffer(fs.readFileSync(filePath))`
(`packages/core/src/scanners/secret-scanner.ts:525`). The decoder trusts only
a byte-order mark (`packages/core/src/utils/text-decode.ts:30-41`); anything
else is UTF-8. `ls-files -s` and `ls-tree` both print the blob id, and both
parsers throw it away (`file-utils.ts:832-835`; `trust-base.ts:607-613`).

A checkout applies `.gitattributes` transforms between the blob and the
file on disk: `working-tree-encoding` re-encodes, `eol`/`text` convert line
endings, `filter` runs a smudge driver, `ident` expands `$Id$`. A pull
request controls the head's `.gitattributes`, and `CONFIG_FILENAMES`
(`trust-base.ts:62`) plus `BASELINE_FILENAME` (`trust-base.ts:637-638`) are
the only control inputs. So one added line,
`src/leak.ts working-tree-encoding=UTF-16LE`, turns the committed UTF-8 key
into BOM-less UTF-16 on disk, the scan passes, and the report says
`Proposed, not applied: none`. `--staged` is not affected: it reads the index
blob (`readGitIndexBytes`, `packages/core/src/utils/git-utils.ts:250-302`),
which is the bytes git will commit.

### 1.2 MB2: the baseline path is followed

The writer builds `outPath` as root plus `.vault-guard.baseline.json`
(`packages/cli/src/commands/baseline.ts:299`), reads it with `readFileSync`
(`:301-303`) and writes it with `fs.writeFileSync` (`:393`). Nothing calls
`lstat`, so a committed symlink at that path is followed on both. The reader
is the same shape: `loadBaseline` uses `existsSync` and `readFileSync`
(`packages/core/src/baseline.ts:175-197`, the read at `:179-183`), and `parseBaselineText` returns
`JSON: ${detail}` with the `JSON.parse` message (`baseline.ts:165-167`). On
Node 22 that message quotes the first characters of the input. `scanCommand`
puts it into a `baseline.invalid` diagnostic, which reaches JSON and SARIF,
and prints it in text (`packages/cli/src/commands/scan.ts:501-513`). The
config loader has the same two gaps: `loadConfig` follows a link
(`packages/core/src/config.ts:165-189`) and `parseConfigText` echoes the
`JSON.parse` message (`config.ts:146-152`).

### 1.3 MB3: two-letter basenames are locale files

`LOCALE_BASENAME` (`packages/core/src/utils/path-severity.ts:111`) matches
any two lowercase letters with an optional region and a `json`, `yaml`,
`yml`, `ts`, `js`, `po` or `properties` extension. `isLocalePath`
(`:122-126`) returns true on that alone. It feeds
`isLowPrecisionContextPath` (`:165-167`) and the docs-only test (`:185-186`).
On a locale path every id in `LOW_PRECISION_PATH_DOWNGRADE_IDS`
(`packages/core/src/utils/path-downgrade-ids.ts:4-15`) drops to `low`: the
four DSN rules, `ssh-private-key` and `jwt-token` included. The dogfood test
pins the bare-basename case as intended (`src/en.json` in
`packages/core/src/scanners/__tests__/dogfood-fp.test.ts:117-125`). Present
since 1.4.0.

### 1.4 N1: the hook's git environment leaks into the file set

`runFileSetGit` (`file-utils.ts:732-739`) calls `spawnSync('git', ...)` with
no `env`, so it inherits the caller's. A pre-commit hook runs with
`GIT_INDEX_FILE` set (a relative `.git/index` for `git commit`, a temporary
index for `git commit -a`). The recursion into a submodule or nested
repository (`file-utils.ts:841`, `:872`) runs git in that directory with the
outer repository's index variable, which fails ("index file open failed: Not
a directory") or lists the wrong repository's paths (four bogus "tracked
files missing" in the audit's run).

### 1.5 Where the audit's citations did not match

All cited lines were checked at adc39e5. Mismatches and gaps:

- **The staged read is not `git show`.** The audit and the coordinator's
  notes say `--staged` reads through `git show :path`, citing
  `scan-utils.ts:381` and `:498`. Both lines are comments, and both are
  stale. The code is `readGitIndexBytes` (`git-utils.ts:250-302`): one `git
  ls-files -s -z -- <path>` to find the stage-0 blob id, then one `git
  cat-file blob <id>`, so two processes per staged file. It was moved off
  `git show` on purpose (`git-utils.ts:220-237`, the `0:` stage-reference
  bypass). The comments should be corrected in the same change.
- **`trust-base.ts:59`** is `FORCED_GIT_CONFIG`. The config names are at
  `:62`; the baseline name enters at `:637-638`.
- **`path-severity.ts:165-166`** covers one of two uses. The second,
  `:185-186`, decides whether the docs exemption for `ssh-private-key`
  applies, and has to change too (section 5).
- **Not in the audit, same class as MB2:** `parseConfigText` echoes the
  `JSON.parse` message (`config.ts:146-152`), and the hook installer writes
  repository paths with `existsSync` then `writeFileSync` or
  `appendFileSync` and no `lstat`
  (`packages/core/src/scanners/pre-commit-hook.ts:390`, `:453`, `:552`,
  `:560`, `:624`, `:666`, `:723`). A committed `.husky/pre-commit` symlink
  would be appended to wherever it points. Reasoned from the code, not
  reproduced. The config part is folded in below (ruling 3 invites it); the
  hook writers are section 13, pending an operator decision.
- **Not in the audit, same class as MB2:** `vault-guard config validate`
  finds its file with `findVaultGuardConfigPath`, which uses `existsSync`
  (`packages/core/src/config.ts:115-124`), then reads it with
  `readFileSync` and prints the `JSON.parse` message
  (`packages/cli/src/commands/config.ts:14-35`). It follows a link and
  echoes the start of the target. Folded in below (4.1, 4.2).
- **Not in the audit:** `listHeadTreeFiles` returns `[]` when `git ls-tree`
  fails (`trust-base.ts:604-605`). Only the zero-files backstop
  (`scan.ts:474-485`) turns that into exit 2, and only when no other target
  scanned a file. Section 2.6 makes it an explicit exit 2.
- **There is no `--max-file-size` flag.** The size limit is the constant
  `MAX_SCAN_FILE_BYTES`, 32 MiB (`packages/core/src/utils/scan-file.ts:16`),
  which `scan-utils.ts:153` copies into the default `MAX_FILE_SIZE` for the
  internal `maxSize` option. "Size limit" below means that.

---

## 2. Tracked content from git (MB1)

### 2.1 Rule

The source of a file's content is decided per file, not per target type, so
a tracked file named on the command line is read the same way as one reached
through a directory.

| Run | Tracked file | Untracked file |
|---|---|---|
| `--trust-base` | HEAD tree blob. Also the disk copy when it differs from HEAD or carries a `filter` attribute (2.4). | Not in the file set (unchanged). |
| Plain, inside git | Index (stage 0) blob; stage 2 and 3 blobs for a conflicted path. Also the disk copy when it differs from the index, carries a `filter` attribute, or is marked assume-unchanged or skip-worktree and present on disk (2.4). | Disk (no blob exists). |
| `--staged` | Index blob (unchanged, moved onto the shared reader, 2.3). | Not in the file set. |
| Outside git | n/a | Disk (unchanged). |

**A tracked symlink named on the command line** (`scan link.txt`, mode
`120000` in the listing) gets two reads, and never loses the coverage a
named link had before:

1. Its blob, the link text, is scanned like any blob (`source: index` or
   `head`).
2. The link is resolved once, with `fs.realpathSync`, and the result is
   compared with the canonical repository root. If it resolves to a regular
   file inside the root, that file is scanned from disk as `source:
   worktree`, reported under the path the user gave. If it resolves outside
   the root, is dangling, loops, or resolves to something other than a
   regular file, it is not followed: the run prints a warning naming the
   path and the reason (`link.txt: symlink target is outside the repository,
   not followed`; `... target does not exist, not followed`; `... target is
   not a regular file, not followed`), records a `symlink.not_followed`
   warning diagnostic, and does not exit 2 for it, because the blob was
   scanned.

This applies only to a link named explicitly. Directory scans keep skipping
symlinks as today, in every mode. In pull-request mode the resolution reads
the checkout, so a head-side link can only point the extra read at a file
inside the repository, which is itself tracked or untracked content of the
same checkout; it cannot remove the blob read.

**The boundary, stated.** Untracked files have no blob, so they are read
from disk and keep the BOM-only decoder: BOM-less UTF-16 in an untracked
file is still not detected. That is not a pull-request vector, since
everything a pull request carries is tracked. The disk copy of a tracked
file, when it is scanned in addition to the blob (2.4), is decoded by its
BOM first and then by its declared `working-tree-encoding` through the
label map in 2.4; an encoding outside the map is scanned as UTF-8 and
reported as a coverage line. Either way the blob is always scanned, so the
extra read can add findings and never removes one. `scan_file` in the MCP
server keeps reading the named file from disk; it answers "what is in this
file now" for an agent and has no trust-base mode. `fix` edits files on
disk and is unchanged. The VS Code extension scans editor buffers, so its
content path is unchanged, but it loads config through `loadConfig`: its
`safeLoadConfig` (`packages/vscode-extension/src/extension.ts:19-30`) turns
a `ConfigError` into a warning and falls back to the built-in defaults, so
a symlinked config now produces that warning and default rules in the
editor (section 9).

### 2.2 Which blob

**Pull-request mode reads the HEAD tree entry.** It is the tree under
judgment and already the file set's source (`trust-base.ts:574-602` argues
HEAD over the index for exactly this mode). The blob id comes from the same
`ls-tree -r -z HEAD` record that names the path.

**Plain mode reads the index (stage 0) entry, not HEAD.** Four reasons:

1. The tracked half of the file set already comes from `ls-files --cached`,
   which is the index, and its records already carry the stage-0 blob id. A
   HEAD read would need a second listing and would disagree with the file
   set: a staged new file has no HEAD entry at all.
2. A fresh repository has no HEAD (10-11 design, T6). An index read works
   there; a HEAD read would have nothing to read.
3. The index is what the next commit will contain. A secret that is staged
   and then removed from the working copy (edit, `git add`, revert the file)
   sits in the index and not on disk. Reading HEAD and disk would miss it;
   reading the index finds it.
4. Plain mode judges the developer's own tree (10-11 design, 2.1). The index
   plus the disk copy when it differs covers both halves of that tree.

**Conflicted paths** are recognised from the `ls-files -s` stage column
(stages 1 to 3, no stage 0), not from `git status`. They read the stage 2
and stage 3 blobs, plus the disk copy, which holds the conflict markers.
Stage 1 is the merge base and already in history. In 2.5 both stage blobs
are on the blob side (B), stage 2 entered into the multiset first, then
stage 3; the disk copy is W.

**A tracked file staged and then deleted on disk** has an index blob that
the next commit will contain. The rule: a path listed by `--deleted` with
`lstat` ENOENT is scanned from its index blob, with `source: index`, only
when the first `git status` column (index against HEAD, from the call 2.4
already makes) is not a space, that is `AD` or `MD`: the index holds
content HEAD does not. It is still counted in `tracked_files_missing`, so
the count keeps meaning "not in the working tree". A committed file removed
with plain `rm` and not yet staged (` D`) is only counted, as in the 10-11
design. The reason for the limit: its index blob is just the committed
content, and scanning it would make a plain-scan hook on `git commit -a`
block the very commit that removes an accidentally committed secret file
(under the clean environment the hook lists `.git/index`, where that file
is still present). This widens the 10-11 design, which left all such files
unscanned. A skip-worktree entry that is absent on disk (a sparse checkout)
stays unscanned and counted, as before: its blob may not be local in a
partial clone, and reading it could start a network fetch.

### 2.3 Mechanism: one reader, generalised from the staged path

A new module, `packages/core/src/utils/blob-reader.ts`, replaces the
per-file `ls-files` plus `cat-file blob` pair in `readGitIndexBytes` and
serves all three modes. It reads by **object id only**. A path never reaches
git's revision grammar, which keeps the property the staged path was
hardened for (`git-utils.ts:220-237`).

Per repository (the outer one, and each submodule or nested repository the
file set recursed into, since each has its own object store), at most two
long-lived processes:

```
git -c core.quotePath=false cat-file --batch-check     # stdin: one object id per line
git -c core.quotePath=false cat-file --batch           # stdin: one object id per line
```

- **`--batch-check` runs first**, over every object id the run will read,
  and answers `<oid> <type> <size>` or `<oid> missing`. Sizes decide the
  size limit before any content moves, and a missing object is known before
  scanning starts.
- **`--batch` streams content** in request order: `<oid> blob <size>`, then
  `size` bytes, then a newline. The reader keeps a FIFO of pending requests
  and a bounded window: it writes at most `concurrency` object ids (10, the
  existing scan concurrency) ahead of what it has consumed. Memory is
  therefore bounded by the window, at most 10 times the 32 MiB limit, and in
  practice the size of ten ordinary source files.
- **Identical blobs are read once.** Two paths with one object id share the
  bytes; the scan still runs per path, because path context changes
  severity.
- **No `--buffer`.** git flushes after each object, so a windowed request is
  answered without waiting for stdin to close.
- **The environment is a parameter.** The reader takes the `env` its
  processes run with and never chooses one itself. Plain and pull-request
  runs pass `cleanGitEnv()` (section 6). `--staged` passes `process.env`
  unchanged, to every git call it makes, `cat-file` included. The reason is
  a repository located only through the environment: a bare dotfiles
  repository driven by `GIT_DIR` and `GIT_WORK_TREE`, or a hook's
  `GIT_INDEX_FILE`. The staged listing finds its object ids through those
  variables; a `cat-file` run without them would look in a different object
  store, or in none, and fail or read the wrong blob.

Where the object ids come from:

| Mode | Source of `path -> oid` | New git calls |
|---|---|---|
| `--trust-base` | `git ls-tree -r -z HEAD`, already run by `listHeadTreeFiles`; the parser keeps the object column. | none |
| Plain | `git ls-files -z -s -v --cached -- <spec>`, already run by `collectGitPaths` (with `-t` today); the parser keeps the tag, object and stage columns. `-v` replaces `-t`: it prints the same tags, lowercased for assume-unchanged entries (2.4). | none |
| `--staged` | The staged listing itself, switched from `--name-only` to `--raw --no-abbrev` (below). | none; replaces N |
| Explicit tracked file target | Batched: the named files are grouped by the toplevel `git rev-parse --show-toplevel` reports for each (a named file inside a submodule belongs to the submodule), and each group is one `git ls-files -z -s -v -- :(literal)<path> ...` (plain) or one `git ls-tree -z HEAD -- :(literal)<path> ...` (pull-request), run at that toplevel. | one per repository named into |

**The staged listing.** `STAGED_DIFF_ARGV` (`git-utils.ts:116-132`) becomes
`--raw --no-abbrev` in place of `--name-only`, with every other argument
unchanged (`-c diff.relative=false`, `-c core.quotePath=false`,
`--diff-filter=ACMRT`, `--ignore-submodules=all`, `-z`). Each record then
carries the new side's mode and object id, so no second listing is needed.
The parser takes the destination path of an `R` or `C` record. The pinning
test is updated to the new argv and still asserts every safety flag. A
whole-index `ls-files -s` was rejected: on a very large index its output
grows with the index rather than with the commit, and it would need its own
`maxBuffer`. A staged entry of mode `120000` (a symlink) stays readable: its
blob is the link text, which is scanned as text, exactly as today.

The staged move must be behaviour-neutral: every existing `--staged` test,
including the `0:` stage-reference test, passes unedited apart from the
argv pin.

**The synchronous exports keep per-file spawns.** `readGitIndexBytes` and
`readGitIndexFile` are public and synchronous, and the baseline's `readBytes`
hook (`scan.ts:531`) is synchronous too. A long-lived batch process cannot
serve a synchronous call, so these keep today's two spawns per file. No scan
path uses them any more: the scan reads through the async reader, and the
baseline's file digests come from bytes kept from the scan (2.8), so neither
the reader nor the writer calls back into a per-file spawn.

**Data flow.** `collectGitPaths` and `listHeadTreeFiles` return a
`Map<absolutePath, { repoTop, oid, stage }>` beside the path lists.
`PlainFileSetInfo` gains `blobs` (that map) and `worktreeAlso` (paths whose
disk copy is scanned as well, 2.4); `TrustedControls` gains `headBlobs`.
`scanFilesAsync` takes an optional `contentSource` that, for a path, answers
`{ blob?: Promise<Buffer>, disk: boolean }`. The scan step changes from
`scanner.scan(file)` to the shape the staged path already uses
(`scan-utils.ts:502-522`): bytes, `decodeTextBuffer`, `scanner.scanContent`
with the file path, then `applyPathAwareSeverity`. Each resulting
`SecretMatch` carries a new `source`: `index`, `head` or `worktree`.

### 2.4 When the disk copy is scanned as well

The disk copy of a tracked file is scanned in addition to its blob when any
of three holds:

- **git says the working copy differs from the blob being read.** One call
  per repository, with `GIT_OPTIONAL_LOCKS=0` so it never writes the index:

  ```
  git -c core.fsmonitor=false -c core.quotePath=false status --porcelain=v1 -z \
      --untracked-files=no --ignore-submodules=all --no-renames -- <spec>
  ```

  Plain mode: the second status column (working tree against index) is `M`,
  `T` or `A` (`A` is an intent-to-add entry, whose index blob is empty).
  Pull-request mode: either column is not a space, so the disk copy differs
  from HEAD by way of the index or directly. `D` is not a difference to
  scan: that file is absent, and the 10-11 design's missing-file rule
  applies (with the `AD` widening in 2.2). Conflicts are not taken from
  these columns; they come from the stage column (2.2). `status` is used
  rather than `diff-files` because it checks content for a file whose stat
  data is stale instead of listing it as modified; `core.fsmonitor=false`
  stops a monitor hook from deciding the answer.
- **git has been told not to look at the file.** `status` is silent about
  an entry marked assume-unchanged (`git update-index --assume-unchanged`,
  or every entry added while `core.ignoreStat` is true) and about a
  skip-worktree entry, whatever is on disk. The common case is deliberate: a
  tracked config template marked skip-worktree so a developer can put real
  local credentials in it without git showing the edit. A plain scan that
  read only the blob would see the template and pass. The `ls-files -s -v`
  call already made (2.3) tags these entries: a lowercase tag is
  assume-unchanged, `S` (or `s`) is skip-worktree. The disk copy is scanned
  as well when the tag is lowercase, or when it is `S` or `s` and the file
  is present on disk. (A skip-worktree file present on disk is in the file
  set today: `collectGitPaths` adds every non-gitlink entry to `tracked`
  and only records the `S` tag, `file-utils.ts:845-850`, and the 10-11
  design counts it missing only when `lstat` also fails, its lines
  188-196.) This item does not apply under `--trust-base`: the file set and
  the blobs come from the HEAD tree, which carries no such flags, a fresh
  CI checkout sets none, and a disk copy that differs from HEAD for any
  other reason is already caught by the first item.
- **The path has a `filter` attribute.** One call per repository:

  ```
  git -c core.quotePath=false check-attr -z --stdin filter working-tree-encoding
  ```

  with every tracked path in the file set on stdin. Any `filter` value
  other than `unspecified` or `unset` counts. Under Git LFS the blob is a
  pointer and the real content exists only on disk; `status` runs the clean
  filter and reports no difference. Without this rule, 1.10.0 would stop
  scanning LFS content that 1.9.1 scans today.

`status` compares the disk copy after git's own clean conversion, so a file
whose only difference is the checkout transform (line endings, encoding) is
not listed and is not read twice.

**Decoding a disk copy.** Blobs are always decoded by `decodeTextBuffer`
(BOM, else UTF-8): git stores the canonical UTF-8. A disk copy is decoded
in this order:

1. **A BOM always wins.** `FF FE`, `FE FF` or `EF BB BF` at the start
   selects the encoding, whatever the attribute says.
2. **No BOM, and a `working-tree-encoding` the label map knows:** decode
   with the mapped encoding. The map is explicit, keyed on the upper-cased
   label git was given:
   - `UTF-16LE` to `utf-16le`, `UTF-16BE` to `utf-16be`;
   - `UTF-8`, `UTF-16`, and every label ending in `-BOM` (`UTF-16LE-BOM`,
     `UTF-16BE-BOM`, `UTF-8-BOM`) route to the BOM sniff, because git writes
     those with a BOM and step 1 has already decided them; with no BOM
     present they fall through to UTF-8;
   - the legacy encodings in the WHATWG Encoding standard that git users
     declare in practice: `SHIFT_JIS` (and `SJIS`, `CP932`), `EUC-JP`,
     `ISO-2022-JP`, `EUC-KR`, `GBK`, `GB18030`, `BIG5`, `WINDOWS-1250` to
     `WINDOWS-1258`, `ISO-8859-1` to `ISO-8859-16` (those WHATWG defines),
     `KOI8-R`, `KOI8-U`, each to its WHATWG name.
   A unit test constructs a `TextDecoder` for every mapped name on Node 22
   and fails if any throws.
3. **Anything else is unsupported** (`UTF-32` in any form, any label not in
   the map, any label whose decoder throws). This is **not exit 2**: the
   blob is always scanned, so an undecodable disk copy is a coverage gap on
   that copy only. The copy is decoded with the BOM sniff and UTF-8, and
   the run reports it: an `encoding.unsupported` warning diagnostic, the
   JSON list `run.worktree_undecodable` (path and label), and in text, when
   non-zero,
   `Working-tree copies in an encoding vault-guard cannot decode, scanned as UTF-8: N (src/a.txt: UTF-32, ...)`,
   naming up to three paths. The exit code is unchanged.

A disk copy scanned because of a `filter` attribute is decoded twice when
the attribute map applies: once with the declared encoding and once with
the BOM and UTF-8 sniff, and both results go through 2.5. A smudge filter
can produce bytes in any encoding, and the declared label describes git's
conversion, not the filter's output.

Facts the implementer would otherwise rediscover (measured by the design
reviewer on Node 22 and git on macOS):

- `new TextDecoder('UTF-16')` is little-endian only; it does not honour a
  big-endian BOM. Never pass `UTF-16` to `TextDecoder`; that is why it
  routes to the BOM sniff.
- git converts `working-tree-encoding=UTF-16` through iconv, and on macOS
  writes it big-endian with a BOM.
- `new TextDecoder('UTF-16LE-BOM')` and `new TextDecoder('UTF-32')` throw
  `RangeError`. Hence the `-BOM` routing and the unsupported path.

In pull-request mode these attributes come from the head's working tree.
That is safe because they can only add a disk read or change how an extra
copy is decoded. The blob is scanned whatever they say.

### 2.5 Reporting once per distinct finding

A file can produce matches from its blob (B) and from its disk copy (W). The
merge runs in three steps, per file:

1. **Value-bearing matches** (those with a `valueDigest`): build a multiset
   of `(rule, valueDigest)` over B. For a conflicted path, the stage 3
   matches are first deduplicated against the stage 2 matches by this same
   rule, so a value present in both stages is reported once, from stage 2;
   B is then stage 2 plus the surviving stage 3 matches, and W is
   deduplicated against that. A W match whose pair is still in the
   multiset is dropped and the count decremented; the rest are kept. So the
   same secret on both sides is reported once, from B, and a second pasted
   copy that exists only on disk is still reported.
2. **The baseline** is applied to B and the surviving W in one pass, B
   first, so an entry's `count` is spent on B before W. A header-only
   entry's `file_digest` is compared with the bytes each match came from:
   the blob for B, the disk copy for W (2.8).
3. **Header-only matches** (`ssh-private-key`, `gcp-service-account`): a W
   match is dropped only when an unsuppressed B match has the same rule,
   line, offset and length. A W match whose B twin was suppressed by the
   baseline stays and is judged on its own bytes; since the disk copy
   differs, its digest does not match and it is reported. That is the 10-11
   design's stated cost for header-only rules (any edit re-surfaces the
   finding), not a new one, and it closes a key-body swap made in an
   unstaged edit.

The output says which copy a finding came from:

- **JSON:** `matches[].source`, one of `index`, `head`, `worktree`, or
  `file` (an untracked file, a run outside git, an MCP `scan_file`).
  Additive.
- **SARIF:** `result.properties["vault-guard/source"]`, same values.
- **Text:** a suffix only when the file's disk copy was also scanned:
  `(index)` or `(head commit)` on blob findings, `(working tree, not in the
  index)` or `(working tree, not committed)` on disk findings; for a
  conflicted path, `(index, ours)` and `(index, theirs)` for stages 2 and
  3. A clean tree
  prints byte for byte what it prints today, which matters because the
  plain summary is pinned byte for byte (10-11 design, 2.3).
- **Run fields:** `run.content_source` (`git` or `disk`) and
  `run.worktree_copies_scanned`. Text line, only when non-zero:
  `Tracked files whose working-tree copy differs, both scanned: N`.

### 2.6 Failure modes

A `.git` was found, so the content of a tracked file has to come from git.
None of these falls back to reading the disk copy alone.

| Failure | Result | Exit |
|---|---|---|
| A `cat-file` process cannot start, exits non-zero, or its output does not parse (desync, short read). | `GitError` quoting git's stderr: "could not read committed content for tracked files ... Nothing was scanned." Caught by the existing `GitError` branch (`scan.ts:832-836`). | 2 |
| `--batch-check` answers `<oid> missing`. | That file is recorded as `read_error`: "the committed blob for this tracked file is not in the local object store (a damaged repository, or a partial clone that cannot fetch it)". The run continues, so every such file is named, then reports INCOMPLETE with the usual exclude hint. | 2 |
| An object id resolves to a type other than `blob`. | `GitError`. Listings only yield blob entries, so this means the repository changed under the run. | 2 |
| A blob over 32 MiB (from `--batch-check`). | `too_large`, same record, wording and exclude as a file over the limit on disk. Its disk copy is not read separately. | 2 |
| `status` or `check-attr` fails. | `GitError`. A run that cannot tell whether the disk differs does not assume it does not. | 2 |
| A disk copy that 2.4 says to read cannot be read. | `read_error` naming the file. | 2 |
| A disk copy whose `working-tree-encoding` is unsupported (2.4). | Decoded with the BOM and UTF-8 sniff, reported as a coverage line and `encoding.unsupported` warning. Not a failure. | unchanged |
| `git ls-tree -r -z HEAD` fails under `--trust-base`, including output over its buffer. | `TrustBaseError` (new; today `listHeadTreeFiles` returns `[]`). Its `maxBuffer` is raised from 64 MiB (`trust-base.ts:93`) to the 512 MiB `runFileSetGit` uses (`file-utils.ts:738`), and an `ENOBUFS` failure says the tree listing was too large rather than quoting a buffer error. | 2 |
| `git diff-tree` for `.gitattributes` fails under `--trust-base` (section 3). | `TrustBaseError`. | 2 |

A partial clone may fetch a missing blob on demand; vault-guard does not
set `GIT_NO_LAZY_FETCH`. Blobs of checked-out files are already local. A
skip-worktree file that is present on disk is in the file set and its blob
is read, but a file a sparse checkout left out is absent on disk and stays
out of the file set (2.2), so a lazy fetch is not expected on an ordinary
run. If one is needed and fails, the missing-object row above applies.

The MCP workspace scan reports the same failures as `isError` or as
unscannable entries, as it does for git failures today.

### 2.7 Performance budget

New git work per repository: the two `cat-file` processes, one `status`,
one `check-attr`. Nothing is spawned per file. Counted per repository:

- **Plain mode:** 5 existing file-set calls in `collectGitPaths`
  (`rev-parse --show-toplevel`, `ls-files -s` (now `-v`), `ls-files
  --deleted`, `ls-files --ignored`, `ls-files --others`) plus 4 new
  content calls, 9 file-set and content calls in all.
- **Plain mode, outside that count:** two more `rev-parse --show-toplevel`
  calls that decide path roots, not the file set: one per target in
  `resolveContextRoot` (`packages/cli/src/utils/scan-utils.ts:136`; the
  plain path at `scan.ts:428-442` passes no `pathRoot`, so it runs), and
  one in `resolveContentRoot` through `getGitWorkTreeRoot` (`scan.ts:89`,
  called at `:521`). Both also run with `cleanGitEnv()` in plain and
  pull-request mode, for the same reason as ruling 5: a hook's
  `GIT_DIR` or `GIT_WORK_TREE` must not move the root a path is judged
  against. `--staged` keeps the inherited environment for its root lookups
  too, as for every other staged git call (section 6).
- **Pull-request mode:** the existing trust-base calls (ref resolution,
  control-file lookups, `ls-tree -r HEAD`, the tracked-ignored listing),
  plus the same 4 new per repository, plus one `diff-tree` per run for
  `.gitattributes` (section 3).
- **`--staged`:** the existing listing (now `--raw`) plus the 2 `cat-file`
  processes, replacing 2 per staged file.

None of these grows with the number of files. That is a hard requirement:
the per-file alternative is two spawns per file, about 14,000 spawns on a
7,000-file repository, at roughly 2 to 5 ms each on macOS and Linux, so 30
to 70 seconds before any scanning.

Expected cost on a repository the size of facebook/react (7,082 files
scanned in 2.9 s by the 1.10.0 candidate in the audit's run). These are
estimates from git's known behaviour, not measurements; section 8 measures
them:

- `--batch-check` over about 7,000 ids: tens of milliseconds;
- `--batch` content: bounded by zlib inflate and delta resolution, a few
  hundred MB/s from packfiles, so roughly 0.3 to 1 s for a tree of that
  size, partly overlapped with scanning;
- `status` over 7,000 files with fresh stat data: about 50 to 300 ms;
- `check-attr` over 7,000 paths: under 100 ms.

**Budget:** wall time on the React run no more than 1.5 times the adc39e5
candidate's on the same machine, median of three runs. Over that is a
release blocker until it is understood. U1 counts file-set and content git
invocations: exactly 9 for a plain scan of a single repository with no
submodules, never more than 2 `cat-file` per repository, and none whose
count grows with the number of files. The two root `rev-parse` calls above
are outside that count; U1 filters them out by argv and the cwd they run
in, and asserts separately that both ran with `GIT_INDEX_FILE` unset.

### 2.8 Interactions

**`--staged`.** Content source unchanged (the index blob); only the reader
underneath moves (2.3). The staged run passes `process.env` to the reader
and to every other git call, on purpose (2.3, section 6): in a `git commit
-a` hook the temporary index is what will be committed, and in a repository
located through `GIT_DIR` the object store is only reachable through it.

**`--trust-base`.** File set unchanged: HEAD tree regular files, filtered
by `getPullRequestFilesToScan`, including its `lstat`/`isFile` check on the
disk path. Keeping that check means the file set is exactly the one the
10-11 design and its tests define; a HEAD file missing from the checkout is
still exit 2. Content now comes from the HEAD blob.

**Size limit.** Judged on the blob's size for the blob and on `lstat` size
for a disk copy, the same 32 MiB constant. As today, the limit is on raw
bytes, never on decoded text.

**Binary and type filters.** Applied by path before anything is read, as
today: `isBinaryFile` by extension (`scan-utils.ts:201-204`, `:626-629`),
the type filter and config `ignore` in the file-set builders. No content
sniffing is added; a blob with a NUL byte is scanned as text, the same rule
as the V2 fix.

**Scan budget.** Applied per source. A blob and its disk copy are timed
separately.

**Baseline fingerprints.** Reading the blob changes no fingerprint for a
file whose checkout applies no transform. The argument:

1. With no `working-tree-encoding`, no `eol`/`text` conversion that changes
   bytes, no `filter` driver and no `ident`, git's checkout writes the
   blob's bytes to disk unchanged. Disk bytes equal blob bytes.
2. `decodeTextBuffer` is a function of the bytes, so the decoded text is
   identical, and so are every match, its `line`, its `offset` (a UTF-16
   offset into that text, `packages/core/src/types.ts:10-11`), its
   `matchLength` and its
   `valueDigest`.
3. The positional fingerprint is `sha256(relpath|rule|line|offset|length)`
   and the content fingerprint is `sha256("vg-fp-v2" NUL relpath NUL rule
   NUL valueDigest)` (`packages/core/src/match-fingerprint.ts:18-22`,
   `:63-67`). The path is
   the same absolute path either way. Both are unchanged.
4. `file_digest` is SHA-256 over the bytes scanned; those bytes are equal.

That is every fingerprint the baseline reads. U9 asserts it directly and
section 8 checks it on four public repositories.

**What does change, for files that do have a transform:**

- `eol=crlf` (or `core.autocrlf=true` on Windows): the blob is LF, the disk
  is CRLF. The content fingerprint of a value-bearing match is unchanged
  (the match text holds no line ending). The positional fingerprint and
  `file_digest` change, because offsets and bytes now describe the blob.
  The offset is an absolute offset into the file's text
  (`packages/core/src/types.ts:10-11`), so every carriage return before a
  match moves it: **every** positional baseline entry made by 1.9.x on such
  a checkout, for a match after line 1, stops matching. Not some, every one.
  A 1.9.x run on Linux computed the same entries from LF bytes and still
  matches. The fix for an affected adopter is one `vault-guard baseline
  --write`, which writes content keys that do not depend on offsets.
- `working-tree-encoding`: findings appear that were never found before
  (the BOM-less case), or keep their content fingerprint (the BOM case).
- `filter`: the pointer blob rarely matches anything; the disk copy is still
  scanned (2.4), with `file_digest` over the disk bytes.

**Where digests come from.** The scan keeps the raw bytes of every file that
produced a header-only match, keyed by `(path, source)`, and both the reader
and the writer take `file_digest` from those kept bytes. Nothing is re-read
after the scan, so a file cannot change between the bytes judged and the
bytes digested, and no per-file spawn is needed. `applyBaseline`'s digest
cache (`packages/core/src/baseline.ts:289-293`, keyed by path today) becomes
keyed by `(path, source)`, so a blob and its disk copy never share a digest.
Kept bytes are released once the baseline has been applied; only files with
a header-only match are kept, which in practice is a handful.

**Baseline writer.** `baseline --write` takes `file_digest` from the kept
bytes the finding came from, never with a bare `fileDigest(file)`
(`commands/baseline.ts:271` today reads disk). It
accepts findings from the index blob only. A `worktree` finding is not
accepted and is listed apart:
`uncommitted working-tree edits with findings: N (not accepted; stage or
revert them)`. The writer still writes the rest and its exit code rules are
unchanged.

**MCP workspace scan.** `scanWorkspaceDirectory`
(`packages/mcp/src/workspace-scan.ts:56-110`) uses the same content source
as a plain CLI scan, so an editor and CI agree.

---

## 3. `.gitattributes` as a pull-request control file

With section 2, the head's attributes no longer change what a pull-request
run reads for any tracked file's verdict. They are still reported, because
they decide what every other tool and every reviewer's checkout sees, and
because the next change that reads the disk should not reopen MB1 in
silence.

**Detection.** One call, after `assertTrustBaseResolvable`:

```
git -c core.quotePath=false diff-tree -r -z --raw --no-abbrev --no-renames \
    <base commit> HEAD -- ':(glob,icase)**/.gitattributes'
```

`**/` matches zero or more directories, so the root file is included. Each
record gives old mode, new mode and status (A, D, M, T). `icase` errs
toward reporting a `.GitAttributes` that a case-insensitive checkout would
honour.

**Wording.** Constants beside `CONFIG_PROPOSAL_LINE` (`trust-base.ts:76`):

```
Proposed, not applied: .gitattributes changed in this pull request (1 file: src/.gitattributes)
Proposed, not applied: .gitattributes changed in this pull request (4 files: .gitattributes, a/.gitattributes, b/.gitattributes, and 1 more)
Proposed, not applied: .gitattributes at docs/.gitattributes is a symlink at the head commit, not a regular file
```

At most three paths are named, sorted, then `and N more`. A path containing
a control character is printed JSON-escaped. In text mode, one grey line
follows the first attributes proposal:
`   Committed content is read from git, so attribute changes do not alter
what this run scanned.` The shape line uses the existing `shapeProposal`
wording (`trust-base.ts:412-423`) for new mode `120000`, and its
`not a regular file` line for any other non-regular mode.

**Where it surfaces.** The same three places as every proposal: the text
`Proposed, not applied:` lines (`scan.ts:702-711`), `trustBase.proposals` in
JSON, and a `vault-guard/trust-base/proposal` notification in SARIF
(`scan-output.ts:576-588`). `TrustBaseReport` gains `attributesChanged:
boolean` and `attributesPaths: string[]`, both additive. conductor relays
`proposals` as text and needs no change.

**Every change is reported**, not only changes to content-affecting
attributes. Telling the two apart would mean parsing attribute files,
including `[attr]` macro definitions and macros such as `binary`, and a
parser that judges "harmless" is the part a pull request would aim at. The
cost is a proposal line on benign pull requests (linguist hints, export
rules). Proposals never change the exit code.

The base side is not a control input the run consumes, so a non-regular
`.gitattributes` at the base is not could-not-run. It is reported only if
the head changes it.

**What is not reported, and why that is acceptable.** Attributes also come
from `$GIT_DIR/info/attributes`, from the file `core.attributesFile` names,
from the tree `GIT_ATTR_SOURCE` names, and, inside a submodule, from the
submodule's own `.gitattributes`. None is reported. The first three are
runner configuration, not pull-request content: a pull request cannot write
them. A submodule's attributes belong to the submodule's history, which
pull-request mode does not scan (an existing invariant). And in every case
the blob is read whatever any attribute source says, so none of them can
change what a tracked file's verdict rests on.

---

## 4. Baseline and config paths are never followed (MB2)

### 4.1 One reader for control files on disk

A new `readRegularFileNoFollow(path)` in core:

- Opens with `O_RDONLY | O_NOFOLLOW` where `fs.constants.O_NOFOLLOW` exists
  (Linux, macOS). An open of a symlink fails with `ELOOP` (or `EMLINK` on
  some BSDs), which is reported as "a symlink". Then `fstat` on the open
  descriptor must be a regular file; a directory, FIFO, socket or device is
  refused. Reading from the descriptor closes the gap between a check and a
  read.
- Where `O_NOFOLLOW` does not exist (Windows), `lstat`, then open, then
  `fstat`, and refuse unless `lstat` says regular file and `lstat` and
  `fstat` agree on `dev` and `ino`.
- Returns `{ kind: 'absent' }`, `{ kind: 'file', text }`, or
  `{ kind: 'refused', what: 'symlink' | 'not-a-file' }`. Only ENOENT for
  the entry itself is absent. Any other error is a read failure with the
  errno code and the path, not the file's content.
- **A dangling link is a refused link, not an absent file.** The open (or,
  on Windows, the `lstat`) looks at the directory entry, which exists, so a
  link to nowhere is `refused: symlink`. This only holds if nothing checks
  existence first: `existsSync` follows links and calls a dangling link
  absent, after which the search walk would fall through to a parent
  directory's file and the run would obey a config the link was hiding.

Used by every reader of these three names, and the `existsSync` pre-checks
in front of them are removed, so the helper alone decides absent, present
or refused:

- `loadBaseline` (`packages/core/src/baseline.ts:175-197`, the `existsSync`
  at `:179`);
- `loadConfig` (`packages/core/src/config.ts:165-189`, the `existsSync` at
  `:171`);
- `findVaultGuardConfigPath` (`config.ts:115-124`, the `existsSync` at
  `:120`), which now returns the path of the first entry that is present or
  refused, so a refused link stops the walk instead of being skipped;
- `vault-guard config validate` (`packages/cli/src/commands/config.ts:14-35`),
  which reads through the helper instead of `readFileSync`;
- the writer's read of the previous file (`commands/baseline.ts:301-303`).

The MCP server's `loadConfig` call (`packages/mcp/src/server.ts:53`) gets
it through `loadConfig`.

### 4.2 Read side

- **Baseline:** a refused baseline path is exit 2, before any file is
  scanned. `scanCommand` loads the baseline today after scanning
  (`scan.ts:493-500`); the plain-mode load moves up beside the config load,
  so the run fails fast and announces nothing it did not do. Message, after
  the same red cross prefix the other exit-2 messages in `scan.ts` use:

  ```
  Cannot read the baseline: .vault-guard.baseline.json at <path> is a symlink, not a regular file. vault-guard never follows a link on a control file, because a committed link can point anywhere on this machine. Replace it with the file itself (git rm the link, then run vault-guard baseline --write). Nothing was scanned.
  ```

  (`is not a regular file` for the other kinds.) Pull-request mode is
  unchanged: the base-side baseline is
  already refused when it is not a regular blob
  (`assertBaseSideIsRegularFile`, `trust-base.ts:716-728`), and a head-side
  link is already a shape proposal.
- **Config:** the same rule, through `ConfigError`, so the existing
  `Config error` path prints it and exits 2 (`scan.ts:264-280`). Applied to
  both `.vault-guard.json` and `.vault-guard.local.json`. Recommended and
  adopted: a linked config can point the gate's own settings outside the
  repository just as a linked baseline can, and pull-request mode already
  refuses a base-side linked config, so plain mode now agrees with it. The
  cost is a monorepo that symlinks one shared config into several packages:
  it must copy the file instead. That layout already fails under
  `--trust-base` today.
- **No parse text is echoed.** `parseBaselineText` returns `could not be
  parsed as JSON` in place of `JSON: ${detail}`, and `unsupported version
  (expected 1)` without the found value. The warning, the JSON diagnostic
  and the SARIF notification carry that text and the path, nothing else.
  `parseConfigText` returns `could not be parsed as JSON` plus, when the
  engine's message contains them, the line and column (taken with a regex
  that captures digits only). For config the position is kept because it is
  how a user finds a typo, and it holds no file content. The base-ref path
  (`trust-base.ts:643-649`) uses the same two parsers and gets the same
  text.
- **`config validate`** gets both rules. A refused link prints the same
  sentence as the scan's config refusal. Its own `Invalid JSON in <path>:
  ${detail}` (`packages/cli/src/commands/config.ts:29-35`) becomes the `parseConfigText` wording:
  `could not be parsed as JSON`, plus line and column when available. The
  command keeps its existing exit contract, 1 for any config it cannot
  accept and 0 for a valid or absent one, because its 1 already means "this
  config is not valid", not "findings"; a refused link is one more invalid
  config.

### 4.3 Write side

1. Before scanning, `lstat` the output path. Absent or a regular file:
   continue. Anything else: exit 2, nothing written, with the same prefix:

   ```
   baseline --write refuses <path>: it is a symlink, not a regular file. baseline --write never writes through a link. Remove the link (git rm it) and run again. Nothing was written.
   ```

2. Read the previous file with `readRegularFileNoFollow`. A refusal at this
   point (the path changed after step 1) is the same exit 2.
3. Write the new document to a temporary file in the same directory,
   `.vault-guard.baseline.json.<pid>.<random hex>.tmp`, opened with flag
   `wx` (`O_CREAT | O_EXCL`, which does not follow a link), mode `0o644`;
   write, `fsync`, close.
4. `renameSync` the temporary file over the output path. `rename` replaces
   a directory entry and never follows a link at the destination, so a link
   planted after step 1 is replaced, not written through. A hard link at the
   path is likewise replaced, not written through.
5. On any failure in steps 3 or 4, unlink the temporary file and exit 2.

**Test seam.** The write is factored as `writeBaselineAtomically(outPath,
text, hooks?)`, where `hooks.beforeRename` is an optional callback, absent
in production, that a test uses to plant a link at `outPath` after the
temporary file is written and before the rename. F10b uses it to prove the
rename replaces a link rather than writing through it, independent of the
`lstat` check in step 1.

Exit codes are unchanged otherwise: 0 written, 1 written with criticals
refused, 2 could not run.

---

## 5. The locale rule (MB3)

### 5.1 Rule

- **A path is a locale path only when a `LOCALE_DIR_SEGMENTS` directory is
  on it** (`locales`, `locale`, `translations`, `translation`, `i18n`,
  `lang`, `langs`; `path-severity.ts:98-106`). The ruling says the basename
  rule fires only together with such a directory. Since the directory test
  alone already returns true (`:124`), the basename rule adds nothing under
  the ruling, so `LOCALE_BASENAME` and its test at `:125` are deleted. The
  behaviour is exactly the ruling's; the code is smaller.
- **On a locale path only four rules downgrade:** `password-in-code`,
  `api-key-generic`, `secret-generic` and `bearer-token`. A new positive
  list, `LOCALE_PATH_DOWNGRADE_IDS`, in `path-downgrade-ids.ts`. It is a
  list of what may drop, not `LOW_PRECISION_PATH_DOWNGRADE_IDS` minus
  exceptions, so a rule added to the low-precision list later is not
  downgraded on locale paths without a decision.
- **`applyPathAwareSeverity` takes the union per context.** A match is
  downgraded when any context the path is in allows its rule: a test path
  allows the low-precision list; a docs path allows the low-precision list
  without `ssh-private-key` (unchanged, `DOCS_EXEMPT_IDS`); a locale path
  allows the four above. This replaces the docs-only special case at
  `:185-186`, which reads "not a locale path" as permission to downgrade the
  PEM rule and would be wrong once locale paths stop downgrading it.
- `isLocalePath` stays exported from core (`packages/core/src/index.ts:56`)
  with its new meaning.
- No directory names are added. `messages/` (next-intl) and `assets/`
  layouts that hold catalogues lose the downgrade; `messages/` also holds
  queue and protocol code, where a DSN is exactly what lives, so adding it
  would recreate MB3.

### 5.2 Acceptance table

Same production-shaped values under each name, default `fail_on` (`high`).
Before is adc39e5 as the audit measured it; After is this design.

| Path | Content | Before | After |
|---|---|---|---|
| `loc/db.ts` | postgres URL to a non-local host | low, exit 0 | critical, exit 1 |
| `loc/database.ts` | same | critical, exit 1 | critical, exit 1 |
| `loc/db.js` | postgres URL | low, exit 0 | critical, exit 1 |
| `loc/database.js` | same | critical, exit 1 | critical, exit 1 |
| `loc/db.yml` | postgres URL | low, exit 0 | critical, exit 1 |
| `loc/database.yml` | same | critical, exit 1 | critical, exit 1 |
| `loc/ci.yml` | JWT | low, exit 0 | high, exit 1 |
| `loc/auth.yml` | same | high, exit 1 | high, exit 1 |
| `loc/sa.json` | JSON-escaped PKCS#8 private key | low, exit 0 | critical, exit 1 |
| `loc/key.json` | same | critical, exit 1 | critical, exit 1 |
| `loc/pg.js` | password assignment | low, exit 0 | high, exit 1 |
| `loc/pgconf.js` | same | high, exit 1 | high, exit 1 |
| `src/locales/de-DE.yaml` | `tfa_secret:` translated label | low, exit 0 | low, exit 0 |
| `src/locales/de.json` | postgres URL | low, exit 0 | critical, exit 1 |
| `config/locales/en.yml` | JWT | low, exit 0 | high, exit 1 |
| `i18n/en.json` | PEM private key | low, exit 0 | critical, exit 1 |
| `src/en.json` | `tfa_secret:` translated label | low, exit 0 | high, exit 1 (deliberate) |

The `db.js` row is the audit's sixth name; the audit reproduced the other
five pairs. The last row flips the existing `dogfood-fp.test.ts` case for
`src/en.json` (section 7, U14).

---

## 6. Clean git environment (N1)

In plain and pull-request runs, `runFileSetGit`, the blob reader (through
its `env` parameter, 2.3), `status`, `check-attr`, and `trust-base.ts`'s
`runGit` run git with `env: cleanGitEnv()`, which is a copy of
`process.env` with these removed:

```
GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_PREFIX
GIT_IMPLICIT_WORK_TREE GIT_INTERNAL_SUPER_PREFIX GIT_GRAFT_FILE
GIT_SHALLOW_FILE GIT_NO_REPLACE_OBJECTS GIT_REPLACE_REF_BASE GIT_CONFIG
```

and `GIT_OPTIONAL_LOCKS=0` added, plus `GIT_NO_REPLACE_OBJECTS=1` (added in
the fix round after review) so a `refs/replace` substitute never stands in
for the object a listing names. The list is git's own "local repository"
set, the one `git rev-parse --local-env-vars` prints, **minus
`GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`, which are kept**. Those two
carry configuration, not repository location, and containers commonly pass
`safe.directory` through them; stripping them would turn a working
container run into a "dubious ownership" exit 2. The list is hard-coded,
not asked for at run time, so there is no new failure route; U16 asserts
that every line `git rev-parse --local-env-vars` prints on the machine
running the suite is either in the stripped list or one of the two kept
names, so a git that adds a variable fails the build rather than the scan.

**It applies to the outer repository too, not only to recursion.** The
plain file set describes the work tree; a hook's temporary index is not the
work tree. In a `git commit -a` hook the outer listing then reads
`.git/index`, and every file that `-a` is about to commit differs from it on
disk, so section 2.4 scans those disk copies. Nothing the commit will
contain goes unscanned. The outer rule matters on its own, apart from
recursion: a hook in repository A that runs a plain scan of repository B
would otherwise list B through A's index. F17 pins exactly that.

**`--staged` keeps the inherited environment, for every git call it
makes, `cat-file` included.** `git-utils.ts` is not changed to use
`cleanGitEnv`, and it passes `process.env` to the blob reader. Two reasons:

- in a `git commit -a` hook, `GIT_INDEX_FILE` names the temporary index,
  which is exactly what will be committed; stripping it would make
  `--staged` read `.git/index` and miss everything `-a` staged (U17);
- in a repository located only through `GIT_DIR` and `GIT_WORK_TREE` (a
  bare dotfiles repository with no `.git` entry in the tree), the index and
  the object store are reachable only through those variables, so the
  staged listing and `cat-file` must both see them, or the object ids from
  one would be looked up in an object store the other cannot find (U20).

That exemption is a reading of ruling 5, which names "file-set git calls";
`--staged` builds its list from the index, not the file set (open
questions).

A plain or pull-request run in that dotfiles layout has no `.git` for
`findGitRoot` to find. A plain run was and stays a walk. A pull-request
run resolves its repository through `runGit`, which now runs with the
variables stripped, so `rev-parse --show-toplevel` fails and the run exits
2 with the existing "not inside a git worktree" `TrustBaseError`. Before
this change it read the repository through `GIT_DIR`; pull-request mode
needs a real checkout, and an Action checkout always has a `.git`
(section 9).

---

## 7. Test plan

Each fixture is a temporary git repository under `os.tmpdir()`, built with
real commits and driven through `scanCommand` or `baselineCommand`
in-process, except where a row says subprocess (a stub `git` or a real hook
needs a separate process, 10-11 design section 8, item 6). Every row names
the mutation it must kill; the implementer applies each mutation once and
records the red run in the implementation PR.

### 7.1 Adversarial fixtures (before and after stated)

| id | Fixture | Before (adc39e5) | After | Mutation killed |
|---|---|---|---|---|
| F1 | Base commit. Head commit 1 adds `src/leak.ts` with an AWS-shaped key (built at run time, not the documentation example key). Head commit 2 adds `.gitattributes` with `src/leak.ts working-tree-encoding=UTF-16LE`. A fresh `git clone` (so checkout applies the attribute). `scan . --trust-base base`. | exit 0, `Proposed, not applied: none`, `No secrets found` | exit 1, the key at `src/leak.ts` critical, `source: head`; `Proposed, not applied: .gitattributes changed in this pull request (1 file: .gitattributes)` | Pull-request content read from disk (F1a); `.gitattributes` not a control file (F1b, proposal line absent). |
| F2 | F1's clone, plain `scan .`. | exit 0 | exit 1, `source: index`, no worktree copy scanned (`status` clean) | Plain tracked content read from disk. |
| F3 | F1 with the attribute in a nested `src/.gitattributes`. | exit 0 | exit 1; proposal names `src/.gitattributes` | Root-only pathspec for the diff-tree. |
| F4 | F1 with `--staged` on a repository where the file is staged, not committed. | exit 1 | exit 1 | Staged path regressed by the reader move. |
| F5 | Clean tracked file; an unstaged edit adds a key. Plain `scan .`. | exit 1 | exit 1, `source: worktree`, text suffix `(working tree, not in the index)` | Disk copy never scanned (F5a); `status` second column ignored (F5b). |
| F6 | A key is staged, then the working copy is reverted to the clean text. Plain `scan .`. | exit 0 | exit 1, `source: index` | Plain mode reading HEAD instead of the index. |
| F7 | Local filter driver `rot` (`tr A-Za-z N-ZA-Mn-za-m` both ways) configured in the fixture's `.git/config`; `.gitattributes` `secret.txt filter=rot`; the blob is the clean (rotated) form, the disk holds the key. Plain `scan .` and `--trust-base`. | exit 1 (disk) | exit 1, `source: worktree` | `filter` rule dropped (LFS-style content lost). |
| F8 | A tracked file's loose object deleted from `.git/objects`. Plain `scan .`. | exit per disk content | exit 2, names the file, says the blob is not in the object store | Missing object skipped or read from disk. |
| F9 | Subprocess with a stub `git` on `PATH` that passes everything to real git except `cat-file`, which exits 128 with a message. | exit per content | exit 2, quotes the message | Reader failure caught and routed to a disk read. |
| F10 | Committed `.vault-guard.baseline.json` is a symlink to `../victim.txt` outside the repository. `baseline . --write` from the root. | exit 0, `victim.txt` overwritten with baseline JSON | exit 2, message names the path, `victim.txt` byte-identical, no temp file left | No `lstat` before write (F10a); write through the link instead of rename (F10b: the `lstat` check removed and `writeBaselineAtomically`'s `beforeRename` seam used to plant a link to `victim.txt` after the temporary file is written; red if `victim.txt` changes). |
| F11 | F10's repository, `scan .`, `victim.txt` holding `aws_secret=...` text. | warning quotes the first characters of `victim.txt` | exit 2 before scanning, message names the path; no byte of `victim.txt` in stdout, stderr, JSON or SARIF | Reader follows the link. |
| F12 | Dangling symlink at the baseline path (target does not exist, outside the repository). `baseline . --write`. | exit 0, file created outside the repository | exit 2, nothing created | `existsSync` used for the absence check (follows the link, says absent). |
| F13 | Committed `.vault-guard.json` symlink to `../outside.json` holding `{"fail_on":"none"}`; a tracked key. `scan .`. | exit 0 | exit 2, `Config error` naming the path | Config reader follows the link. |
| F14 | A regular baseline file whose text is `{"version":1, aws_secret ...` (invalid JSON). `scan . --format json` and `--format sarif`. | warning and diagnostic contain `JSON: Unexpected token ... "aws_secret"...` | `could not be parsed as JSON` and the path only; findings exit per gate | Parse message echoed. |
| F15 | The six two-letter files and their long-named twins of section 5.2, plus the five locale rows. `scan . --format json`. | as section 5.2 Before | as section 5.2 After | `LOCALE_BASENAME` alone still downgrades (F15a); locale path downgrading DSN, PEM or JWT (F15b). |
| F16 | Superproject with a checked-out submodule `sub/` whose committed `lib/key.ts` holds a key; a pre-commit hook that runs the built CLI `scan .`; `git commit` of an unrelated file. Subprocess. | hook exit 2, `index file open failed` | hook exit 1, finding in `sub/lib/key.ts` | `cleanGitEnv` not applied to recursion. |
| F17 | Two sibling repositories. Repository B tracks a gitignored `.env` holding a key (force-added). Repository A has a pre-commit hook that runs the built CLI's plain `scan .` with B as its working directory. `git commit -a` in A after modifying a tracked file, so the hook inherits A's absolute temporary `GIT_INDEX_FILE`. Subprocess. No submodule is involved, so recursion cannot be what makes it pass. | B is listed through A's index: B's `.env` is not in it and is ignored, so it is not scanned; A's paths count as missing in B; hook exit 0 | B is listed through its own index: `.env` is a tracked-ignored file, scanned; no missing line; hook exit 1 | `cleanGitEnv` applied to recursion only, not to the outer listing. |
| F18 | A tracked `config/local.json` template with no secret, marked `git update-index --skip-worktree`; the developer then writes a real key into the working copy. Plain `scan .`. Repeated with `--assume-unchanged` instead, and with `core.ignoreStat=true` and the file re-added. | exit 1 (disk read finds the key) | exit 1, `source: worktree` | Disk copy chosen from `status` alone (`status` is silent about all three, so the blob-only read passes: exit 0). |
| F19 | A config link whose target does not exist (`.vault-guard.json` pointing nowhere) in a subdirectory, and a parent directory inside the repository holding a regular `.vault-guard.json` with `{"fail_on":"none"}`; a tracked key. `scan .` from the subdirectory. Repeated for the baseline name. | exit 0 (the dangling link reads as absent and the parent's config applies) | exit 2, names the link | `existsSync` pre-check kept in the search walk. |
| F20 | `.vault-guard.json` linked to a file outside the repository holding invalid JSON that starts `aws_secret`. `vault-guard config validate`. | exit 1, prints `Invalid JSON in ...` with the start of the target | exit 1, says the path is a symlink; no byte of the target printed. With a regular invalid file instead: exit 1, `could not be parsed as JSON` and at most line and column | `config validate` left on `findVaultGuardConfigPath` with `existsSync` and `readFileSync` (F20a); validate's parse message echoed (F20b). |
| F21 | A tracked file with `working-tree-encoding=UTF-32` whose unstaged edit adds a key written in plain ASCII bytes; a second tracked file with `working-tree-encoding=UTF-16` whose working copy the test overwrites with a key encoded big-endian with a BOM (what git itself writes for `UTF-16` on macOS; written by the test so the case does not depend on the platform's iconv). Plain `scan .`. | both keys found (adc39e5 reads disk: ASCII bytes as UTF-8, and the BOM selects UTF-16BE) | both found; the run prints the unsupported-encoding coverage line naming the UTF-32 file; exit 1, not 2 | Unsupported label made exit 2 (F21a); the U21b mutant, label consulted before the BOM, so `UTF-16` reaches `TextDecoder`, which is little-endian only (F21b, red: the big-endian key decodes as garbage). |
| F22 | (a) A key is added and staged in a new tracked file, then the file is deleted from disk (`AD`). (b) A committed file holding a key is removed with plain `rm`, not staged (` D`); then a pre-commit hook running plain `scan .` on `git commit -a` (subprocess). Plain `scan .` for (a). | (a) exit 0, `tracked_files_missing: 1`; (b) hook exit 0, the commit lands | (a) exit 1, `source: index`, `tracked_files_missing: 1`; (b) hook exit 0, `tracked_files_missing: 1`, the commit removing the file lands | Missing files skipped before the blob read (F22a, red on (a)); every `--deleted` path read from its blob regardless of the status column (F22b, red on (b): the hook blocks the removal). |
| F23 | Three tracked symlinks named as explicit targets, plain `scan` and `--trust-base`: (a) `in.txt` to `secrets/k.txt` inside the repository, which holds a key; (b) `out.txt` to a file outside the repository holding a key; (c) `dead.txt` to a path that does not exist; (d) `loop.txt` to `loop2.txt`, which links back to `loop.txt`; (e) `dir.txt` to a directory `secrets/` inside the repository that holds a key file. | (a) exit 1, finding under `in.txt`; (b) exit 1, the outside file's key reported; (c) exit 2, `dead.txt` not found; (d) exit 2, the stat fails with ELOOP; (e) the directory is walked as a target and its key found, exit 1 | (a) exit 1, finding reported under `in.txt` with `source: worktree`, link text scanned too; (b) exit 0, warning `out.txt: symlink target is outside the repository, not followed`, link text scanned, nothing outside read; (c) exit 0, warning `dead.txt: symlink target does not exist, not followed`, link text scanned; (d) exit 0, warning `loop.txt: symlink target cannot be resolved (a loop), not followed`, link text scanned; (e) exit 0, warning `dir.txt: symlink target is not a regular file, not followed`, link text scanned (the directory is not walked through a named link; name `secrets/` to scan it) | Named link not resolved, inside-root coverage lost (F23a, red on (a)); outside target followed (F23b, red on (b)); dangling, looping or non-file made exit 2 (F23c, red on (c) and (d)); a named link to a directory walked (F23e, red on (e)); directory scans start following links (F23d: a directory scan of the same tree still skips all five). |

### 7.2 Unit and integration tests

| id | Test | Mutation killed |
|---|---|---|
| U1 | Blob reader: 200-file fixture, a PATH-stub `git` that logs argv then runs real git (subprocess). A plain scan makes exactly 9 file-set and content git calls (2.7), not counting the two root `rev-parse --show-toplevel` calls from `resolveContextRoot` and `resolveContentRoot`, which are asserted separately to run without `GIT_INDEX_FILE`; `cat-file` appears at most twice per repository; no `show` and no per-file `ls-files`. | Per-file reads (U1a); root lookups left on the inherited environment (U1b). |
| U2 | Reader protocol: blobs of 0 bytes, 1 byte, a blob containing `\n<oid> blob 5\n` in its body, and one at exactly 32 MiB; each comes back byte-identical. | Header parsing that trusts content (U2a); off-by-one on the trailing newline (U2b). |
| U3 | Size: a 33 MiB blob is `too_large` with the disk-path wording; its disk copy is not read. A UTF-16LE blob with a BOM, of ASCII text, between 32 and 64 MiB of raw bytes, is also `too_large` (its decoded text is about half as many UTF-8 bytes, so under the limit if measured after decoding). A UTF-16 blob just under 32 MiB raw is scanned. | Size taken from decoded text (U3a, red only on the UTF-16 case: an ASCII blob decodes to the same length and cannot catch it); limit skipped for blobs (U3b). |
| U4 | Same object id at two paths (`a/k.ts`, `b/k.ts`): one read, two scans, two findings. | Dedup by path collapsed to one scan. |
| U5 | De-duplication: one key in blob and disk (reported once, from B); a second copy only on disk (reported, `worktree`); a baselined key (`count` 1) with an extra disk-only copy: one suppressed, one reported, and the reported match has `source: worktree`. | Multiset ignored (U5a); baseline applied to W before B (U5b, red because the reported match is then `source: index`). |
| U6 | Header-only: baselined PEM; unstaged edit elsewhere in the file. Plain scan reports the `worktree` match, suppresses the `index` one. A key-body swap in an unstaged edit: reported. | Header-only W dropped when B was suppressed. |
| U7 | Conflicted path (stages 1 to 3), key only in stage 3: found once, `(index, theirs)`. The same key in stages 2 and 3: found once, from stage 2. | Stage-0-only lookup (U7a); conflicts taken from the `status` columns (U7b); stage 3 not deduplicated against stage 2 (U7c). |
| U8 | Intent-to-add file (`git add -N`) with a key: found, `source: worktree`. | `A` excluded from the status columns. |
| U9 | Fingerprint stability: a fixture tree with no attributes whose committed files include CRLF bytes (committed as CRLF, no `text` attribute, `core.autocrlf=false`), a UTF-8 file with a BOM, a UTF-16LE file with a BOM, and non-ASCII text before a finding. For every match, JSON `fingerprint` and `content_fingerprint` from the blob path equal those computed by reading the same file from disk; `file_digest` of a header-only entry written by `--write` equals SHA-256 of the disk file. | Any normalisation of blob bytes (U9a: line-ending, BOM-stripping or re-encoding of the bytes before the decoder; an all-ASCII LF tree could not catch these); path keyed differently for blobs (U9b). |
| U10 | CRLF: `.gitattributes` `*.ts text eol=crlf`, a `.ts` file holding a value-bearing key and a full-body PEM (header-only). After a fresh re-checkout with the attribute, the test first asserts the disk bytes differ from the blob bytes (CRLF on disk, LF in the blob), so the case is real. Then `baseline --write` and `scan .`: both suppressed, and the header-only `file_digest` equals SHA-256 of the blob, not of the disk file. | Writer digest over disk (U10a); reader digest over disk (U10b). |
| U11 | Writer and worktree findings: an unstaged key in a tracked file is not written; stdout has `uncommitted working-tree edits with findings: 1`. | Writer accepts `worktree` findings. |
| U12 | Trust-base listing failure: `ls-tree` stubbed to fail; exit 2 with `TrustBaseError` even with a second, explicit file target that scans. | `[]` on failure kept. |
| U13 | `.gitattributes` proposals: four changed files (three named, `and 1 more`); a symlinked `.gitattributes` at the head (shape line); a path with a newline (escaped); no change (no line). JSON `attributesChanged` and `attributesPaths`; SARIF notification. Exit code equal with and without the change. | Names not escaped (U13a); proposal changes exit code (U13b). |
| U14 | `path-severity.test.ts`: `it.each` over `db.ts`, `db.js`, `db.yml`, `ci.yml`, `sa.json`, `pg.js` with no locale directory: `isLocalePath` false, severity unchanged. `dogfood-fp.test.ts`: `src/en.json` moves from the locale list to the non-locale list. Locale directory with each DSN rule, `ssh-private-key`, `jwt-token`: not downgraded. Locale directory with the four allowed rules: downgraded. `docs/locales/x.md` with a PEM: not downgraded. | Basename rule kept (U14a); low-precision list used for locale paths (U14b); the old docs-only special case kept (U14c, red on the `docs/locales` row). |
| U15 | `readRegularFileNoFollow`: regular file, symlink to a file, symlink to a directory, dangling symlink, directory, FIFO; on platforms with `O_NOFOLLOW` the symlink case fails at open, not at a separate `lstat`. | `lstat` and `readFileSync` (racy) instead of `O_NOFOLLOW` (U15a, asserted by spying `fs.openSync` flags). |
| U16 | `cleanGitEnv`: every line of `git rev-parse --local-env-vars` is either in the stripped list or is `GIT_CONFIG_PARAMETERS` or `GIT_CONFIG_COUNT`, and those two survive; `GIT_OPTIONAL_LOCKS` is `0`. | A variable dropped from the list (U16a); the two config variables stripped (U16b). |
| U17 | `--staged` in a `git commit -a` hook (subprocess) where the key is only in a modified tracked file that `-a` stages: hook exit 1. | `cleanGitEnv` applied to the staged path (red: exit 0). |
| U18 | Explicit tracked file targets under `--trust-base` with F1's attribute: `scan --trust-base base src/leak.ts` exits 1. Three named files across the outer repository and a submodule: one listing call per repository, each at its own toplevel, and the submodule's file is read from the submodule's object store. | Explicit file targets read from disk (U18a); one listing per file, or all run at the outer toplevel (U18b). |
| U19 | MCP `scan_workspace` on F2's clone: the finding is returned. | MCP left on disk reads. |
| U20 | Bare dotfiles layout: `git init --bare` repository, work tree elsewhere with no `.git` entry, `GIT_DIR` and `GIT_WORK_TREE` exported, a key staged. `scan --staged` (subprocess) exits 1, and the `cat-file` calls in the stub log ran with `GIT_DIR` set. | Blob reader given `cleanGitEnv` on the staged path. |
| U21 | Disk-copy decode map: every mapped label constructs a `TextDecoder` on Node 22; a BOM overrides a contrary label; `UTF-16`, `UTF-16LE-BOM`, `UTF-8-BOM` route to the sniff; `UTF-32` and an unknown label give the coverage entry and a UTF-8 decode; a `filter`-attributed copy with a declared encoding is decoded both ways. | Label passed straight to `TextDecoder` (U21a: no map, so `UTF-16LE-BOM` throws and `UTF-16` decodes little-endian); label consulted before the BOM (U21b: a BOM contrary to the label loses); filter copy decoded once (U21c). |
| U22 | Pull-request run in the dotfiles layout of U20 (no `.git` entry, `GIT_DIR` exported): exit 2, "not inside a git worktree". | `runGit` left on the inherited environment. |
| U23 | `ls-tree -r HEAD` output over the old 64 MiB buffer (a fixture tree with enough long paths, or a stub returning that much): the listing succeeds at 512 MiB; a stub that overflows 512 MiB gives exit 2 saying the tree listing was too large. | Buffer left at 64 MiB (U23a); `[]` or raw buffer error on overflow (U23b). |

---

## 8. Real-repository validation

The 10-11 design made a 1.9.1-versus-candidate comparison a release blocker
and it was not checked in. This PR does it, for that design and this one
together. It is part of the implementation PR, not a follow-up.

**Repositories** (public, the four the audit used): facebook/react,
urllib3/urllib3, gitleaks/gitleaks, Yelp/detect-secrets. Each is cloned at
depth 1 and the commit SHA recorded. The two private dogfood groups the
10-11 design named are run by the operator; their results are recorded as
counts only, under the group letters, with no names or paths.

**Builds compared:** published 1.9.1, `main` at adc39e5, and the
implementation branch. Command per build and repository: `scan .
--format json`, plus `scan . --trust-base <parent commit> --format json` on a
one-commit branch made in the clone.

**Recorded per repository and build** in
`bench/real-repos/2026-10-12-1.10.0.json`, with a method section in
`bench/real-repos/README.md`:

- `files_scanned`, `file_set`, `content_source`, `worktree_copies_scanned`,
  the 10-11 counts (`tracked_ignored_files_scanned`,
  `tracked_nested_vendored_scanned`, `tracked_files_missing`);
- every finding as rule, file, line, severity, source, positional and
  content fingerprint. Never the value;
- wall time, median of three runs, and the machine;
- number of tracked files with a `working-tree-encoding`, `eol`/`text`
  conversion or `filter` attribute (from `git check-attr`), so a fingerprint
  difference can be traced to a transform.

**Expected:** the implementation branch scans the same file list as adc39e5;
findings equal except two-letter basenames (section 5) and files with a
transform; every fingerprint equal for files with no transform; 1.9.1
versus 1.10.0 differs only by the 10-11 file-set additions and the above.

**Release blockers:** a file adc39e5 scanned that the branch does not; a
finding lost that is not explained by a transform; a fingerprint change on
a file with no transform; React wall time over 1.5 times adc39e5's.

---

## 9. What adopters will see

All of this is in 1.10.0 alongside the file-set and baseline changes.

1. **Tracked files are read from git, not from the checkout.** A key in a
   committed file is found whatever `.gitattributes` says about encoding,
   line endings or filters. A pull request can no longer hide a key by
   adding a `working-tree-encoding` line.
2. **A staged secret is found by a plain scan even if the file on disk no
   longer has it.** A plain scan inside git now reads the staged version of
   each tracked file and, when the file on disk is different, the disk
   version too. Findings that exist only in uncommitted edits say so.
3. **Files with a non-UTF-8 `working-tree-encoding` may show findings for
   the first time.**
4. **Git LFS and other filtered files are still scanned from disk**, as
   before, and their pointer files are scanned from git as well.
5. **On a checkout that converts line endings** (Windows with
   `core.autocrlf=true`, or `eol=crlf`), positions in findings describe the
   committed file. A positional baseline entry stores an absolute offset
   into the file, so every positional entry that 1.9.x made on such a
   checkout, for a finding after line 1, stops matching. Run `vault-guard
   baseline --write` once to replace them with content entries, which do
   not depend on positions. Baselines made on Linux or macOS checkouts are
   unaffected.
6. **New ways to exit 2**, each naming the file or the git error: a tracked
   file whose committed content is missing from the local repository; a
   failure of `git cat-file`, `git status` or `git check-attr`; and under
   `--trust-base`, a failure of `git ls-tree` or of the `git diff-tree` that
   looks for `.gitattributes` changes (previously an `ls-tree` failure was
   caught only by the zero-files check).
7. **A pull-request run that finds its repository only through `GIT_DIR`**
   (no `.git` in the checkout) now exits 2 with "not inside a git
   worktree". Pull-request mode needs a real checkout; an Action checkout
   always has one.
8. **Skip-worktree and assume-unchanged files are scanned from disk too.**
   A tracked config template marked `git update-index --skip-worktree` (or
   `--assume-unchanged`) so real local credentials can sit in it unseen by
   git is scanned from the committed template and from the file on disk,
   so those credentials are still found by a plain scan.
9. **Text output gains labels only when a tracked file's disk copy
   differs**: findings are suffixed `(index)`, `(head commit)`, `(working
   tree, not in the index)`, `(working tree, not committed)`, or `(index,
   ours)` and `(index, theirs)` during a merge conflict, and a line
   `Tracked files whose working-tree copy differs, both scanned: N`
   appears. On a clean tree the output is unchanged.
10. **An edited file whose `working-tree-encoding` vault-guard cannot
    decode** (UTF-32, or an unusual label) is scanned as UTF-8 and named in
    a coverage line, `Working-tree copies in an encoding vault-guard cannot
    decode, scanned as UTF-8: N`. The committed version is still read from
    git. The exit code does not change.
11. **A tracked symlink named on the command line** (`scan link.txt`) is
    scanned twice: the link text git stores, and the file it points to when
    that file is inside the repository. A link that points outside the
    repository, or nowhere, is no longer followed: the run prints a warning
    naming the link and the reason and carries on (a dangling named link
    used to be exit 2). Directory scans skip symlinks, as before.
12. **A tracked file staged and then deleted from disk** is now scanned from
    the staged version, and still counted as missing, but only when the
    staged version differs from the last commit (`git status` shows `AD` or
    `MD`). A committed file you removed with `rm` and have not staged yet
    (` D`) is only counted, not scanned, so a plain-scan hook on `git commit
    -a` never blocks the commit that removes an accidentally committed
    secret file.
13. **A pull request that changes any `.gitattributes`** shows
    `Proposed, not applied: .gitattributes changed in this pull request`
    with the file names. The exit code does not change. conductor shows the
    line with the other proposals.
14. **A symlinked `.vault-guard.baseline.json`, `.vault-guard.json` or
    `.vault-guard.local.json` is refused with exit 2**, including a link
    that points nowhere (it no longer lets a parent directory's file take
    over). `vault-guard config validate` refuses it too, with its usual
    exit 1. The VS Code extension shows its existing "ignoring broken
    config" warning for a symlinked config and scans with the built-in
    rules. Replace the link with the file. `baseline --write` never writes
    through a link, and replaces the file by rename.
15. **A malformed baseline no longer quotes its content** in warnings, JSON
    or SARIF. A malformed config, in `scan` and in `config validate`, gives
    the line and column, not the text.
16. **Two-letter file names are no longer treated as translation files.**
    `db.ts`, `ci.yml`, `sa.json`, `pg.js` and similar get full severity, so
    a DSN, key, JWT or password in them now blocks.
17. **Inside `locales/`, `i18n/`, `lang/` and similar directories,
    connection strings, private keys and JWTs are no longer downgraded.**
    Generic password, API key, secret and bearer findings still are.
18. **A translation file outside those directories** (`src/en.json`,
    `messages/de.json`) is judged like any other file, so a translated label
    such as `tfa_secret: ...` can now block. Declare such files in
    `ignore.paths`.
19. **A plain scan run from a pre-commit hook** no longer reads the hook's
    index: with submodules it no longer fails with "index file open
    failed", `git commit -a` no longer produces bogus "tracked files
    missing" counts, and a hook that scans a different repository lists
    that repository's own files. `scan --staged` still reads exactly what
    the commit will contain, including in a repository reached through
    `GIT_DIR`.
20. **New output fields**, all additive: `matches[].source`,
    `run.content_source`, `run.worktree_copies_scanned`,
    `run.worktree_undecodable`, and in pull-request runs
    `trustBase.attributesChanged` and `trustBase.attributesPaths`; SARIF
    results carry `vault-guard/source`.
21. **`baseline --write` lists findings in uncommitted edits** as not
    accepted, beside the existing untracked-file line.

---

## 10. Release shape

**Version.** 1.10.0, minor, all four packages, Action default and tag, as
the 10-11 design set. A run green on 1.9.1 can be red on 1.10.0 for the
reasons in section 9; a minor, not a patch.

**CHANGELOG** gains, after the 10-11 paragraph, one paragraph per item in
section 9 that changes a verdict or an exit code (items 1 to 3, 5 to 8,
11, 12, 14, 16 to 19; item 19 because hook exit codes change, F16 going
from 2 to 1), in the
same plain style, plus a line under "Security" for MB1 and MB2 naming them
as found by an independent audit on 2026-10-12.

**Docs.** README "Baseline" section: the symlink refusal and the rename.
README file-set table (from the 10-11 design): a "content read from" column.
`docs/THREAT_MODEL.md`: `.gitattributes` as a pull-request input, and the
untracked-file encoding boundary. Correct the stale `git show` comments at
`scan-utils.ts:381` and `:498`.

---

## 11. Invariants to append to `docs/INVARIANTS.md`

Each names the test it will cite; test titles are the exact `it` strings
the implementer uses.

**New entry: "Tracked content comes from git, never through a checkout
transform".**

> Inside a git repository a tracked file's content is read from its blob by
> object id: the HEAD tree entry under `--trust-base`, the index (stage 0)
> entry in a plain scan and under `--staged`. `.gitattributes` transforms
> (`working-tree-encoding`, `eol`, `filter`, `ident`) therefore cannot change
> what is judged. The disk copy of a tracked file is scanned as well when
> `git status` says it differs from that blob, when the file has a `filter`
> attribute, or, in a plain scan, when the index marks it assume-unchanged
> or skip-worktree and it is present on disk; it can add findings and never
> removes one. A disk copy's BOM always decides its encoding; otherwise a
> declared `working-tree-encoding` is used only through an explicit label
> map, and an unsupported one is a reported coverage gap on that copy, not
> a failure. Untracked files have no blob and are read from disk, so
> BOM-less UTF-16 in an untracked file is still not detected. Blob reads use
> at most two `git cat-file` processes per repository. A git failure while
> reading tracked content, or a blob missing from the object store, is exit
> 2 naming the file or quoting git; there is no fall back to the disk copy
> alone.
>
> **Enforced by:** `blob-reader.ts` and the content source in
> `scan-utils.ts`; `blob-content-source.test.ts` (`F1: a head-side
> working-tree-encoding does not hide a key under --trust-base`, `F2: the same
> attribute does not hide a key in a plain scan`, `F6: a staged key whose
> working copy was reverted is found by a plain scan`, `F5: an unstaged edit
> that adds a key is found and labelled worktree`, `F7: a key behind a filter
> driver is found from the working-tree copy`, `F8: a missing blob is exit 2
> naming the file`, `F9: a failing cat-file is exit 2 quoting git`, `F18: a
> key in a skip-worktree or assume-unchanged file is found from disk`, `F21:
> an unsupported working-tree encoding is a coverage line, not exit 2`, `U1:
> blob reads use at most two cat-file processes per repository`, `U21: a BOM
> decides a disk copy's encoding before its declared label`).

**New entry: "Reading the blob does not move a fingerprint for an
untransformed file".**

> For a tracked file whose checkout applies no transform, the positional
> fingerprint, the content fingerprint and the header-only `file_digest` are
> the same whether computed from the blob or from the disk copy. Where a
> transform applies, the baseline writer and reader both take `file_digest`
> from the bytes kept from the scan, keyed by path and source, never from a
> fresh read.
>
> **Enforced by:** `blob-content-source.test.ts` (`U9: fingerprints from the
> blob equal fingerprints from disk for an untransformed tree`, `U10: a
> header-only entry written on a CRLF checkout matches on the next scan`);
> `bench/real-repos/2026-10-12-1.10.0.json` (fingerprint sets per
> repository).

**New entry: "`.gitattributes` is a pull-request control file".**

> Under `--trust-base` any added, removed, modified or retyped
> `.gitattributes`, at any depth, between the base ref and HEAD is reported
> as `Proposed, not applied: .gitattributes changed in this pull request`
> with up to three paths, in text, JSON `trustBase.proposals` and SARIF
> notifications. It never changes the exit code. Content is read from blobs,
> so the head's attributes cannot change what was scanned.
>
> **Enforced by:** `trust-base.ts` (the attributes diff-tree);
> `trust-base.test.ts` (`F1: a head-side .gitattributes change is reported as
> a proposal`, `F3: a nested .gitattributes change is reported`, `U13: a
> symlinked .gitattributes at the head is reported as a shape change`, `U13:
> an attributes proposal does not change the exit code`).

**New entry: "Control files on disk are never read or written through a
link".**

> `.vault-guard.baseline.json`, `.vault-guard.json` and
> `.vault-guard.local.json` are opened without following a symlink and must
> be regular files; anything else, a dangling link included, is refused
> naming the path: exit 2 from `scan` and `baseline` before any file is
> scanned, exit 1 from `config validate`. No existence check runs first, so
> a refused link stops the search walk instead of letting a parent
> directory's file take over. `baseline --write` refuses a non-regular file
> at its output path and writes by temporary file and rename, so it never
> writes through a link. No `JSON.parse` message reaches a warning, JSON,
> SARIF or `config validate` output; a baseline parse failure says `could
> not be parsed as JSON` and the path, a config parse failure adds only a
> line and column.
>
> **Enforced by:** `readRegularFileNoFollow` in core; `baseline-writer.test.ts`
> (`F10: baseline --write refuses a symlinked baseline and leaves the target
> untouched`, `F10b: baseline --write replaces a link planted before the
> rename instead of writing through it`, `F12: baseline --write refuses a
> dangling symlink`); `baseline-symlink.test.ts` (`F11: scan refuses a
> symlinked baseline with exit 2 and prints none of the target`, `F13: scan
> refuses a symlinked config with exit 2`, `F14: a baseline parse error never
> echoes file content`, `F19: a dangling config or baseline link is refused,
> not treated as absent`); `config-validate.test.ts` (`F20: config validate
> refuses a symlinked config and echoes none of it`); `read-no-follow.test.ts`
> (`U15: a symlink fails at open, not at a separate lstat`).

**New entry: "File-set git calls run with a clean git environment;
`--staged` does not".**

> Every git call that builds the plain or pull-request file set or reads its
> content, for the outer repository as well as any submodule or nested
> repository, runs with git's local-repository variables removed
> (`GIT_INDEX_FILE`, `GIT_DIR`, `GIT_WORK_TREE` and the rest of `git rev-parse
> --local-env-vars`, except `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`,
> which carry configuration such as `safe.directory`) and
> `GIT_OPTIONAL_LOCKS=0`. `--staged` keeps the inherited environment for
> every git call, `cat-file` included, because in a hook the inherited index
> is what will be committed and a repository reached through `GIT_DIR` is
> only reachable that way.
>
> **Enforced by:** `cleanGitEnv` in core, and the blob reader's `env`
> parameter; `hook-environment.test.ts` (`F16: a plain scan from a pre-commit
> hook reads a submodule's own index`, `F17: a hook in one repository that
> scans another lists the other repository through its own index`, which
> pins the outer-listing rule with no submodule involved, `U17: --staged in
> a commit -a hook still reads the hook's index`, `U20: --staged in a
> GIT_DIR-only repository reads blobs through GIT_DIR`); `git-env.test.ts`
> (`U16: the stripped list covers git rev-parse --local-env-vars except the
> two config variables`).

**Amend "Vendor-anchored rules are not downgraded in docs or markdown".**
Replace "`ssh-private-key` is downgraded on test, fixture and locale paths
(throwaway PEMs live there)" with:

> `ssh-private-key` is downgraded on test and fixture paths (throwaway PEMs
> live there) but NOT on documentation, markdown or locale paths. A locale
> path is one with a `locales`, `locale`, `translations`, `translation`,
> `i18n`, `lang` or `langs` directory on it; a two-letter file name alone
> is not. On a locale path only `password-in-code`, `api-key-generic`,
> `secret-generic` and `bearer-token` are downgraded; the connection-string
> rules, `ssh-private-key` and `jwt-token` keep their severity.

and replace the first sentence of its **Enforced by:** (`docs/INVARIANTS.md`
lines 670-672 at adc39e5, "`applyPathAwareSeverity` consults only the
low-precision set, skipping `DOCS_EXEMPT_IDS` (`ssh-private-key`) when the
path is documentation and neither a test nor a locale path"), which
describes the docs-only special case this change removes, with:

> **Enforced by:** `packages/core/src/utils/path-downgrade-ids.ts` no longer
> exports a docs vendor set and defines `LOCALE_PATH_DOWNGRADE_IDS`, the
> four rules a locale path may downgrade; `applyPathAwareSeverity`
> downgrades a match when any context the path is in allows its rule: the
> low-precision set on a test path, that set without `ssh-private-key`
> (`DOCS_EXEMPT_IDS`) on a documentation path, and
> `LOCALE_PATH_DOWNGRADE_IDS` on a locale path.

then keep its existing test list and add: `path-severity.test.ts` (`U14:
two-letter basenames outside a locale directory keep full severity`, `U14:
DSN, PEM and JWT rules are never downgraded on a locale path`, `U14: a PEM
under docs/locales is not downgraded`) and `dogfood-fp.test.ts` (`does not
treat src/en.json as a locale path`).

**Amend "Scope: supported encodings".** Add after its first sentence:

> Tracked files inside a git repository are read from their blobs, so
> `working-tree-encoding` cannot turn one into BOM-less UTF-16. The BOM-only
> rule still governs untracked files and files outside git. The disk copy of
> a tracked file that is scanned in addition to its blob is decoded by its
> BOM first, then by its declared `working-tree-encoding` through an explicit
> label map; an encoding outside the map is scanned as UTF-8 and reported as
> a coverage line.

---

## 12. Open questions for the operator

1. **Hook installer symlinks.** Ruled in scope 2026-10-12: in 1.10.0, see
   section 13.
2. **For the record, not a question:** exempting `--staged` from the
   clean-environment rule is a reading of ruling 5, which names "file-set
   git calls"; `--staged` builds its list from the index, and stripping its
   environment would break `git commit -a` hooks and `GIT_DIR`-only
   repositories (section 6). The coordinator agrees with this reading.
3. **Open, follow-up work, not fixed in 1.10.0:** plain mode drops a
   typechanged tracked file (its index blob replaced on disk by a symlink,
   `git status` `MT` or ` T`) from the file set without counting it as
   missing, because the disk entry is not a regular file. Pre-existing
   behaviour; `--staged` still reads the index blob.

Everything else in this doc is decided above, with its reason: index over
HEAD for plain mode (2.2), `status` plus the index tags over `diff-files`,
and the `filter` rule (2.4), the disk-copy decode order and the unsupported
encoding coverage line (2.4), the de-duplication order (2.5), reporting
every `.gitattributes` change (3), the config refusal, `config validate`'s
exit code and the config parse position (4.2), deleting the basename rule
and adding no directory names (5.1), keeping the two config variables in
the environment (6), and the private dogfood results recorded as counts
only (8).

---

## 13. Pre-commit hook installer symlink (ruled in scope 2026-10-12)

**Status: in 1.10.0, ruled in scope 2026-10-12.**

**The gap.** `packages/core/src/scanners/pre-commit-hook.ts` writes
repository paths (`.husky/pre-commit`, `lefthook-local.yml`,
`.pre-commit-config.yaml`, the native hook files) with `existsSync` then
`writeFileSync` or `appendFileSync`, and no `lstat` (`:390`, `:453`,
`:552`, `:560`, `:624`, `:666`, `:723`). A repository that commits one of
those paths as a symlink makes `vault-guard init` or `install-hook` append
to it, or create its target, outside the repository. A dangling link reads
as absent to `existsSync`, so the "create" branch writes the target. The
text written is fixed, not attacker-chosen, so the impact is lower than
MB2, but appending a hook block to a shell rc file breaks every shell.
Reasoned from the code, not reproduced.

**The fix, if in.** The same two helpers as section 4:

- every read of an existing hook file goes through
  `readRegularFileNoFollow`; a refused path (link, dangling link, not a
  regular file) makes that installer step fail with a message naming the
  path, "is a symlink, not a regular file; vault-guard does not write
  through a link", and changes nothing; `init` reports it as a skipped
  action, as it reports other hook failures today (as implemented after
  review: `init`'s plan reads hook files the same way, so a linked hook
  file is a `linked_hook` conflict and init writes nothing);
- every write, create or append, goes through the temporary-file-and-
  rename writer of 4.3 (an append becomes read, concatenate, write
  atomically), preserving the file mode (`0o755` for hook scripts);
- the `init` templates already open with `wx` and stay as they are.

**Tests, if in:** for each of the seven write sites, a committed link to a
file outside the repository and a dangling link: the outside file is
byte-identical (or not created), the step reports the refusal, and the
other `init` actions still run. Mutation: the `existsSync` and
`writeFileSync` pair restored at any one site turns its case red.
