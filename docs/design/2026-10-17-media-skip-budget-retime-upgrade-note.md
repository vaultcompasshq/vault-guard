# Binary skips by content agreement, a re-timed scan budget, and the upgrade note on exit 2

Status: design, revised after an independent review (three blocking
findings fixed: the signature-less `.bin` row no longer skips on NUL bytes,
the first-stderr-line rule now covers progress and verbose output, and the
name-only bypass is filed as a security fix), then after re-verification
(non-text evidence no longer includes invalid UTF-8 for `.bin` or for
printable signatures, a declared working-tree encoding that decodes means
text, and INCOMPLETE is the first stderr line with no exempt class).
Target: 1.11.0, a
minor, all four packages in lockstep as for 1.10.0. It covers two findings
from the dogfood runs:

- **F04.** One large media or data file makes a run exit 2 (could-not-run).
  A committed `.MOV` is read as text and trips the 5000 ms post-hoc per-file
  budget, nondeterministically under machine load (seen on a frontend with
  16 to 33 MB videos committed). A 32.1 MiB tracked JSON trips the 32 MiB
  limit (seen on a monorepo).
- **F07, the vault-guard half.** The 1.4.0 upgrade note is printed on stderr
  when findings exist and none block under the implicit default, and it is
  printed before the INCOMPLETE block, so the umbrella quoted the note as the
  stated reason for a could-not-run.

**Decided before this doc, not reopened** (operator plan for item 2.4):

1. Do not print the upgrade note when the run is exiting 2.
2. Extend binary handling with media and font types, counted under the
   existing "skipped by type" accounting.
3. Under load, re-time an over-budget file once before declaring it
   untrusted. The over-budget outcome after the re-time stays INCOMPLETE and
   exit 2.
4. Over 32 MiB stays exit 2 for anything scanned as text.
5. Minor release 1.11.0. Detection changes are validated against real public
   repositories, with a recorded baseline a later run can diff against.

Line citations are against `main` at 8680511, the commit this branch was cut
from. Each was read in the code, not taken from the plan.

---

## 1. Current behaviour

### 1.1 Two skip lists, both by name only

There are two independent extension lists, plus a copy of one of them:

1. **The file-set type filter**, `shouldIgnoreFile`
   (`packages/core/src/utils/file-utils.ts:1111-1149`). Extensions `.png`,
   `.jpg`, `.jpeg`, `.gif`, `.ico`, `.pdf`, `.zip`, `.tar`, `.gz`, `.lock`,
   `.log`, `.map`; the three lockfile names; minified and bundled files
   (`isGeneratedArtifact`, `:1102-1109`). The extension test is
   case-sensitive (`path.extname` with no lowercasing, `:1115`). It runs while
   the file set is built: in the walk (`:312`), in pull-request mode and in
   plain mode inside git through `getPullRequestFilesToScan` (`:690`, called
   for the plain tracked half at `:993`), and for the plain untracked half
   (`:1044`). It is counted as `type_filtered_files` and printed as `Files
   skipped by type or name: N`. It has three more callers, all walk
   variants that feed the same scan paths: the synchronous walk (`:389`)
   and the two gitignore-filtered listings (`:527`, `:565`). Removing the
   binary extensions from the function changes all of them at once, which
   is the intent.
2. **The scan-time binary list**, `BINARY_EXTENSIONS` and `isBinaryFile`
   (`packages/cli/src/utils/scan-utils.ts:215-218`, `:721-724`). Extensions
   `.png`, `.jpg`, `.jpeg`, `.gif`, `.ico`, `.pdf`, `.zip`, `.tar`, `.gz`,
   `.exe`, `.dll`, `.so`, `.dylib`, `.bin`, compared lowercased. Applied in
   `scanFilesAsync` (`:932`) and in the `--staged` branch of
   `scanFileListAsync` (`:629`, `:640`), and used to leave those files out of
   `cat-file --batch-check` (`:620`, `:923`). Counted as
   `binary_files_skipped`, printed as `Binary files skipped: N`
   (`packages/cli/src/commands/scan.ts:686`, `:907-909`).
3. **The MCP copy**, `packages/mcp/src/workspace-scan.ts:17-24`, the same
   fourteen extensions, applied at `:88` and `:92`. Not counted.

The images and archives sit in both lists. A lowercase `.png` is removed by
the type filter first; an uppercase `.PNG` passes the case-sensitive type
filter and is then removed by the lowercased `isBinaryFile`. A file named
explicitly on the command line never meets the type filter
(`scan-utils.ts:864-865`) but does meet `isBinaryFile`.

There is no video, audio or font extension in either list. A `.mov`, `.mp4`,
`.mp3`, `.woff2` or `.ttf` is read and scanned as text.

### 1.2 Correction: no NUL sniff exists

The plan says the NUL-sniff part of this item "landed in 1.10.0". It did not.
At 8680511:

- `decodeTextBuffer` trusts only a byte-order mark and documents that
  BOM-less UTF-16 is not detected and that guessing from NUL density was
  rejected (`packages/core/src/utils/text-decode.ts:9-17`, `:30-56`).
- The 1.10.0 design states it outright: "No content sniffing is added; a
  blob with a NUL byte is scanned as text, the same rule as the V2 fix"
  (`docs/design/2026-10-12-blob-reads-baseline-symlinks-locale-basenames.md`,
  section 2.8).
- The staged path says the same in code: "No content sniffing: only the
  extension rule skips a blob" (`scan-utils.ts:610`).
- `docs/INVARIANTS.md` has the rule as an invariant: "Nothing is skipped on
  content", in the section headed "The staged path skips a blob by extension
  only, never by content". It records why: a `.ts` file holding a key and one
  NUL byte used to be skipped and exit 0 (the V2 fix), and refusing NUL
  blobs with exit 2 broke ordinary commits of fonts and images.

What 1.10.0 did ship for MB1 was the blob read, not a sniff: tracked content
is read from git, so a head-side `working-tree-encoding` cannot turn a file
into BOM-less UTF-16. This design therefore adds the first content check the
scanner has ever had, and it must keep that invariant's purpose: **a NUL
byte, or any other content property, never causes a skip on its own.**
Content may only veto a skip that the name proposed.

### 1.3 The existing extension skip is already a bypass

The adversarial question asked of this design applies to the code today.
Nothing reads a byte before either list decides. Measured against the code
paths above:

| Fixture | Plain `scan .` in git | `--trust-base` | `--staged` | Named target |
|---|---|---|---|---|
| A text file `config/credentials.png` holding a key | skipped, `type_filtered_files` +1 | skipped, `Files skipped by type or name: 1` | skipped, `binary_files_skipped` +1 | skipped by `isBinaryFile` |
| The same as `credentials.PNG` | skipped by `isBinaryFile` | same | same | same |
| The same as `dump.bin` (a tool writing an env dump; `env -0`, `find -print0` and `/proc/PID/environ` all write NUL-separated text) | skipped by `isBinaryFile` | same | same | same |

Each exits 0. A pull request can add a plaintext key under any of the
fourteen binary extensions and the gate never opens the file. The run does count it, so the
skip is not silent, but a count is not a scan.

This design closes that weakness for every binary family, old and new
(section 2.4). The name-based skips of TEXT files (`.lock`, `.log`, `.map`,
lockfile names, minified bundles) are a different, already documented class
(README, pull-request section: "a key committed as `src/leak.min.js` is still
skipped") and are out of scope (section 2.5, open point 3).

### 1.4 What the budget measures today

`scanText` (`packages/core/src/utils/content-source.ts:383-397`) takes
`Date.now()` before and after `scanner.scanContent` plus
`applyPathAwareSeverity`, for one decoded text. `scanTrackedCopies` keeps the
slowest copy (`:589`, `:611`), and so does the untracked path (`:523-526`).
`scanOneFile` compares that with the budget after the fact
(`scan-utils.ts:541-543`) and records `kind: 'scan_budget'` with a
`file.scan_timeout` error diagnostic (`:259-277`). Default 5000 ms
(`:213`). The MCP surface does the same with its own constant
(`workspace-scan.ts:35`, `:120-122`). Neither the budget nor the binary
skip is configurable: no config key, no flag (checked in `config.ts`,
`types.ts`, the config schema and `cli.ts`).

So "over budget" is **post-hoc wall time of one synchronous scan of one
copy**. The scan is synchronous, so the ten files in flight never overlap on
the main thread; decoding and reading are outside the measured span. Wall
time over that span is the thread's own CPU time plus every interval the OS
did not run it (other processes on a loaded machine or a shared CI runner)
plus GC pauses. The first term is what the budget is for (a runaway pattern
burns CPU); the second is noise, and is why F04 is load-dependent.

F04's `.MOV` case: a 16 to 33 MB binary decoded as UTF-8 becomes tens of
millions of characters, mostly U+FFFD, and every pattern runs over all of
them. That takes seconds of CPU on an idle machine and goes over 5000 ms of
wall time as soon as the machine is busy.

### 1.5 The size limit and its hint

`MAX_SCAN_FILE_BYTES` is 32 MiB (`packages/core/src/utils/scan-file.ts:16`).
For a blob the size comes from `cat-file --batch-check` before any content
moves (`content-source.ts:566`); for a disk copy from `lstat` (`:578`) or
`stat` (`:518-519`). `recordTooLarge` (`scan-utils.ts:173-192`) records
`kind: 'too_large'` with the reason `32.1 MiB: over 32 MiB, not scanned` and
the exclude entry, and `reportIncomplete` (`scan.ts:115-154`) prints, on
stderr, after the red cross prefix the other exit-2 messages use (omitted
here and below):

```
INCOMPLETE: 1 file(s) or target(s) over the 32 MiB scan limit were not scanned

  data/export.json
    32.1 MiB: over 32 MiB, not scanned
    to exclude it on purpose, add "/data/export.json" to "ignore.paths" in .vault-guard.json
```

(On a pull-request run the last line says the entry must be on the base ref.)
So the hint already names the file and the remedy, as the plan says. Two
gaps: the first line names neither the file nor the remedy, and the list is
in completion order (pushed from inside `Promise.all` batches), so with
several files the first one named is not deterministic.

### 1.6 The upgrade note and the order of stderr

The note (`scan.ts:727-745`) is printed when `gateIsImplicitDefault &&
totalMatches > 0 && blocking === 0`. Nothing in that condition looks at
`scanIncomplete`, and it runs before the format branches, so in JSON and
SARIF mode it is the first thing on stderr and the INCOMPLETE block
(`:754-758`, `:772-775`) follows it. In text mode two more advisory lines can
precede INCOMPLETE on stderr: the yellow `N warning(s)` summary (`:780-784`),
which is always present on an incomplete run because every unscannable file
also adds an error diagnostic, and the `Baseline file invalid` warning
(`:582-588`).

The umbrella takes the first non-empty stderr line as what a gate said about
a could-not-run, strips control characters and non-ASCII, and caps it at 160
characters. That is how the note became the stated reason in F07. The
umbrella-side change (preferring a recognised INCOMPLETE line) is the
umbrella's own item; this design makes the gate's stderr correct on its own.

---

## 2. The rule: the name proposes, the bytes must agree

### 2.1 The threat, stated

Pull-request mode exists so that a pull request cannot change what the gate
looks at or how it judges it. The 1.10.0 work treated every input a pull
request controls without changing the judged content as a control input:
config, baseline, `.gitattributes`. A file name is the same kind of input.
Renaming `credentials.txt` to `credentials.mov` changes no byte of the
content, costs nothing, and can happen by accident (a tool that writes
`dump.bin`, an editor's "save as"). If the name alone decides a skip, the
name is a mute switch.

Changing the bytes is a different thing. A pull request that rewrites a key
into a container format, base64, or any encoding has changed the content, and
no pattern scanner detects an encoded secret; that is outside what
vault-guard claims in any mode. So the property this design guarantees is
about the name, not about deliberately disguised content:

> **No extension, by itself, ever removes text content from the scan.** A
> file is skipped as binary only when its extension names a binary family
> AND its own leading bytes carry that family's signature AND those bytes are
> not text. Content alone never causes a skip. Anything that fails the check
> is scanned as text, in full, and counted.

### 2.2 The rule in full

For each copy of a file the run would read (an untracked or non-git file;
a tracked file's blob, or both conflict-stage blobs; a tracked file's disk
copy when 2.4 of the 1.10.0 design says to read it):

- **R1. Candidate by name.** The lowercased last extension
  (`path.extname(name).toLowerCase()`) is in the table in section 3. A
  dotfile with no other dot (`.mp4`) has no extension and is not a candidate.
  `a.mp4.txt` is `.txt` and is not a candidate.
- **R2. Read the head.** The first `min(size, 4096)` bytes of that copy are
  read (`SNIFF_BYTES = 4096`; the largest offset any signature needs is 262,
  for `tar`).
- **R3. Signature.** The head matches one of the signatures listed for that
  extension, at its stated offset. A head shorter than the signature does
  not match.
- **R4. Not text.** The head does not begin with a byte-order mark
  (`FF FE`, `FE FF`, `EF BB BF`), and it carries non-text evidence. Below,
  a **control byte** means a C0 control byte (`00` to `1F`) outside the
  text set: NUL, BEL (`07`), BS (`08`), tab, LF, VT, FF, CR, SUB (`1A`) and
  ESC. BEL, BS and SUB are in the text set because accidental text carries
  them: BEL ends the OSC title sequences in terminal captures, BS is the
  nroff overstrike in raw man output, and SUB is the DOS end-of-file byte.
  Four KiB of real binary nearly always holds some other C0 byte. What
  counts as evidence depends on which signature matched:
  - **A binary signature** (one that contains at least one byte outside
    printable ASCII: PNG, JPEG, ICO, TIFF, EBML, ASF, MPEG, the MP3 frame
    sync, `00 01 00 00` fonts, ZIP, gzip, ELF, Mach-O, ADTS, `FLV 01`): a
    NUL byte, a control byte, or invalid UTF-8. Text cannot produce such a
    signature by accident, so the extra check only has to rule out the
    contrived case. In almost every such row the signature's own
    non-printable byte already supplies the evidence: `89` (PNG), `FF`
    (JPEG, MP3, ADTS), `B2` (ASF) and `FE` or `CA FE` (Mach-O) are invalid
    UTF-8; ICO, TIFF, MPEG and the `00 01 00 00` fonts contain a NUL; ZIP
    (`03`), gzip (`1F`) and `FLV 01` contain a control byte. Two rows do
    not: **ELF**, whose one non-printable byte `7F` (DEL) is valid UTF-8
    and not a C0 byte, and **EBML** (`.webm`, `.mkv`, `.weba`), whose
    `1A 45 DF A3` is SUB, a letter and a valid two-byte UTF-8 sequence. A
    head of either is confirmed only by what follows the signature, which
    every real file supplies at once (an ELF header's class, version and
    zero padding; an EBML header's size and version elements).
  - **A printable signature** (every signature byte is printable ASCII:
    `ftyp`, `moov`, `mdat`, `free`, `skip`, `wide`, `pnot` at offset 4,
    `RIFF` with `WEBP`, `AVI `, `WAVE`, `FORM` with `AIFF` or `AIFC`,
    `GIF87a`, `GIF89a`, `BM`, `%PDF-`, `OggS`, `fLaC`, `ID3`, `MThd`,
    `caff`, `wOFF`, `wOF2`, `OTTO`, `true`, `ttcf`, `ustar` at 257, `LP` at
    34, `MZ`): a NUL byte or a control byte. Invalid UTF-8 is NOT evidence:
    a text file in a legacy codepage that happens to begin with such bytes
    is invalid UTF-8 as soon as it holds one accented character, and is
    still text. Real files of these formats carry a NUL or a control byte
    in their first bytes (2.3).
  - **No signature (`.bin`):** only a control byte. A NUL byte is NOT
    evidence, so NUL-separated text (`env -0`, `find -print0`,
    `/proc/PID/environ`) is never confirmed. Invalid UTF-8 is NOT evidence
    either, so text in a legacy codepage (Latin-1, Windows-1252,
    Shift-JIS, GBK; on Windows, `cmd`'s `set > dump.bin` writes the ANSI
    codepage) is never confirmed, though it is invalid UTF-8 as soon as it
    holds one non-ASCII byte. `decodeTextBuffer` reads such text as UTF-8
    with replacement characters, and ASCII key material in it is matched.
  - **A copy with a declared `working-tree-encoding`** (a disk copy whose
    attribute names an encoding): first decode the head with the declared
    label, through the 1.10.0 label map (`text-decode.ts:68-96`), with
    `fatal: true` and `stream: true`. If that succeeds the copy is text and
    is never confirmed, whatever the row and whatever bytes it holds (a
    UTF-16 copy of `U+00E9` is `E9 00`, invalid UTF-8 with a NUL; of
    `U+0101` is `01 01`, two control bytes). A label routed to the BOM
    sniff is handled after the BOM rule (a copy with a BOM is already text)
    by what the label names: `UTF-8` and `UTF-8-BOM` decode as UTF-8;
    `UTF-16`, `UTF-16LE-BOM` and `UTF-16BE-BOM` with no BOM present decode
    as UTF-16, big-endian first (what git assumes for `UTF-16` with no BOM)
    and then little-endian, and the copy is text if either succeeds.
    Decoding a BOM-less UTF-16 copy as UTF-8 would fail on its first
    non-ASCII character and drop the copy to the row rule, where `U+0101`
    confirms a `.bin`. A label outside the map is never confirmed either:
    git applied a text encoding to that copy, and it is scanned and
    reported as undecodable exactly as in 1.10.0. Only a copy whose
    declared decode fails falls through to the row's evidence rule above.

    Cost of this rule: a single-byte label (`ISO-8859-x`, `windows-125x`,
    `KOI8-R`, `KOI8-U`) maps every byte to a character, so its fatal decode
    never fails, and a real binary file under such a label is always
    scanned as text. That file can then exceed the budget and make the run
    exit 2, which fails closed; the remedy is the attribute or an
    `ignore.paths` entry.

    `stream: true` matters most here. The 4096-byte window can end inside
    a character of the declared encoding (half of a UTF-16 surrogate pair,
    the first byte of a Shift-JIS pair). Without `stream: true` the fatal
    decode fails on that cut, the copy falls to the row rule, and a UTF-16
    `.bin` holding `U+0101` is confirmed and skipped. U3 pins this.

  A multi-byte sequence cut off by the end of the window is not counted as
  invalid (decode with `fatal: true` and `stream: true`).
- **R5. Outcome.**
  - R1 to R4 all hold: the copy is **skipped by type**. It is not decoded,
    not scanned, and not subject to the size limit or the budget.
  - R1 holds and R3 or R4 fails: the copy is a **type mismatch**. It is
    scanned as text exactly as any other file, under the size limit and the
    budget, and counted under its own label (section 5). One exception: a
    blob that is a Git LFS pointer (R6) is scanned as text but not counted
    as a mismatch.
  - R1 fails: the copy is scanned as text, as today.
- **R6. LFS pointer.** A copy under 1024 bytes that begins with
  `version https://git-lfs.github.com/spec/v1` followed by a newline is a
  pointer, which is expected for media under LFS. It is scanned (it is text,
  and cheap), and not labelled a mismatch, so an LFS repository does not
  print one warning per media file. Its disk copy, the real media, is judged
  on its own bytes.

The exit status is decided by findings and unscannable files exactly as
today. A skip by type and a type mismatch never change it.

### 2.3 Why this shape and not another

- **Not the extension alone.** That is today's bypass (1.3).
- **Not a NUL or binary-byte test alone.** It would skip a `.ts` file with a
  stray NUL, which is the V2 regression the invariant exists to prevent, and
  BOM-less UTF-16 text is full of NUL bytes. R4 only ever vetoes; it never
  proposes.
- **Not the signature alone.** Several signatures are printable ASCII
  (`%PDF-`, `OggS`, `fLaC`, `wOFF`, `OTTO`, `RIFF`, `ID3`, `MThd`, `BM`,
  `ftyp` at offset 4). A text file that happens to start with `OggS` and is
  named `.ogg` would be skipped. For these R4 requires a NUL or a control
  byte, which ordinary text in any codepage does not contain (the one
  known exception, ISO-2022-KR, is named in the `.bin` bullet below). Every
  real file of
  these formats has one in its first few bytes (version fields, big- or
  little-endian sizes, reserved zeros); a real file that does not is
  scanned, which is the safe direction. Invalid UTF-8 is not accepted for
  them, because it only says the text is not UTF-8: a Latin-1 file is
  invalid UTF-8 and is text.
- **Not a whole-file check.** Any bounded check is satisfiable by a file that
  starts with a valid header and continues with text. That is a content
  change, the encoding case of 2.1, and is accepted as the documented
  boundary (open point 2). A whole-file text-likeness test would reintroduce
  a full read and a heuristic threshold for every image and video, which is
  the cost F04 is about.
- **`.bin` is the weakest row, and NUL is not evidence there.** With no
  signature, only R4 stands between the name and a skip. If a NUL byte
  were enough, a name plus one NUL would skip text, which is the V2 shape
  behind a generic name, and the most likely real `.bin` text file (an env
  dump written NUL-separated) holds exactly the keys this tool exists to
  find. Invalid UTF-8 is not enough either: an env dump written in the
  Windows ANSI codepage becomes invalid UTF-8 with one accented character
  in a user name, which is ordinary accidental text, not deliberately
  disguised content. So for signature-less rows a skip needs a control
  byte that text does not use, and nothing else counts. That is still
  weaker than a signature. The remaining known accidental-text limit is
  ISO-2022-KR, which switches character sets with SO and SI (`0E`, `0F`):
  a text file in that encoding named `.bin`, with no declared
  `working-tree-encoding`, is skipped. A text file with any other stray
  control byte outside the text set is skipped too, but no common tool
  writes one into text. It is an improvement on today all the same, where
  every `.bin` is skipped on its name, text or not; after this change a
  `.bin` of ordinary text, of NUL-separated text, of legacy-codepage text,
  or of UTF-16 text with a BOM is scanned.
- **The BOM rule** keeps a UTF-16 text file with a BOM named `notes.bin`
  scanned: without the rule, a UTF-16 file's NULs or control bytes could
  satisfy R4 on a row that accepts them, while `decodeTextBuffer` reads
  it perfectly well as text. No
  signature in section 3 begins with a BOM; the MP3 frame-sync signature is
  limited to Layer III second bytes so that `FF FE` (a Layer I header) is
  never a signature.

### 2.4 Closing the existing weakness

The images, PDF, archives and native libraries of both old lists move under
the same rule. Concretely:

1. `shouldIgnoreFile` loses `.png`, `.jpg`, `.jpeg`, `.gif`, `.ico`, `.pdf`,
   `.zip`, `.tar`, `.gz`. It keeps `.lock`, `.log`, `.map`, the lockfile
   names and the generated-artifact test, which skip text by name on purpose
   (2.5).
2. `BINARY_EXTENSIONS` and `isBinaryFile` in the CLI, and the MCP copy, are
   replaced by one table and one classifier in core (section 4.1).
   `isBinaryFile` is reachable only through the CLI's internal utils barrel,
   not from the package's published entry point, so it is deleted outright
   (4.6).

Consequences an adopter will see, all in the CHANGELOG (section 12):

- Images and archives the type filter used to drop are now counted under
  `binary_files_skipped` instead of `type_filtered_files`. The total of the
  two is unchanged for files whose bytes agree.
- They now pass through the config `ignore` filter like any other file, so a
  project that listed `*.png` under `ignore.paths` sees them counted under
  `config_ignored_files` instead.
- A text file with an image, archive or library extension is scanned and can
  turn a green run red. That is the fix.
- In pull-request mode a head-tree image now reaches the
  `lstat` check of `getPullRequestFilesToScan` (`file-utils.ts:703-715`), so
  an image missing from a sparse checkout is exit 2 like any missing tracked
  file, where it was silently type-filtered before. In plain mode it is
  counted in `tracked_files_missing`, as any other missing file is. Open
  point 9.
- A tree whose only files are confirmed binary scans nothing and meets the
  existing "nothing was scanned" exit 2 (`scan.ts:549-559`), exactly as a
  tree of only `.png` files does today.

### 2.5 What stays name-based, and why

`.lock`, `.log`, `.map`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
`*.min.js` and the other generated names are skipped because they are text
that produces false positives, not because they are binary. A content check
cannot help there: their bytes are text. A key committed as `leak.log` still
passes on its name, and the run counts it. Changing that is a precision
decision with its own false-positive cost and needs its own real-repository
run, so it is not folded into a release about binary files (open point 3).

---

## 3. Families, extensions and signatures

Offsets are in bytes from the start of the copy. "or" lists alternatives.
Every row is additionally subject to R4.

| Family | Extension | Signature | Status |
|---|---|---|---|
| image | `.png` | 0: `89 50 4E 47 0D 0A 1A 0A` | existing, now checked |
| image | `.jpg`, `.jpeg` | 0: `FF D8 FF` | existing, now checked |
| image | `.gif` | 0: `GIF87a` or `GIF89a` | existing, now checked |
| image | `.ico` | 0: `00 00 01 00` | existing, now checked |
| image | `.webp` | 0: `RIFF` and 8: `WEBP` | new |
| image | `.bmp` | 0: `BM` | new |
| image | `.tif`, `.tiff` | 0: `49 49 2A 00` or `4D 4D 00 2A` | new |
| image | `.avif`, `.heic`, `.heif` | 4: `ftyp` | new |
| document | `.pdf` | 0: `%PDF-` | existing, now checked |
| video | `.mp4`, `.m4v`, `.mov`, `.3gp`, `.3g2` | 4: `ftyp`, `moov`, `mdat`, `free`, `skip`, `wide` or `pnot` | new |
| video | `.webm`, `.mkv` | 0: `1A 45 DF A3` | new |
| video | `.avi` | 0: `RIFF` and 8: `AVI ` | new |
| video | `.ogv` | 0: `OggS` | new |
| video | `.flv` | 0: `FLV` `01` | new |
| video | `.wmv`, `.asf` | 0: `30 26 B2 75 8E 66 CF 11` | new |
| video | `.mpg`, `.mpeg` | 0: `00 00 01 BA` or `00 00 01 B3` | new |
| audio | `.mp3` | 0: `ID3`, or 0: `FF` followed by one of `FB FA F3 F2 E3 E2` | new |
| audio | `.wav` | 0: `RIFF` and 8: `WAVE` | new |
| audio | `.ogg`, `.oga`, `.opus` | 0: `OggS` | new |
| audio | `.flac` | 0: `fLaC` | new |
| audio | `.m4a`, `.m4b` | 4: `ftyp` | new |
| audio | `.aac` | 0: `FF F1` or `FF F9`, or 0: `ID3` | new |
| audio | `.aif`, `.aiff` | 0: `FORM` and 8: `AIFF` or `AIFC` | new |
| audio | `.wma` | 0: `30 26 B2 75 8E 66 CF 11` | new |
| audio | `.weba` | 0: `1A 45 DF A3` | new |
| audio | `.mid`, `.midi` | 0: `MThd` | new |
| audio | `.caf` | 0: `caff` | new |
| font | `.woff` | 0: `wOFF` | new |
| font | `.woff2` | 0: `wOF2` | new |
| font | `.ttf` | 0: `00 01 00 00` or `true` | new |
| font | `.otf` | 0: `OTTO` or `00 01 00 00` | new |
| font | `.ttc` | 0: `ttcf` | new |
| font | `.eot` | 34: `4C 50` | new |
| archive | `.zip` | 0: `PK 03 04`, `PK 05 06` or `PK 07 08` | existing, now checked |
| archive | `.gz` | 0: `1F 8B` | existing, now checked |
| archive | `.tar` | 257: `ustar` | existing, now checked |
| executable | `.exe`, `.dll` | 0: `MZ` | existing, now checked |
| executable | `.so` | 0: `7F 45 4C 46` | existing, now checked |
| executable | `.dylib` | 0: `FE ED FA CE`, `FE ED FA CF`, `CE FA ED FE`, `CF FA ED FE` or `CA FE BA BE` | existing, now checked |
| other | `.bin` | none: R4 alone decides, a control byte only (2.2) | existing, now checked; weakest row |

**Reasoning per family.**

- **Video and audio** are the F04 class: large, committed to frontends and
  docs sites, and pure cost when read as text. The container signatures are
  stable, published and checked by every media tool. QuickTime `.mov` files
  written before the ISO base format may start with a `moov`, `mdat`,
  `wide`, `free`, `skip` or `pnot` atom instead of `ftyp`, hence the list at
  offset 4; the four bytes before it are a big-endian atom size, which for
  any real file contains a zero byte, so R4 holds.
- **Fonts** are committed beside every web frontend and are already named in
  the invariants file as the reason a NUL-blob refusal was rejected. The
  existing test `a staged .woff2 containing a NUL does not exit 2` uses the
  bytes `wOF2 00 01 00 02`, which pass R3 and R4.
- **Images** gain the formats modern frontends commit (`webp`, `avif`,
  `heic`) plus `bmp` and `tiff`. `.svg` is **never** a candidate: it is XML
  text and can hold anything.
- **Old entries** are kept, now checked. A `.tar` without the `ustar` magic
  (the pre-POSIX format) is a mismatch and is scanned as text, which for a
  tar of text files is more coverage, not less. A POSIX tar stores its
  members uncompressed, so a key in a tarred `.env` would be findable as
  text; skipping a `.tar` that has the `ustar` magic is today's behaviour,
  not a regression, and is listed as a known limit beside A7. `.bin` has no
  format, so R4 alone decides it, with the signature-less test: a `.bin`
  is skipped only when its first 4096 bytes contain a control byte (a C0
  byte outside the text set of 2.2: NUL, BEL, BS, tab, LF, VT, FF, CR, SUB
  and ESC). NUL-separated text and
  text in any legacy codepage are therefore scanned, whatever their bytes
  above `7F`.

**Excluded on purpose.** `.ts` (MPEG transport stream, but TypeScript here),
`.mts` (MPEG-2 TS, but a TypeScript ES module extension), `.m2ts`, `.vob`,
`.pfa` (a Type 1 font in ASCII), `.pfb`, `.fnt`, `.svg`. Archive formats not
already listed (`.tgz`, `.bz2`, `.xz`, `.7z`, `.zst`, `.jar`, `.whl`) are not
added in this release (open point 7).

A unit test (U2) lists the excluded set explicitly; adding `.ts`, `.mts` or
`.svg` to the table turns it red.

---

## 4. Where the check runs

### 4.1 One module in core

`packages/core/src/utils/binary-type.ts`, new:

- `binaryCandidate(path): { family, ext } | undefined`: R1 against the table.
- `confirmsBinary(ext, head: Uint8Array, declaredEncoding?: string): boolean`:
  R3 and R4, including the declared-encoding decode for a disk copy.
- `isLfsPointer(bytes: Uint8Array, size: number): boolean`: R6.
- `SNIFF_BYTES = 4096`.

The table is a frozen constant. Nothing reads it from config, the
environment or the scanned tree (section 9).

`scanFileContent` (`content-source.ts:499-542`) and `scanTrackedCopies`
(`:545-631`) apply the rule per copy, so the CLI's directory, pull-request,
plain-git, named-target and `--staged` paths and the MCP workspace scan all
share it. `FileContentOutcome` gains:

- `skippedByType?: { family }`: every copy that would have been read was
  confirmed binary; `matches` is empty, `bytesRead` is the head bytes only.
- `binaryCopiesSkipped: number`: copies confirmed binary when at least one
  other copy of the file was scanned (the LFS case).
- `typeMismatch?: { family }`: at least one copy was a candidate, was not
  confirmed, and was not an LFS pointer.

`scanOneFile` (`scan-utils.ts:485-550`) and the MCP `scanOne`
(`workspace-scan.ts:90-134`) fold these into the run counts (section 5).
The early `isBinaryFile` returns at `scan-utils.ts:629-632`, `:640-643` and
`:932-935` and at `workspace-scan.ts:92` are removed, and `prepare` is given
every file (`scan-utils.ts:620`, `:923`; `workspace-scan.ts:88`), since a
candidate's blob is now read.

### 4.2 Blob path

`BlobBatchReader` gains a head read: `readHead(oid, n)` writes the object id
to the same `cat-file --batch` process as any other request, consumes the
whole `size` bytes of the body from the stream, keeps only the first `n`, and
resolves with them. git has no ranged blob read, so the full body still
crosses the pipe, but memory per request is `n`, not `size`. Head requests
take a window slot like any other request; shared-blob deduplication is keyed
on `(oid, head)` separately from full reads.

Two implementation constraints the memory bound depends on:

- **A discard mode in `onData`.** Today `onData` buffers the whole body of
  the object at the front of the queue before resolving it
  (`blob-reader.ts:355-363`). A head request must switch the parser into a
  mode that copies the first `n` bytes and then counts and drops the rest
  of the body as it arrives, including the trailing newline, without ever
  holding `size` bytes. U5 asserts the bound.
- **Release through the existing path.** A `(oid, head)` entry is a shared
  entry like a full read: `GitContentSource.prepare` counts a reference for
  it, and `GitContentSource.done` and `BlobBatchReader.release`
  (`content-source.ts:285-294`, `blob-reader.ts:175-177`) release it after
  its last path. A head entry that is never released keeps 4 KiB per blob
  for the whole run, which breaks the bound on a repository with many
  images. U5 also asserts `blobsHeld` returns to zero.

Order for a candidate blob:

1. `--batch-check` as today. `missing` and a non-blob type fail exactly as
   in the 1.10.0 design, section 2.6.
2. `readHead(oid, 4096)`.
3. Confirmed: skipped by type. No size check, no full read.
4. Not confirmed: the size check of today (`too_large` above 32 MiB), then a
   full `read(oid)` and a text scan. That second request is the only extra
   git work, and it only happens for a mismatch, which is rare.

A non-candidate blob is read exactly as today, size check first. A
conflicted path classifies the stage 2 and stage 3 blobs separately.

No new git process: head reads use the reader's existing `--batch` process,
so the call count from the 1.10.0 design's test U1 (exactly 9 file-set and
content calls for a plain scan of one repository, at most two `cat-file` per
repository) holds unchanged and is the pin for this (U6 below).

### 4.3 Disk path

- **Untracked file, or a run outside git** (`content-source.ts:517-527`):
  for a candidate, open the file, read up to 4096 bytes from the descriptor,
  decide; only a mismatch then goes on to `stat`, the size check and the full
  read, from the same descriptor so the bytes judged are the bytes read.
- **The disk copy of a tracked file** (`:568-621`): the same, judged on the
  disk copy's own bytes, independent of the blob's outcome. A blob that is
  an LFS pointer and a disk copy that is the real `.mp4` give: blob scanned,
  disk copy skipped, `binaryCopiesSkipped` 1, the file counted as scanned. A
  `.png` blob that is a real image and an unstaged disk copy replaced with
  text give: blob skipped, disk copy scanned, findings tagged `source:
  worktree`, a mismatch counted.
- **A tracked symlink named on the command line** (1.10.0 design, 2.1),
  whose entry carries a `diskPath` to the resolved target: each copy is
  judged by the name of the bytes it holds. The blob is the link text and
  is judged by the link's own name, which is what the user typed. The disk
  read is the target's content and is judged by the target's name
  (`diskPath`). So `notes.txt` pointing at `clip.mp4` has its link text
  scanned and the video skipped; `clip.mp4` pointing at `notes.txt` has
  its link text judged as a `.mp4` (a mismatch, scanned, since link text
  is not media) and the target scanned as text.

### 4.4 `--staged`

The staged branch reads the index blob through the content source built from
the staged listing, with the inherited git environment (1.10.0 design, 2.3).
The head read goes through the same reader and the same environment. The
`No staged (stage 0) blob found` check (`scan-utils.ts:633-635`) now applies
to candidates too, which is correct: a staged file must have a blob.

### 4.5 Pull-request mode

The HEAD blob is classified on its own bytes (4.2). A disk copy is read only
when the 1.10.0 rules say so (it differs from HEAD, or has a `filter`
attribute) and is classified on its own bytes. A head-side attribute can
therefore only add a disk read; it cannot stop the blob from being judged.

### 4.6 Other surfaces

- **MCP `scan_workspace`** uses `scanFileContent`, so it gets the rule and
  the counts; its result gains the same counts (section 5). Its own copy of
  the extension list and both uses (`workspace-scan.ts:17-24`, `:88`,
  `:92`) are deleted, not left as dead code.
- **MCP `scan_file`** (`packages/mcp/src/server.ts:272`) scans the named
  file with no binary skip and no budget today, and keeps doing exactly
  that: the user named the file, so there is nothing to skip on their
  behalf. It gains no skip, no re-time and no new count.
- **The `baseline` command** scans through `scanFilesAsync`
  (`packages/cli/src/commands/baseline.ts:243`), so it gets the rule.
  `baseline --write` output changes accordingly: a text file under a
  binary name that used to be skipped now produces findings the writer
  lists and accepts or refuses under its existing rules, and confirmed
  binary files under the new families produce none where, read as text,
  they could produce false positives. Its counts follow section 5.
- **The programmatic `skipBinary` option** of `ScanOptions`
  (`scan-utils.ts:360`, default `true`) keeps its name and changes meaning:
  `true` applies this design's rule (skip only on name and bytes agreeing),
  `false` scans every file as text with no classification at all, as it
  does today. Its doc comment says so.
- **`isBinaryFile`** is reachable only through the CLI's internal utils
  barrel (`packages/cli/src/utils/index.ts`) and is not re-exported from
  `packages/cli/src/index.ts`, so it is deleted outright, together with
  `BINARY_EXTENSIONS`.
- **`scanFiles` (sync)** has no production caller (`docs/INVARIANTS.md`).
  It switches to the classifier with a synchronous head read, so no exported
  function keeps the name-only skip.
- **The VS Code extension** scans editor buffers, which are already text,
  and is unchanged.
- **`fix`** edits files on disk and is unchanged.

### 4.7 The size limit and confirmed binary files

The size limit applies to everything scanned as text, which includes every
type mismatch: a 33 MiB `credentials.mov` that is text is `too_large` and
exit 2, and a 32.1 MiB JSON is exit 2, exactly as today.

A copy confirmed binary is not scanned as text, so the limit does not apply
to it, in the same way it never applied to a `.png` or `.zip` the type
filter dropped before reading anything. A 40 MiB `.mp4` whose bytes agree is
skipped and counted, not exit 2. Applying the limit first would turn every
committed archive or image over 32 MiB, which 1.10.0 skips, into a new
exit 2. This reading of "over 32 MiB stays exit 2" is flagged for the
operator as open point 1.

### 4.8 Cost

New work per run: a head read for every candidate. For a blob the whole
object is inflated and piped even though 4096 bytes are kept, because git
cannot read a range. Media and images are already compressed, git stores
them with little further compression, and inflate of that is fast; the cost
is roughly the tracked size of binary files at pipe and inflate speed. For a
disk read it is one `open` and one 4 KiB `read`. Against that, every video,
audio and font file stops being decoded and pattern-scanned, which is by far
the larger cost. Section 10 measures both and sets the budget.

Rejected: sniffing the disk copy instead of the blob when `status` says the
two agree. `status` compares after git's clean conversion, so with a head
`working-tree-encoding` or `filter` on the path the disk bytes can differ
while `status` is silent. That is exactly the MB1 shape; the blob is the
only copy whose bytes nobody upstream of the run controls.

---

## 5. Accounting and output

A skip by type is a decision the run made, so it is stated every run. A
type mismatch is a file whose name and content disagree, which is either a
broken file or someone hiding text behind a name, so it is named.

**Counting unit is the file.** A file is "skipped by type" when no copy of
it was scanned (`skippedByType`). A file with at least one scanned copy is
"scanned", counted in `files_scanned`, and its confirmed binary copies are
counted in `binary_worktree_copies_skipped`.

**JSON `run`**, every field always present, zero included (the existing rule
for skip counts):

| Field | Meaning |
|---|---|
| `binary_files_skipped` | Existing name, narrower meaning: files skipped because name and bytes agreed. |
| `binary_files_skipped_by_family` | New. `{ "image": n, "document": n, "video": n, "audio": n, "font": n, "archive": n, "executable": n, "other": n }`, all keys present. Sums to `binary_files_skipped`. |
| `binary_worktree_copies_skipped` | New. Disk copies confirmed binary whose file was otherwise scanned. |
| `binary_type_mismatch_scanned` | New. Files with a binary extension whose bytes are text, scanned as text. |
| `binary_type_mismatch` | New. `[{ "file", "family" }]`, sorted by file, every entry. |
| `scan_budget_retimed` | New, section 6. |

**SARIF** run properties carry the same six keys. `formatSarif` copies run
fields by name (`packages/core/src/scan-output.ts:528-581`), so each needs
its own line there; a test asserts SARIF and JSON carry equal values.

**Diagnostics.** A type mismatch adds a `file.type_mismatch` warning
(`ctx: { file, family }`), a new `DiagnosticCode`. A skip by type adds no
diagnostic: it is counted, and a warning per image would make the warning
count meaningless.

**Text**, each line only when non-zero, so a clean run with no binary files
prints byte for byte what it prints today:

```
Binary files skipped: 19 (content matched the extension: image 12, video 3, font 4)
Working-tree copies skipped as binary, blob scanned: 2
Files named as binary but holding text, scanned as text: 1 (config/credentials.mov)
```

The first keeps its existing prefix so anything reading it keeps working;
families are listed in table order, non-zero only. The mismatch line is
yellow, names up to three files, then `and N more`, with the same escaping
of control characters as the 1.10.0 proposal lines.

**MCP** `scan_workspace` JSON and SARIF gain the same counts beside its
existing `unscannable_files`.

**Exit status** is unchanged by every one of these.

---

## 6. The budget: CPU time, and one re-time

### 6.1 What changes

The budget stops measuring wall time and measures **CPU time spent by the
scanning thread during the scan of one copy**. A copy whose first scan is
over the budget is scanned once more, from the same decoded text, and the
second measurement decides.

### 6.2 Why CPU time

| Measure | Catches a runaway pattern | Load-dependent | Notes |
|---|---|---|---|
| Wall time (today) | yes | yes: counts time the OS did not run the thread | F04's flakes |
| Wall time plus one re-time | yes | less: needs two unlucky slices | still flakes on a saturated runner |
| CPU time | yes: backtracking is CPU | barely: frequency scaling and shared cores still move it, by a bounded factor | needs a CPU clock |
| A load-aware threshold (budget scaled by load average) | yes | no, in principle | load average is not available on Windows, lags by a minute, and turns the budget into a number nobody can predict |

The budget exists to refuse a result whose scan behaved pathologically, and
pathological here means CPU: catastrophic backtracking burns CPU, and an
11-second runaway on an idle machine is 11 seconds of CPU. Time the thread
spent descheduled says nothing about the content. CPU time keeps the first
property and drops the noise. The re-time stays as well, for what CPU time
does not remove (a throttled or shared core can still inflate CPU time, by
a factor far below what descheduling does).

**The clock.** Node gives process-wide CPU time through `process.cpuUsage()`.
A per-thread clock (`process.threadCpuUsage()`) exists only in newer Node
releases; whether the lowest supported Node (22.0.0, per `engines`) has it
is not established here and the implementer checks it (open point 4). The
rule is static, decided once per process from facts that can be read
without calling the clock: use `process.threadCpuUsage()` only when the
function exists AND `process.versions.node` falls in a recorded range in
which it is stable (a constant beside the clock, holding the Node lines
the implementer verified, open point 4). Otherwise measure **the smaller
of process CPU time (`process.cpuUsage()`, user plus system) and wall
time** over the same span. The decision is never made by calling the
per-thread clock and watching for a warning, because that probe would
itself emit the warning. Two tests pin it: one drives the decision with a
stubbed version string and a stubbed function presence (in range and
present: per-thread; out of range or absent: fallback); the other, run on
every Node line in the CI matrix, spies on `process.on('warning')` during
a full scan and asserts no warning is emitted.

Why the minimum on the fallback: process CPU also counts the libuv
threadpool reading the other in-flight files and V8's concurrent GC and
compiler threads, so on a multi-core machine it can exceed wall time and
put an honest file over budget where today's wall-time check would not.
The scanning thread's own CPU time is at most its wall time and at most
the process's CPU time, so `min(process CPU, wall)` is never below the
thread's true CPU time: it never under-measures a runaway, and it is never
larger than today's measure, so the fallback is never worse than 1.10.0.

With the per-thread clock the same holds directly: thread CPU is at most
wall time, so every measurement, and therefore the 10 s cap in 6.3, is at
most what today's wall-time check would see. The cap can only send a file
to INCOMPLETE without a re-time when today's check would already have
called it over budget.

The measured span is unchanged: `scanContent` plus `applyPathAwareSeverity`
for one decoded text. Decoding and reading stay outside it. The budget
itself moves into core: `ScanFileContentOptions` gains `budgetMs` and a
seam `clock` that supplies both the CPU and the wall reading (default the
rule above), and `scanFileContent` decides trusted or untrusted, including
the re-time. The post-hoc comparisons in `scanOneFile`
(`scan-utils.ts:541-543`) and in the MCP `scanOne` (`workspace-scan.ts:120-122`)
are replaced by reading that decision from the outcome, so the CLI and MCP
cannot drift apart.

**The scanner is deterministic.** `scanContent` builds a fresh `RegExp`
for each pattern on every call, iterates `Map`s in insertion order, and
reads no time and no random input (`packages/core/src/scanners/secret-scanner.ts:551-581`).
Two passes over the same text therefore return the same matches, and the
"results differed" outcome in 6.3 step 6 is a guard against a future
change, not a new source of flakes.

### 6.3 The re-time

For one copy:

1. First pass: scan, take the 6.2 measure `c1`. If `c1 <= budget`, done.
2. If `c1 > 2 * budget` (10 s), the copy is untrusted at once. No re-time:
   no plausible load factor doubles CPU time, and a genuine runaway should
   not be paid for twice.
3. Otherwise run a second pass over the **same decoded text**, with a fresh
   inline-directive tally that is then discarded (so suppressions are not
   counted twice), and measure `c2`.
4. If `c2 <= budget` and the second pass's matches equal the first pass's
   (same rule, line, offset, length and value digest, in order), the copy is
   trusted. The first pass's matches are reported (they are the same).
   `scan_budget_retimed` is incremented.
5. If `c2 > budget`, the copy is untrusted: `kind: 'scan_budget'`, reason
   `scan exceeded the 5000 ms CPU budget twice (first 6210 ms, re-timed 6034 ms)`,
   the `file.scan_timeout` diagnostic with `ctx: { file, elapsed_ms: c2,
   first_ms: c1, wall_ms, budget_ms, measure, retimed: true }`, where
   `measure` is `thread-cpu` or `min-process-cpu-wall` (6.2).
   `elapsed_ms` stays the deciding measurement, so existing readers keep a
   meaningful number.
6. If the two passes' matches differ, the copy is untrusted with
   `kind: 'scan_budget'` and the reason `scan results differed between two
   passes over the same content`. The scanner is deterministic, so this
   cannot happen today; if a later change makes it happen, the run must not
   pick one answer quietly.

The over-budget outcome after the re-time is exactly today's: an
INCOMPLETE entry, exit 2, the exclude hint. A blob and its disk copy are
timed and re-timed separately, as in the 1.10.0 design (2.8).

### 6.4 Why this is not a coverage loss

Both passes scan the whole content with every pattern. The re-time changes
only the decision about whether the first pass's result is trusted, never
what was scanned or what was found. The worst case for coverage is
unchanged: a file over budget twice is INCOMPLETE and exit 2, as a file over
budget once is today.

### 6.5 Output

- JSON and SARIF: `scan_budget_retimed`, always present.
- Text, when non-zero, grey:
  `Files re-timed after a slow first scan, then trusted: 1`.
- README "What fails the build": "took longer than the per-file time budget
  (5000 ms)" becomes "used more than 5000 ms of CPU time to scan, twice".

---

## 7. The 32 MiB limit and the first line on stderr

The limit is unchanged for anything scanned as text (4.7). The hint already
names the file and the remedy (1.5). Two changes make the first line enough
on its own:

1. **`reportIncomplete` sorts its entries by file** before printing, so the
   first file named is deterministic.
2. **The first line names the first file, immediately after the label**,
   before the counts:

   ```
   INCOMPLETE: First: data/export.json. 1 file(s) or target(s) over the 32 MiB scan limit were not scanned
   ```

   The counts part joins one clause per kind with `; ` (`scan.ts:126-137`),
   so with two or three kinds the line passes a 160-character cap; putting
   the file first means the cap only ever cuts counts, never the name. A
   path longer than 60 characters is shortened in the middle with `...`.
   The remedy stays on the detail lines below, where it can be printed in
   full and pasted.

**Everything else that can reach stderr before INCOMPLETE today.** Read from
the code. There is no `--verbose` flag: `scanCommand` sets the internal
`verbose` option to `format === 'text'` (`scan.ts:473`, `:496`), so every
"verbose" line below is a text-format line. The umbrella runs vault-guard
with `-f json`, where only the upgrade note precedes INCOMPLETE today; the
text-format lines matter for every other wrapper and for CI logs.

| Line | Where | When | Treatment |
|---|---|---|---|
| `extra_pattern rejected: ...` and its follow-up | `scan.ts:372-385` | text format, before the scan | Collected, printed after the INCOMPLETE block. A rejected pattern is a warning and the run carries on; the exit 2 comes from the unscannable file. |
| Progress `Scanning... N%`, written with a carriage return and no newline | `scan-utils.ts:689-697`, `:980-990`; on whenever the format is text (`scan.ts:475`, `:498`) | text format, more than 10 files | Suppressed when stderr is not a TTY (below). |
| `Warning: Cannot access ...`, `Warning: Cannot read directory ...` | `file-utils.ts:326-328`, `:339-341` | text format, during the walk outside git | Collected, printed after the INCOMPLETE block. |
| `Warning: <link>: symlink target ...` | `scan-utils.ts:834` | text format, during the scan | Collected, printed after. |
| `Error: Path not found: ...`, `Error: Invalid path: ...` | `scan-utils.ts:849`, `:885` | text format, during the scan | Collected, printed after. |
| `Error scanning file: ...` and the error text | `scan-utils.ts:678-681`, `:965-971` | text format, during the scan | Collected, printed after. |
| `Baseline file invalid: ...` | `scan.ts:582-588` | text, after the scan | Collected, printed after. |
| The 1.4.0 upgrade note | `scan.ts:727-745` | all formats, after the scan | Dropped on exit 2 (section 8). |
| The `N warning(s)` summary | `scan.ts:780-784` | text, after the scan | Printed after the INCOMPLETE block. |

**Progress is suppressed when stderr is not a TTY**, in every mode: it
exists for a person watching a terminal, and in a pipe or a CI log it is
noise. Worse, its carriage return puts the next stderr text on the same
physical line, so a wrapper that splits on newlines, strips control
characters and caps at 160 characters reads `Scanning... 100% INCOMPLETE:
...` and loses the reason once the scan had more than 10 files. The same
change closes the dogfood polish finding that the progress indicator floods
piped output. A TTY run keeps it, and ends the progress line with a newline
before anything else is written to stderr.

**The invariant, stated precisely:** when stderr is not a TTY, in every
format, on a run that exits 2 through the INCOMPLETE path, the INCOMPLETE
line is the first line vault-guard itself writes to stderr. There is no
exempt class within vault-guard's own output. Outside it, and so outside
the invariant: the unsupported-Node warning `cli-entry.ts:7` prints before
the CLI starts, and process warnings Node writes on its own (deprecations,
MaxListeners). Chosen: scope, not a deferring `process.on('warning')`
listener, because deferring them would hide runtime diagnostics from every
reader. The one such warning this design could introduce, an
ExperimentalWarning from the CPU clock on some Node line, is avoided by
the static rule of 6.2: the per-thread clock is used only when it exists
and `process.versions.node` is in the recorded stable range, never decided
by probing it. A stubbed-version test pins the decision, and a warning-spy
test on every CI Node line asserts a scan emits no process warning.

Implementation shape: the walk and scan paths write their text-format lines
to a collector passed in through `ScanOptions` instead of calling
`console.error` directly, and `scanCommand` collects the extra_pattern
rejection lines the same way instead of printing them before the scan; `scanCommand` prints the collected lines after `reportIncomplete`
on an incomplete run, and where they were before on a complete run, so a
complete run's output is unchanged apart from progress on a non-TTY.
`scanIncomplete` is computed before any advisory stderr is written. stdout is
unchanged, including the JSON and SARIF documents, which are still written in
full.

---

## 8. The upgrade note

**When it is printed** (unchanged otherwise): the run completed (no
INCOMPLETE entry), findings exist, none is at or above the gate, and the
user never chose a threshold (neither `--fail-on` nor `fail_on`).

**When it must not be printed:** any run that exits 2. On the INCOMPLETE
path that is `scanIncomplete`. Every other exit 2 already returns before the
note's code is reached (config error, invalid `--fail-on`, git failure,
trust-base failure, nothing scanned). Two of those can be reached after the
scan, with findings already in hand: the `GitError` catch
(`scan.ts:946-951`), for example when `listTrackedIgnoredFiles` fails in
pull-request mode after the scan (`:645`), and the fatal-error catch
(`:952-953`), for example when the baseline's `readBytes` throws `no bytes
kept` (`:611`). Both throw before the note's code at `:733`, so the note is
never printed there; a test pins each one (A20).

**Moved or dropped:** dropped on exit 2, not moved after INCOMPLETE. Its
sentence "This run would have failed before" is a statement about the
verdict, and an exit-2 run has no verdict; printing it after the INCOMPLETE
block would still be read as part of the reason by anything that reads the
whole of stderr. With no findings the note is already not printed
(`totalMatches > 0`), and that stays.

Whether to retire the note altogether, seven minor releases after 1.4.0, is
open point 6; the recommendation is to keep it, suppressed on exit 2, until
the next major.

---

## 9. Trust base and pull-request mode

- **No control value comes from the head.** The family table, the sniff
  window, the signatures, the budget, the re-time cap and the size limit are
  constants in the published package. None is a config key, so neither the
  base nor the head config can change them; none is read from the
  environment or from any file in the scanned tree. A head `.vault-guard.json`
  that tried to add one would be an unknown key and a proposal either way.
- **What the check reads is content, not control.** The bytes sniffed are
  the bytes being judged: the HEAD blob in pull-request mode, the index blob
  in plain mode and `--staged`. A pull request controls content by
  definition; the rule in 2.1 is what makes a name-only change insufficient.
- **Attributes cannot steer it.** A head `.gitattributes` line such as
  `credentials.mov binary -diff -text` changes nothing: the blob is read
  without attributes (1.10.0 design, section 2) and classified on its bytes.
  An attribute can only add a disk read, which is classified on its own
  bytes and can add findings, never remove the blob's.
- **The base config's `ignore` list** remains the only way to exclude a file
  in pull-request mode, as today.
- **The budget's clock** is the process's own; nothing in the tree can set
  it. A head can only make content slower to scan, which ends in
  INCOMPLETE, exit 2, never in a pass.

---

## 10. Real-repository validation

This is part of the implementation PR, not a follow-up. Recorded in
`bench/real-repos/2026-10-NN-1.11.0.json` (the date of the run), with the
method added to `bench/real-repos/README.md` and `run.cjs` extended rather
than copied.

**Repositories.** The four from the 1.10.0 run (facebook/react,
urllib3/urllib3, gitleaks/gitleaks, Yelp/detect-secrets), to show nothing
regressed where there is little media, plus four public repositories chosen
for committed binary files:

- **mdn/learning-area**: committed video (`.mp4`, `.webm`), audio (`.mp3`,
  `.ogg`) and many images, in a tree that is otherwise HTML, CSS and
  JavaScript.
- **FortAwesome/Font-Awesome**: committed web fonts (`.woff2`, `.ttf`).
- **goldfire/howler.js**: committed audio in its examples (`.webm`, `.mp3`).
- **github/explore**: an image-heavy tree (a PNG logo per topic and
  collection) with no video, which is the case the head-read cost in 4.8
  lands on hardest: in 1.10.0 those PNGs were never read at all, and now
  every one is streamed through `cat-file` for its first 4096 bytes. It is
  the repository the wall-time gate below is really about.

Before running, the implementer records per repository, from `git ls-files`
at the cloned commit, the count of tracked files per extension in the
section 3 table. If a repository turns out not to contain the family it was
chosen for, it is replaced by another public repository that does, and the
record says so. Each clone is at depth 1, `origin` removed, `clone_head`
recorded, as in the 1.10.0 method.

**Builds.** Published 1.10.0 and the implementation branch.

**Commands per build and repository**, three runs each, median wall time:
`scan . --format json` and `scan . --trust-base <clone_head> --format json`
on the existing one-commit `vg-bench` branch. Plus a **load run** on the
three media repositories: the same plain scan with a CPU load generator
running twice as many busy processes as the machine has cores, three runs.

**Recorded** per repository, build and command: `files_scanned`,
`type_filtered_files`, `binary_files_skipped`,
`binary_files_skipped_by_family`, `binary_worktree_copies_skipped`,
`binary_type_mismatch_scanned` and the full `binary_type_mismatch` list,
`unscannable_files` by kind, `scan_budget_retimed`, the per-extension counts
above, every finding as rule, file, line, severity, source and fingerprints
(never the value), wall time, and the machine. The branch also records
`head_read_bytes`, the total body bytes piped through `cat-file` for head
reads (a bench-only counter on `GitContentSource`, not an output field), so
the cost in 4.8 is a measured number. For the load run also the count of
`scan_budget` entries per build.

**Expected.** Define, per repository:

- M: tracked files with a newly listed media or font extension whose bytes
  agree (scanned as text by 1.10.0, skipped by the branch);
- T: files the 1.10.0 type filter removed by a lowercase image, PDF or
  archive extension (that filter is case-sensitive, so an uppercase `.PNG`
  was never in it; see 1.1);
- I: the files of T whose bytes agree (skipped by the branch);
- B: files 1.10.0 skipped through `isBinaryFile` (uppercase image and
  archive extensions, and the library extensions);
- X: files of T or B whose bytes do not agree (ASCII-only PDFs, short or
  damaged headers, text under a binary name), which the branch now scans.

Then:

- `files_scanned` (branch) = `files_scanned` (1.10.0) minus M plus X.
- `binary_files_skipped` (branch) = `binary_files_skipped` (1.10.0) plus M
  plus I minus the files of B that are in X.
- `type_filtered_files` (branch) = `type_filtered_files` (1.10.0) minus T.
- `binary_type_mismatch_scanned` = X plus any newly listed media or font
  file whose bytes do not agree; expected 0 on all eight, or every entry
  explained in the record (an ASCII-only PDF is the expected kind).
- `unscannable_files` of kind `too_large`: unchanged, except media and
  archives over 32 MiB whose bytes agree, which move to skipped by type,
  and any file of X over 32 MiB, which becomes `too_large`.
- Load run: 1.10.0 may show `scan_budget` entries on media; the branch shows
  none.
- Findings: every finding 1.10.0 reported that the branch does not is in a
  file of M or I (false positives from binary content read as text). New
  findings may appear only in files of X. So the branch's set equals
  1.10.0's set minus findings in M and I plus findings in X; it is a subset
  of 1.10.0's only when no file of X holds a finding. On the four 1.10.0
  repositories, findings are identical apart from those three sets.

**Release blockers.**

- A file 1.10.0 scanned as text that the branch does not, outside M.
- A lost finding in a file outside M and I.
- A new finding outside X.
- Any mismatch the record cannot explain.
- Any `scan_budget` entry on the branch in the load run.
- Plain-scan wall time on any of the four 1.10.0 repositories, or on
  github/explore, over 1.15 times 1.10.0's, median of three. On the media
  repositories the branch is expected to be faster and any slowdown is
  investigated before release.

The two private dogfood shapes (a frontend with committed videos, a
monorepo with a 32.1 MiB tracked JSON) are run by the operator and recorded
as counts only, with no names or paths. Expected: the frontend exits on its
findings alone with the videos under `binary_files_skipped`; the monorepo
still exits 2, with a first stderr line naming the JSON file.

---

## 11. Test plan

Fixtures are temporary git repositories built with real commits and driven
through `scanCommand` in-process, except where a row says subprocess. Keys
are built at run time, never the documentation example key. Media fixtures
are synthetic: the minimal valid header for the format followed by
pseudo-random bytes from a fixed seed, so no third-party media is committed.
Every row names the mutation it must kill; the implementer applies each
mutation once and records the red run in the implementation PR.

**Stderr assertions** (A9, A18, A20, A23, A23b, A26, A27) apply the same
cleaning the umbrella applies (control characters and non-ASCII replaced,
whitespace collapsed, trimmed) before looking at the first line, or
equivalently match `INCOMPLETE:` after an optional prefix. The real line
starts with the red-cross prefix, so a bare "starts with INCOMPLETE" on
raw stderr would be red for the wrong reason.

**Every fixture whose subject file may be skipped also holds a second,
ordinary scannable file** (a clean `src/ok.ts`). Without it, a run whose
only file is skipped exits 2 through "nothing was scanned"
(`scan.ts:549-559`) on BOTH sides of a mutation, and the row proves
nothing. This applies to A2 to A4 (and A3's named-target case, which names
both files), A5, A7, A8, A10, A21, A24, A25 and U11. A row's expected exit code is then
the subject file's own verdict.

### 11.1 Adversarial fixtures

| id | Fixture | Before (8680511) | After | Mutation killed |
|---|---|---|---|---|
| A1 | Base commit; head adds `config/credentials.mov`, plain text holding a key. `scan . --trust-base base`. Repeated plain and `--staged`. | exit 1 (`.mov` read as text) | exit 1; `binary_type_mismatch_scanned` 1, the file listed with family `video`; `file.type_mismatch` warning | Media extension skipped on name alone (A1a, red: exit 0). |
| A2 | As A1 with `credentials.png`. | exit 0, `Files skipped by type or name: 1` | exit 1, mismatch counted, family `image` | `.png` left in `shouldIgnoreFile` (A2a); signature check skipped, so any `.png` is confirmed (A2b). |
| A3 | As A1 with `credentials.PNG`, and as a named target `scan credentials.PNG`. | exit 0 | exit 1 | Extension compared case-sensitively in the classifier (red on `.PNG`). |
| A4 | As A1 with `dump.bin`, UTF-8 text with no NUL. | exit 0 | exit 1 | `.bin` confirmed without R4. |
| A21 | `dump.bin` as NUL-separated `KEY=VALUE` records (the `env -0` shape), one of them holding a key. Plain, `--staged`, `--trust-base`. | exit 0 in all three | exit 1 in all three, mismatch counted, family `other` | NUL counted as non-text evidence for a signature-less row (red: exit 0, the V2 shape). |
| A24 | `dump.bin` in Windows-1252, the `set > dump.bin` shape: CRLF-separated `KEY=VALUE` lines, one holding a key, and a `USERNAME=` line whose value ends in byte `E9` (an accented e in Windows-1252, invalid UTF-8). Plain, `--staged`, `--trust-base`. | exit 0 in all three | exit 1 in all three, mismatch counted, family `other` | Invalid UTF-8 accepted as evidence for a signature-less row (red: exit 0). |
| A25 | `intro.mov` whose first bytes are printable text matching a printable signature: four ASCII characters, then `free`, then Latin-1 text with one byte `E9` and a key; no NUL and no control byte in the first 4096 bytes. Plain and `--trust-base`. | exit 1 (`.mov` read as text) | exit 1, mismatch counted, family `video` | Invalid UTF-8 accepted as evidence for a printable signature (red: exit 0). |
| A22 | `clip.mp4` with `working-tree-encoding=UTF-16LE`. Its blob is UTF-8 text with no key; its working copy has an unstaged edit, so git writes it BOM-less UTF-16LE, and the edited text begins `ab` followed by U+7466 and U+7079, which in UTF-16LE puts `ftyp` at byte offset 4 and NULs at bytes 1 and 3, then a key. Plain scan. | exit 1 (`.mp4` read as text; the disk copy is decoded by its label) | exit 1, the key `source: worktree`, a mismatch counted for the disk copy | The declared-encoding rule removed (red: the signature matches and the NULs count, so the disk copy is skipped and the key is lost). |
| A22b | A22 with non-ASCII text: the edited working copy also contains `U+00E9` (UTF-16LE `E9 00`) and `U+0101` (UTF-16LE `01 01`) before the key. | exit 1 | exit 1, the key `source: worktree` | Declared-encoding rule implemented as "NUL alone does not count" instead of "a successful fatal decode with the declared label means text" (red: the `01 01` control bytes and the invalid UTF-8 confirm the copy, and the key is lost). |
| A5 | `notes.bin`, UTF-16LE with a BOM, holding a key, whose first line contains U+0101 (encoded `01 01`, two control bytes). | exit 0 | exit 1, finding at line 2 | BOM rule removed (red: the `01` bytes are control bytes, so R4 calls it binary). |
| A6 | `song.ogg` whose bytes are `OggS` followed by ASCII text holding a key, no NUL. | exit 1 | exit 1, mismatch counted | R4 removed, signature alone confirms (red: exit 0). |
| A7 | Boundary, pinned on purpose: `clip.mp4` whose first 8 bytes are `00 00 00 20 66 74 79 70` followed by text holding a key. A second case: a POSIX `.tar` (with `ustar` magic) holding a `.env` with a key, which is stored uncompressed. | exit 1; the `.tar` exit 0 (type filtered) | exit 0 both, each counted under `binary_files_skipped` | None: these are the documented known limits (2.3, section 3, `.tar` reasoning). The tests exist so that tightening either later is a deliberate, visible change. |
| A8 | A real-header `.mp4` of 40 MiB (header plus seeded random bytes), beside the clean `src/ok.ts`. Plain, `--trust-base`, `--staged`. | exit 2, `too_large` (`.mp4` is not on the list) | exit 0, skipped, family `video`, `files_scanned` 1 | Size check before the head read for candidates (red: exit 2 through `too_large`, distinguishable from the nothing-scanned exit 2 by the INCOMPLETE line). |
| A9 | A 33 MiB `credentials.mov` that is text; and a 32.1 MiB `data/export.json`. | exit 2 both | exit 2 both; first non-empty stderr line starts `INCOMPLETE` and names the file | Mismatch exempted from the size limit (A9a, red on the `.mov`); first line not naming the file (A9b). |
| A10 | LFS shape without git-lfs: a local filter driver whose clean command prints a fixed pointer text and whose smudge is `cat`; `.gitattributes` `*.mp4 filter=vgtest`; the blob is the pointer, the disk copy is a real-header `.mp4`. Plain scan. | disk copy read as text | exit 0; blob scanned, not a mismatch; `binary_worktree_copies_skipped` 1; `files_scanned` counts the file | LFS pointer counted as a mismatch (A10a, red: mismatch 1); disk copy judged by the blob's outcome (A10b). |
| A11 | Tracked real `logo.png` (blob confirmed); unstaged edit replaces the disk copy with text holding a key. Plain scan. | exit 0 (type filtered) | exit 1, finding `source: worktree`, mismatch counted | Copies classified once per file instead of per copy. |
| A12 | Head adds `.gitattributes` `credentials.mov binary -diff -text` on top of A1. `--trust-base`. | exit 1 | exit 1, plus the attributes proposal line | Any attribute consulted by the classifier. |
| A13 | Budget re-time passes: CPU seam returns 6000 ms then 100 ms for one file holding a key below the gate. | exit 2 (wall seam 6000) | exit 0 on findings, `scan_budget_retimed` 1, no INCOMPLETE | No re-time (A13a, red: exit 2); second measurement ignored (A13b). |
| A14 | Budget re-time fails: seam 6000 then 6000. | exit 2 | exit 2, reason says `twice`, `first_ms` 6000 in the diagnostic | Re-time trusts unconditionally (red: exit 0). |
| A15 | Cap: seam 12000 on the first pass. | exit 2 | exit 2, scanner called exactly once for that copy | Cap removed (red: two calls). |
| A16 | Determinism: a test scanner whose second call returns one extra match. Seam 6000 then 100. | n/a | exit 2, reason `scan results differed` | Match comparison removed (red: exit 0). |
| A17 | Wall versus CPU: the `clock` seam drives both readings; wall advances 10 s during the scan while the CPU reading advances 50 ms. Run once with the per-thread branch of the seam and once with the fallback branch (process CPU 12 s, wall 10 s, so the minimum is 10 s against a 5 s budget, then the same pair again on the re-time). | exit 2 | per-thread: exit 0 on findings, no re-time. Fallback: exit 2 with `measure: min-process-cpu-wall`, `elapsed_ms` 10000, never 12000 | Wall time used as the measure (A17a, red on the per-thread run); fallback using process CPU without the minimum (A17b, red: `elapsed_ms` 12000). |
| A18 | Upgrade note on exit 2: implicit gate, one low finding, and two unscannable files: a 33 MiB text file, and an UNTRACKED file made unreadable with `chmod 000` (a tracked file is read from its blob, so only an untracked one fails to read; skipped on Windows). Run with stderr piped (not a TTY), in text, JSON and SARIF, with an invalid baseline in the tree and a config holding one `extra_pattern` the ReDoS guard rejects. | JSON and SARIF: stderr starts with `note: earlier vault-guard versions`. Text: stderr starts with `extra_pattern rejected:` | exit 2; no `note:` line anywhere on stderr; the first non-empty stderr line starts with `INCOMPLETE` in all three formats, and in text `extra_pattern rejected:`, `Error scanning file:`, `Baseline file invalid` and `N warning(s)` all appear after the INCOMPLETE block; JSON and SARIF documents still complete on stdout | `scanIncomplete` missing from the note's condition (A18a); text summary left before INCOMPLETE (A18b); baseline warning left before it (A18c); text-format scan errors printed directly instead of collected (A18d); extra_pattern rejection printed before the scan (A18e). |
| A19 | Control for A18: the same without the unscannable files. | note printed | note printed, exit 0 | Note removed altogether. |
| A20 | The two exit-2 paths reached after the scan with findings in hand, implicit gate and one low finding each: (a) `--trust-base` with `listTrackedIgnoredFiles` failing through a stub `git` (subprocess); (b) the baseline `readBytes` seam throwing. | no note (already) | no note, exit 2 | Pins section 8: a refactor that moves the note above either throw (red: note printed). |
| A23 | Progress on a pipe: a text-mode run over 12 files, one of them an untracked unreadable file (as A18), stderr piped. Subprocess, so `isTTY` is genuinely false. | stderr's first physical line is `Scanning... N%` followed on the same line by `INCOMPLETE`; after the umbrella's sanitising and its 160-character cap the reason is cut | no carriage return anywhere on stderr; the first line starts with `INCOMPLETE` | Progress left on for a non-TTY (red: carriage return present). |
| A23b | Required, not optional: the same run with `process.stderr.isTTY` forced true in-process (the CLI reads only that property to decide), stderr captured. | progress drawn; INCOMPLETE on the same physical line as the last progress update | progress drawn, and a newline written after the last progress update before the INCOMPLETE line | Progress suppressed for a TTY too (A23b-1, red: no progress); progress line not ended (A23b-2, red: `INCOMPLETE` follows a carriage return with no newline). |
| A26 | Walk-time warnings, OUTSIDE git (they fire only on the filesystem walk): a temporary directory with no `.git`, a subdirectory made unreadable with `chmod 000` (skipped on Windows), a file inside it, plus a 33 MiB text file so the run is INCOMPLETE. Text format, stderr piped. | stderr starts with `Warning: Cannot read directory` | exit 2; first line `INCOMPLETE`; `Warning: Cannot read directory` after the block | Walk warnings printed directly instead of collected (red). |
| A27 | `scan a.ts missing.ts`, and `scan a.ts fifo` where `fifo` is a named pipe (skipped on Windows), text format, stderr piped. | stderr starts with `Error: Path not found` / `Error: Invalid path` | exit 2; first line `INCOMPLETE` naming the target; the `Error:` line after the block | Path-not-found and invalid-path lines printed directly (red, each on its own). |

### 11.2 Unit and integration tests

| id | Test | Mutation killed |
|---|---|---|
| U1 | `it.each` over every table row: the minimal valid header confirms; the same with its first signature byte flipped does not; a 0-byte file and a file one byte shorter than the signature do not. | A signature typo or an offset off by one (each row red on its own). |
| U2 | The excluded set (`.ts`, `.mts`, `.m2ts`, `.vob`, `.svg`, `.pfa`, `.pfb`, `.fnt`, `.txt`) is never a candidate. | `.ts` or `.mts` added to the table. |
| U3 | Window edge in the declared-label decode, where `stream: true` is load-bearing. (a) A `.bin` disk copy declared `UTF-16LE`, BOM-less, holding `U+0101` (bytes `01 01`) and a key, laid out so a surrogate pair (an emoji) occupies bytes 4094 to 4097, split by the 4096-byte window. (b) A `.bin` disk copy declared `SHIFT_JIS` holding a `01` control byte and a key, laid out so the window's last byte (offset 4095, offsets counted from 0) is the lead byte of a two-byte character whose trail byte is at offset 4096, outside the window. Both: not confirmed, the key found, `source: worktree`. | Fatal decode without `stream: true` (red on both: the cut character fails the fatal decode, the copy falls to the row rule, the `01` control byte confirms it, the copy is skipped and the key is lost). |
| U4 | R6: the exact pointer header under 1024 bytes is a pointer; the same header in a 2048-byte file is not. | Size bound dropped. |
| U5 | `BlobBatchReader.readHead`: blobs of 0, 3, 4096, 4097 bytes and 40 MiB return `min(size, 4096)` identical bytes; a full `read` of a different object queued right after each returns that object byte-identical; the largest buffer held during the 40 MiB head read stays under 1 MiB; after a scan of 50 image blobs `blobsHeld` is 0. | Head read stops consuming at 4096 bytes (red: the next object desyncs); body buffered whole, no discard mode (red on the memory assertion); `(oid, head)` entries not released through `done` and `release` (red: `blobsHeld` 50). |
| U6 | The 1.10.0 call-count test, unchanged, on a fixture that also holds images and videos: still exactly 9 file-set and content git calls and at most two `cat-file` per repository. | Head reads on a separate process. |
| U7 | JSON: all six new fields present at zero on a tree with no binary files; family counts sum to `binary_files_skipped`; SARIF run properties equal JSON for each. | A field emitted only when non-zero (U7a); SARIF line missing (U7b). |
| U8 | Text: the clean-run plain summary is byte-identical to 1.10.0's on the existing pinned fixture; the three new lines appear with the wording of section 5 when non-zero; the mismatch line names three files then `and 2 more`. | Lines printed at zero. |
| U9 | `reportIncomplete` with three unscannable files completed in reverse order prints them sorted; the first line names the first sorted file; a 90-character path is shortened to 60 with `...`. | Unsorted list (red on order). |
| U10 | MCP `scan_workspace` on A2's tree finds the key and reports the mismatch; on A8's tree reports the skip; budget re-time applies through the same seam. | MCP left on its own extension list. |
| U11 | `--staged` with the existing `.woff2` fixture: still exit 0, and now `binary_files_skipped` 1 with family `font` (the existing test gains the count assertion). The staged `.png` fixture of the same suite: its bytes `89 50 4E 47 00 01 02` are too short for the 8-byte PNG signature, so it becomes a mismatch scanned as text and still exits 0; the test is updated to say so, and a second case with a full signature asserts the skip. | Staged path left on `isBinaryFile`. |
| U12 | A tracked image missing from a sparse checkout: plain run counts it in `tracked_files_missing`; `--trust-base` exits 2 naming it. | Pins the section 2.4 consequence so it is a decision, not an accident. |
| U13 | Inline directives during a re-time: a file with one `ignore-line` directive and seam 6000 then 100 reports `inline_suppressed` 1, not 2. | Second pass's tally folded in. |
| U14 | `--staged` head read under a hook's index: a `git commit -a` pre-commit hook (subprocess) running `scan --staged`, where `-a` stages a modified `logo.png` replaced with text holding a key (so the only copy of that content is in the temporary index `GIT_INDEX_FILE` names), plus a staged real `.woff2`. Hook exit 1 on the `.png`, and the `.woff2` counted as skipped; the stub `git` log shows the head and full reads ran on the one `cat-file --batch` with `GIT_INDEX_FILE` set. | Head read given `cleanGitEnv` (red: the blob is not found or the wrong one is read). U6 counts processes only and cannot catch this. |
| U15 | R4 per signature kind. Signature-less (`.bin`): printable UTF-8 with NULs, not confirmed; with one `0x01` byte, confirmed; with only BEL, BS, tab, LF, VT, FF, CR, SUB and ESC controls (a terminal capture with an OSC title ending in BEL, nroff overstrike, a trailing DOS `1A`), not confirmed; with SO and SI (ISO-2022-KR shape), confirmed, pinning the documented limit; Latin-1 and Shift-JIS text (invalid UTF-8, no controls), not confirmed. Printable signature (`OggS`, `ftyp`): with a NUL, confirmed; with a control byte, confirmed; with only invalid UTF-8, not confirmed. Binary signature (PNG): with only invalid UTF-8 after it, confirmed. ELF: `7F 45 4C 46` followed only by printable text, not confirmed; with a real header's NULs, confirmed. Declared label `UTF-16LE` on a head that decodes cleanly: never confirmed, for every row; an unmapped label (`UTF-32`): never confirmed. Labels routed to the BOM sniff, on a `.bin` disk copy with no BOM holding `U+0101` and `U+00E9`: `UTF-16` with big-endian bytes, not confirmed; `UTF-16` with little-endian bytes that also hold `U+00DF` (bytes `DF 00`, which read big-endian are `U+DF00`, a lone low surrogate, with no code unit before it that reads big-endian as a high surrogate, so the BE decode fails and the LE decode succeeds), not confirmed; `UTF-16LE-BOM` with no BOM, not confirmed; `UTF-8` on valid UTF-8 text, not confirmed. | Control-byte set off by one, or BEL, BS or SUB left out of the text set (each case red on its own); evidence rules swapped between signature kinds (red on the Latin-1 and printable-signature cases); `7F` counted as evidence (red on the ELF text case); unmapped label falling through to the row rule (red on the `UTF-32` case); a BOM-routed UTF-16 label decoded as UTF-8 (red: the UTF-8 decode fails on `U+00E9`, the copy falls to the row rule and `01 01` confirms it); little-endian not tried after big-endian (red on the little-endian case: without `U+00DF` the BE decode of little-endian `U+0101`, `U+00E9` and ASCII would succeed and the mutation could not go red, which is why the case carries it). |
| U16 | MCP `scan_file` unchanged: on a real-header `.mp4` beside nothing else it scans the file as text (no skip, no count, no budget entry), and on A2's `credentials.png` it returns the key. | `scan_file` routed through the classifier (red: the `.mp4` is skipped). |
| U17 | `skipBinary: false` through `scanFilesAsync` on a tree holding a real-header `.png`, A2's `credentials.png` and a `.ts` file: all three are scanned as text, `binary_files_skipped` and `binary_type_mismatch_scanned` are 0, and the classifier is never called (spy). | `false` still classifying (red: the real `.png` skipped or a mismatch counted). |
| U18 | Named tracked symlinks (4.3): `notes.txt` linking to a real-header `clip.mp4` inside the repository, and `clip.mp4` linking to `notes.txt` holding a key. First: link text scanned, target skipped and counted under `binary_worktree_copies_skipped`. Second: link text a mismatch (judged by the link's `.mp4` name), target scanned, key found `source: worktree`. | Disk copy judged by the link's name instead of `diskPath` (red on the first: the video is read as text and no copy is skipped); blob judged by the target's name (red on the second: no mismatch for the link text). |

---

## 12. Release shape

### 12.1 CHANGELOG draft for 1.11.0

```
## [1.11.0] - YYYY-MM-DD

**Minor.** Video, audio and font files are no longer read as text, every
binary skip now needs the file's own bytes to agree with its extension, and
a file that goes over the scan time budget is scanned once more before the
run refuses to trust it. A run that was green on 1.10.0 can be red on this
release: a text file named like an image, an archive or a native library
used to be skipped on its name alone and is now scanned.

### Added

- Video (.mp4, .mov, .m4v, .webm, .mkv, .avi, .ogv, .flv, .wmv, .mpg and
  others), audio (.mp3, .wav, .ogg, .opus, .flac, .m4a, .aac, .aiff, .mid
  and others) and font files (.woff, .woff2, .ttf, .otf, .ttc, .eot) are
  recognised as binary and skipped when their bytes carry the format's
  signature. Until 1.10.0 they were read as text, and one large video could
  go over the per-file time budget and make the run exit 2.
- `run.binary_files_skipped_by_family`, `run.binary_worktree_copies_skipped`,
  `run.binary_type_mismatch_scanned`, `run.binary_type_mismatch` and
  `run.scan_budget_retimed` in JSON, the same counts in SARIF run
  properties, and text lines for each when it is not zero.
- A `file.type_mismatch` warning for a file whose extension names a binary
  type but whose content is text.

### Changed

- A file is skipped as binary only when its extension and its first bytes
  agree. This applies to the existing image, PDF, archive and library
  extensions as well as the new ones, in every mode, including
  `--trust-base` and `--staged`. A file whose bytes do not agree is scanned
  as text and listed. Content alone never causes a skip: a text file with a
  NUL byte is still scanned. A .bin file, which has no format signature, is
  skipped only when its first bytes hold a control byte that text does not
  use; NUL bytes and non-UTF-8 bytes never count, so NUL-separated text
  (an env -0 dump) and text in a legacy codepage (a Windows set > dump.bin)
  are scanned. Formats whose signature is plain ASCII (Ogg, PDF, BMP, MP4
  and QuickTime atoms, and others) also need a NUL or control byte, so text
  in any codepage that happens to start with such letters is scanned. A
  working-tree copy with a declared working-tree-encoding that decodes
  cleanly in that encoding is always treated as text.
- Images, PDFs and archives are now counted under `binary_files_skipped`
  rather than `type_filtered_files`, and pass through the config `ignore`
  list like any other file.
- The per-file scan budget measures CPU time instead of wall time, and a
  file over it is scanned a second time from the same content. Only a file
  over the budget on both passes is reported as not trusted, with exit 2 as
  before. A busy machine no longer makes the result change from run to run.
- On a run that exits 2 with an INCOMPLETE report and stderr not a
  terminal, the INCOMPLETE line is the first line on stderr, in every
  format, and it names the first file. Warnings that used to come first (a
  rejected extra_pattern, per-file scan errors, a baseline parse warning,
  the warning summary) now follow it.
- The progress indicator (Scanning... N%) is no longer written when stderr
  is not a terminal. It used to fill piped output and CI logs with
  carriage-return updates, and it put the INCOMPLETE line on the same line
  as itself.
- The 1.4.0 upgrade note is no longer printed on a run that exits 2.

### Security

- A text file with a binary extension was skipped unread in every mode:
  plain directory scans, pull-request mode (--trust-base), --staged, a file
  named on the command line, and the MCP scan_workspace tool, which has
  carried its own copy of the same name-only list since 1.0.0. The
  affected names were .png, .jpg, .jpeg, .gif, .ico, .pdf, .zip, .tar and
  .gz (dropped by the file-set type filter, in lowercase), the same in any
  case, and .exe, .dll, .so, .dylib and .bin (skipped at scan time). A key
  saved as credentials.png or in an env dump named dump.bin therefore
  passed the gate, including in a pull request, with only a skip count to
  show for it (and no count at all from scan_workspace). This has been the
  behaviour of every release up to and including 1.10.0. From 1.11.0 such
  a file is scanned as text, reported under binary_type_mismatch, and can
  fail the run. A file is skipped only when its own first bytes carry the
  format's signature and are not text, or, for .bin, which has no
  signature, when its first bytes hold a control byte that text does not
  use.

### Fixed

- A committed video could make a run exit 2 at random under machine load.
- A wrapper that quotes the first stderr line of a run that could not
  complete quoted the upgrade note instead of the reason.

Unchanged: the 32 MiB whole-file limit for anything scanned as text, the
exit code rules, and the name-based skips of .lock, .log and .map files,
lockfiles and minified bundles.
```

### 12.2 README wording

"What fails the build" table, the budget row becomes:

```
| The file's scan used more than 5000 ms of CPU time on two passes, so its result is not trusted | Fix the file, or declare it in `ignore.paths` |
```

The paragraph after the exclude example ("A staged blob containing a NUL
byte ...") is replaced by:

```
vault-guard skips a file as binary only when its extension names an image,
document, video, audio, font, archive or library format AND its first bytes
carry that format's signature. A file with a binary extension and text inside
is scanned as text and listed (`binary_type_mismatch`), so renaming a file
never hides it. Content alone never causes a skip: a text file containing a
NUL byte is scanned. A `.bin` file has no signature, so it is skipped only
when its first bytes contain a control byte that text does not use; NUL
bytes and non-UTF-8 bytes never count, so NUL-separated text (an `env -0`
dump) and text in a legacy codepage (Latin-1, Windows-1252, Shift-JIS) are
scanned. A format whose signature is plain letters (Ogg, PDF, BMP, the MP4
and QuickTime atoms) also needs a NUL or control byte before it is skipped.
UTF-16 files that carry a byte order mark are decoded and
scanned, while UTF-16 without a BOM is not detected. A binary file is skipped
at any size; anything scanned as text is limited to 32 MiB.
```

The next paragraph's `binary_files_skipped` gloss becomes "(skipped because
the extension and the file's first bytes agree on a binary format, with a
per-format breakdown in `binary_files_skipped_by_family`)", and it gains
`binary_type_mismatch_scanned` and `scan_budget_retimed` in the list of
always-present counts. The pull-request section's bullet about files skipped
"by extension or name" drops images from its examples and keeps `.min.js`,
`.lock`, `.map` and lockfiles. The implementer greps `README.md`,
`docs/GITHUB_ACTION.md`, `docs/MCP.md` and `docs/THREAT_MODEL.md` for
"binary", "budget" and "extension" and updates every hit in the same PR.
`docs/THREAT_MODEL.md` gains the 2.1 boundary in one paragraph.

---

## 13. `docs/INVARIANTS.md`

### 13.1 Replaced

The section "The staged path skips a blob by extension only, never by
content" is no longer true and is replaced, keeping its history paragraph,
by:

```
## A binary skip needs the extension and the bytes to agree

The rule: a copy of a file (an untracked file, a blob, a disk copy) is
skipped as binary only when its lowercased extension is in the family table
in packages/core/src/utils/binary-type.ts, its first 4096 bytes carry one of
that extension's signatures, and those bytes do not start with a byte order
mark and carry non-text evidence. A control byte below means a C0 byte
outside the text set NUL, BEL, BS, tab, LF, VT, FF, CR, SUB and ESC. For a
binary signature (one
with a byte outside printable ASCII), the evidence is a NUL, a control byte
or invalid UTF-8. For a printable signature (OggS, %PDF-, BM, ftyp and the
other atoms at offset 4, and the rest listed in the design), a NUL or a
control byte; invalid UTF-8 does not count. For a row with no signature
(.bin), a control byte only; neither NUL nor invalid UTF-8 counts. A copy
with a declared working-tree-encoding whose head decodes in that encoding
with fatal, streaming decoding (a UTF-16 label with no BOM decoded as
UTF-16, big-endian then little-endian), or whose label is outside the label
map, is never confirmed. Content never causes a skip on its own: a NUL byte in a .ts
file is scanned, as the V2 fix required, and NUL-separated text or
legacy-codepage text named .bin is scanned.
A copy with a binary extension that fails the check is scanned as text,
under the size limit and the budget, and counted in
run.binary_type_mismatch, except a Git LFS pointer, which is scanned and not
counted. Every mode applies the same classifier: plain, --trust-base,
--staged, a named target, and the MCP workspace scan. The table is a
constant; no config key, flag, environment variable or file in the scanned
tree changes it.

Boundary: a file whose first bytes are a valid binary header followed by
text is skipped. That is a change to the content, the same class as
encoding a secret, which no pattern scanner detects. What the rule
guarantees is that a name alone never removes text from the scan. Known
limits beside it: a POSIX tar with the ustar magic is skipped although its
members are stored uncompressed, which is the behaviour of every earlier
release; and .bin, having no signature, is the weakest row: ISO-2022-KR
text, which uses SO and SI (0E, 0F), named .bin with no declared
working-tree-encoding is skipped, and so is any text file with another
control byte outside the text set. ELF and EBML heads get no evidence
from their signature bytes and are confirmed only by the bytes after them.

Enforced by: binary-type.ts and the per-copy check in scanFileContent and
scanTrackedCopies (content-source.ts). Tests: the adversarial fixtures of
the 2026-10-17 design, section 11.1, by their final test titles.
```

The implementer replaces the last paragraph with the real test titles once
they exist.

### 13.2 Amended

In "Directory and pull-request mode fail closed, with a declared way out",
"The limits" paragraph: "`DEFAULT_SCAN_BUDGET_MS` is 5000 ms per file, checked
after the scan returns" becomes "`DEFAULT_SCAN_BUDGET_MS` is 5000 ms of CPU
time per copy, checked after the scan returns; a copy over it is scanned once
more from the same text and is untrusted only when the second pass is over
too, or the first was over twice the budget", and "Binary extensions and the
walk's type filter are removed before either number applies" becomes "A copy
confirmed binary and the walk's name filter are removed before either number
applies; a binary extension whose bytes are text is subject to both".

### 13.3 Appended

```
## On a run that cannot complete, the reason is the first thing said

The rule: when stderr is not a TTY, in every format (text, JSON, SARIF),
on a run that exits 2 through the INCOMPLETE path, the INCOMPLETE line is
the first line on stderr, and it names the first unscannable file, in
sorted order, right after the label. Every other line (a rejected
extra_pattern, walk and scan errors, a baseline parse warning, the warning
summary) is collected and printed after the INCOMPLETE block. A rejected
extra_pattern is a warning and the run carries on; the exit 2 comes from
the unscannable file, so that file is the reason to state first.
Progress output is not written when stderr is not a TTY, so no carriage
return can join another line to INCOMPLETE. The 1.4.0 upgrade note is
never printed on a run that exits 2: it describes a verdict, and such a
run has none. Wrappers quote the first stderr line as the gate's reason,
so anything printed before it becomes the reason.

Scope: this covers vault-guard's own output. Two kinds of line can still
precede it and are outside the rule: the unsupported-Node warning
cli-entry.ts prints before anything runs (the run is on an unsupported
runtime, and that is the more important thing to say), and warnings Node
itself writes for the process (deprecations, MaxListeners). vault-guard
does not install a process warning listener to defer them, because that
would hide a runtime's own diagnostics from every other reader. One
source is closed instead of scoped: process.threadCpuUsage is used only
when it exists and process.versions.node is in a recorded range where it
is stable, a static rule that never probes the clock; every other line
takes the process-CPU fallback. Tests: the decision driven by a stubbed
version string, and a process warning spy asserting a scan emits no
warning on each supported CI Node line.

Enforced by: scanCommand in packages/cli/src/commands/scan.ts, and the
collector the walk and scan paths write text-format lines to. Tests: the
A18, A19, A20, A23, A23b, A26 and A27 fixtures of the 2026-10-17 design,
by their final test titles. Each asserts on stderr after the same
control-character and non-ASCII stripping the umbrella applies, so the
red-cross prefix does not matter; the first line then begins with
INCOMPLETE: after optional whitespace.
```

```
## The scan budget is CPU time, re-timed once

The rule: the per-file budget is measured in CPU time of the scan of one
decoded copy, not wall time: the scanning thread's CPU time where Node
provides it, otherwise the smaller of process CPU time and wall time, so
the measure is never larger than the wall time 1.10.0 used. A copy over it is scanned a second time from
the same text, with the second pass's inline tally discarded; it is trusted
only if the second pass is within the budget and its matches equal the
first pass's. A first pass over twice the budget is untrusted without a
second pass. An untrusted copy is INCOMPLETE and exit 2. Both passes scan
the whole content, so the re-time changes a decision, never coverage.

Enforced by: scanFileContent in content-source.ts and its clock seam.
Tests: A13 to A17 and U13 of the 2026-10-17 design, by their final titles.
```

---

## 14. Open points

Each has a recommended default; the implementer proceeds on the default
unless the operator rules otherwise.

1. **A confirmed binary file over 32 MiB is skipped, not exit 2.** The plan
   says "over 32 MiB stays exit 2". This design reads that as applying to
   anything scanned as text (the 32.1 MiB JSON, a text file under a media
   name), because 1.10.0 already skips images and archives of any size and
   applying the limit first would make every large committed archive a new
   exit 2. Default: skip and count. If the operator wants every file over
   32 MiB to be exit 2, the change is one ordering line, and the
   CHANGELOG must then say that large images and archives start failing.
2. **The content-change boundary (A7).** Ruled: for rows with a signature,
   a valid header followed by text is skipped, accepted and documented
   (THREAT_MODEL, INVARIANTS); a bounded sniff cannot close it, and a
   whole-file test costs what F04 is about. For signature-less rows the
   ruling is replaced by the stricter R4 of 2.2 (only a control byte
   counts; neither NUL nor invalid UTF-8 does), and printable signatures
   need a NUL or a control byte, not invalid UTF-8.
3. **Text skipped by name (`.lock`, `.log`, `.map`, lockfiles, minified).**
   A key in `leak.log` still passes on its name in every mode. Default: not
   in 1.11.0; raise as its own item with a real-repository false-positive
   run, starting with `.log`, which has no generated-content excuse.
4. **The CPU clock on Node 22.0.** Whether a per-thread CPU clock exists on
   the lowest supported Node was not verified here. Ruled, refined: the
   per-thread clock when present, otherwise `min(process CPU, wall)` (6.2),
   which never under-measures a runaway and is never worse than 1.10.0's
   wall time. The implementer records which branch each supported Node line
   takes.
5. **The re-time cap at twice the budget.** Default: 10 s. A lower cap
   saves time on genuine runaways and risks a flake on a badly throttled
   core; a higher one the reverse.
6. **Retiring the 1.4.0 note.** Default: keep, suppressed on exit 2, and
   remove it in the next major.
7. **More archive types** (`.tgz`, `.bz2`, `.xz`, `.7z`, `.zst`, `.jar`,
   `.whl`). Default: not in 1.11.0. They are read as text today, which is
   more coverage, and the bench will show whether any is a budget problem.
8. **Cost of head reads for blobs.** git streams the whole blob for a 4 KiB
   head. Default: accept if the section 10 budget (1.15 times on the four
   1.10.0 repositories and on the image-heavy github/explore) holds, with
   `head_read_bytes` recorded so the cost is a number; if it does not, the fallback to consider is
   skipping the head read for a blob whose disk copy git reports clean and
   whose path has no `filter` or `working-tree-encoding` attribute, which
   needs its own review because it reads the disk.
9. **Images missing from a sparse checkout in pull-request mode** become
   exit 2 like any missing tracked file (U12). Default: accept; pull-request
   runs on a sparse checkout are already exit 2 for any other missing file,
   and the remedy is the same.
10. **ASCII-only PDFs** are mismatches and print a warning. Default: accept;
    they are text and are scanned, and the bench will show how common they
    are.
11. **Mismatch and pull-request mode.** A type mismatch is listed but does
    not change the exit code or appear as a proposal. Default: keep it that
    way; the file was scanned in full, so there is nothing the run did not
    check.
12. **The plan's premise about a NUL sniff.** No sniff shipped in 1.10.0
    (section 1.2). Nothing to rule; noted so the plan is corrected. BOM-less
    UTF-16 in an untracked file stays undetected and is not part of this
    item.
