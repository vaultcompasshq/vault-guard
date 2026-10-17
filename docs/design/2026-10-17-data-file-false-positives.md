# Fewer false positives in data files: encoded-payload demotion and grouped repeats

Status: design, revised after an independent review (three blocking
findings fixed: bare runs are demoted only on a PNG or JPEG header, demoted
matches stay out of the legacy baseline list and keep the critical refusal,
and a group never mixes severities or demotion status; ten non-blocking
items applied). Target: 1.12.0, a minor, all four packages
in lockstep as for 1.11.0. It covers one finding from the dogfood runs:

- **F17** (verified 2026-10-11). Two shapes, both rated as blocking:
  - Scraped CSV files holding JWT-shaped strings: 24 to 48 hits per
    repository, one data column repeating the same shape thousands of rows
    down. Each cell is its own `jwt-token` finding at `high`.
  - An 800 KB single-line SVG whose `data:image/png;base64,` payload contains
    an `AIza`-shaped run. It is reported as `gcp-api-key` at `critical`.

**Decided before this doc, not reopened** (operator plan, item 4.1):

1. Demote or skip key-shaped matches inside long base64 runs and `data:`
   URIs.
2. Group per-file repeats in data files (CSV, TSV, large minified JSON) into
   one finding.
3. Validate against a public corpus and record a baseline a later run can
   diff against.
4. Minor release.

This design chooses **demote, never skip** for item 1 (section 2.4), and
reads item 2 as **grouping is presentation, never a severity change**
(section 5).

Line citations are against `main` at 90b479a (1.11.0 plus the merged
relative-paths change, unreleased). Each was read in the code, not taken from
the plan. The umbrella's reader is cited from the `@vaultcompass/conductor`
repository at its current `main`.

---

## 1. Current behaviour

### 1.1 How a finding gets its severity today

In order, for one decoded copy of one file:

1. **The rule table.** Each built-in rule carries a fixed severity
   (`packages/core/src/scanners/secret-scanner.ts:76-249`). `gcp-api-key` is
   `/AIza[a-zA-Z0-9_-]{35}/g` at `critical` (`:127`). `jwt-token` is
   `/(?<![A-Za-z0-9_-])eyJ...\....\..../g` at `high` (`:239`).
2. **`severity_overrides`** from the config replace a rule's severity or turn
   it off (`:418-429`). Under `--trust-base` the config is the base ref's.
3. **Suppressing filters** inside `scanContent` (`:575-737`): sequential runs,
   entropy gates, placeholders, redacted templates, function-call and
   identifier values, local connection strings, the jwt.io sample, password
   hashes, PEM headers without a body, documentation-site suppressions,
   inline ignore directives. Each drops a match entirely.
4. **Overlap dedupe** (`:874-916`), which keeps the higher-ranked of two
   overlapping matches and therefore must see the rules' declared
   severities.
5. **In-file test regions** (`applyInlineTestSeverity`, `:769-788`), applied
   after dedupe on purpose (`:751-758`): low-precision rules inside a Rust
   `#[cfg(test)]` block drop to `low`.
6. **Path context** (`applyPathAwareSeverity`,
   `packages/core/src/utils/path-severity.ts:170-198`), applied by the caller
   (`content-source.ts:485-490`, `secret-scanner.ts:529-537`): test,
   documentation and locale paths drop the low-precision set
   (`path-downgrade-ids.ts:4-15`, locale only `:25-30`) to `low`.
   Vendor-anchored rules are never downgraded on a path.

There is no step that looks at what surrounds a match beyond its own line
(the doc-context suppression reads the line; the PEM check reads what follows
the header). A match that is a substring of something much longer is
reported exactly like a match that stands alone.

### 1.2 The two F17 shapes, traced

**The base64 SVG.** `gcp-api-key` has no boundary on either side. Inside a
base64 payload any 39-character window that starts with `AIza` and continues
with 35 characters of `[a-zA-Z0-9_-]` matches. For uniformly random standard
base64, the chance per starting position is

```
p_gcp = 64^-4 * (62/64)^35 = 5.96e-8 * 0.329 = 1.96e-8
```

(`+` and `/` are the two standard-alphabet characters outside the rule's
class). So a repository carrying 50 MB of base64 media in text files expects
about one `critical` from coincidence alone, and an 800 KB line about 0.016
per line. Across many repositories it happens, and F17 is that event. The
1.11.0 binary skip does not apply: an SVG, an HTML page, a CSS file or a
notebook is text, and `.svg` is excluded from the binary table on purpose
(1.11.0 design, section 3).

**The scraped CSV.** `jwt-token` has a lookbehind, but a comma is a
boundary, so every cell of a token column is a complete, ordinary
`jwt-token` match at `high`, and the default gate (`medium`,
`packages/core/src/utils/fail-on.ts:27`) blocks on each. The values are
real-looking tokens: nothing in the content says they are fake, and some may
be real (scraped session tokens). The cost is not a wrong verdict; it is 48
lines of output that say one thing.

So the two shapes are different problems:

- the SVG is a **false positive**: the matched characters are not a key, they
  are a slice of encoded image bytes;
- the CSV is **noise**: possibly real values, reported once per row.

They get different treatments: a demotion for the first (section 3), a
grouping for the second (section 5).

### 1.3 What 1.10.0 and 1.11.0 established

- **A name alone never reduces coverage.** 1.10.0 found that a two-letter
  basename (`db.ts`, `ci.yml`) counted as a locale path and downgraded DSNs,
  PEM keys and JWTs to `low`: a bypass by file name (design 2026-10-12,
  section 5; now `isLocalePath`, `path-severity.ts:120-122`, a locale
  DIRECTORY only). 1.11.0 found that every binary extension skipped text
  unread and made a skip require the bytes to agree (design 2026-10-17,
  section 2). This design keeps that rule: **no decision here reads a file
  name or an extension.**
- **Vendor-anchored rules are not downgraded by path context**
  (`docs/INVARIANTS.md`, "Vendor-anchored rules are not downgraded in docs or
  markdown"). This design does lower a vendor rule (`gcp-api-key` is the F17
  case), so it must say why that is a different kind of decision: it is made
  on the bytes around the match, which show the match is not a key, never on
  where the file sits (section 2.1).

### 1.4 Who reads what

The umbrella reads vault-guard's JSON, not its SARIF. Its normalizer
(`normalizeVaultGuard`, `src/normalize.ts:320-423` in the conductor
repository) turns every entry of `results[].matches[]` into one finding, marks
each blocking from its `severity` against `run.fail_on`, and compares the
number it derived with `run.blocking_matches`. If the two differ it marks
nothing blocking and raises `conductor/blocking-count-mismatch`. Two
consequences bind this design:

- `results[].matches[]` must keep one entry per match, and each entry's
  `severity` must be the severity the gate used. A grouped finding that
  replaced N matches with one would break the reconciliation on every grouped
  run.
- `run.blocking_matches` stays a count of matches (`countBlockingMatches`,
  `fail-on.ts:63-74`), never of groups.

---

## 2. The adversarial question first

### 2.1 The threat, stated

Every demotion is a place to hide a secret. The question is not "is this
match usually a false positive" but "what is the cheapest way for a real
secret to land in the demoted shape, and does that happen by accident".

A path downgrade answers "where is this file", which a pull request controls
for free and which says nothing about the bytes; that is why 1.10.0 cut the
locale basename and why vendor rules are never path-downgraded. A content
demotion has to answer "what are these bytes", and it is only acceptable when
the answer is positive evidence that the matched characters are not a
credential: they are part of a larger encoded object whose decoded form is a
known binary format.

The property this design guarantees:

> **A finding is lowered only on the bytes around the match, never on a
> file name, a path or a config value from the scanned tree; it is lowered,
> never removed; and the report says why.** A key-shaped match is demoted
> only when it lies strictly inside a single base64 run far longer than any
> credential, and that run decodes to the header of a known binary format
> (for a `data:` URI, the format its declared media type names; for a run
> with no `data:` prefix, a PNG or JPEG header only). A key that
> stands alone, is delimited on either side, sits at either end of a run, or
> sits in a run that does not decode to binary media keeps its full severity.
> Grouping never changes a severity or the exit code.

### 2.2 The cases

| Case | How it looks in the file | Outcome | The property that decides it |
|---|---|---|---|
| A real key pasted into a CSV cell | `...,AIzaSy...,...` or `"AIzaSy..."` | **full severity**, one finding | The match is delimited (comma or quote on each side), so it is not inside a run (C2). A single match is never grouped (G is 5). |
| A real key in a column of real keys (an export of customers' keys) | 200 rows, same column, same rule | **full severity**, one grouped finding, blocks | Members of a group share one severity, and every member counts toward the gate (5.4). |
| A real JWT among 500 scraped JWTs in one column | same column, same rule | **full severity** (`high`), one grouped finding, blocks under the default gate | As above. The real one cannot be told from the rest by shape; it was not distinguishable in 500 lines either (2.3, G-abuse). |
| A real API key inside a `data:` URI in an HTML file, plaintext | `href="data:text/html,<script>k='AIza...'</script>"` | **full severity** | Not base64 (no `;base64,`), and the key is delimited by quotes (C1, C2). |
| A real key pasted raw into a base64 text payload | `data:application/json;base64,eyJh...AIzaSy...` | **full severity** | The payload decodes to text, not to a binary signature (C4). |
| A real JWT inside a base64 blob that is decoded at runtime | `config = "ZXlKaGJHY2lPaUpJVXpJMU5pSjku..."` | **not found, as today** | The JWT is encoded, so its plaintext shape is not in the file. Encoded secrets are outside what any pattern scanner claims (THREAT_MODEL, binary-skip boundary). A coincidental match in such a blob stays at full severity: random bytes match the bare-run list (PNG's 8-byte or JPEG's 4-byte header) about once in a billion runs (C4). |
| A real key encoded inside a legitimate PNG's metadata (a `tEXt` chunk), the PNG embedded as a `data:` URI | `data:image/png;base64,iVBORw0KGgo...` | **not found, before and after** | The key's bytes are base64-encoded with the rest of the image, so its plaintext shape is not in the file. Not a regression: 1.11.0 does not find it either. A coincidental match elsewhere in that payload is demoted as in the F17 row. |
| A payload whose JSON encoder escaped `/` as `\/` | `"data:image/png;base64,iVBORw0KGgo\/..."` | **full severity**, as today | The escapes break the payload into runs at every `/`; the first run rarely reaches 1024 characters and the later ones start mid-stream and fail C4, so such a payload is in practice never demoted (3.5). |
| A coincidental `AIza` run inside an embedded PNG, JPEG, font or other media (F17) | `data:image/png;base64,iVBORw0KGgo...AIzaSy...AAAA` | **demoted to `low`**, reason recorded | Strictly inside a run of 1024 or more base64 characters (C1 to C3), the run decodes to a PNG header and its declared type is `image/png` (C4). |
| The same, in a notebook output or a JSON fixture with no `data:` prefix | `"image/png": "iVBORw0KGgo...AIzaSy..."` | **demoted to `low`** | As above, without a declared type: the decoded head must be a PNG header (8 bytes) or a JPEG header (`FF D8 FF` plus a fourth marker byte), from a frozen named list, with the 1.11.0 non-text evidence (C4, bare run). |
| A real key appended to the end of an image payload by a paste error | `...ElFTkSuQmCCAIzaSy...")` | **full severity** | The match touches the end of the run, so it is not strictly interior (C2). |
| A key-shaped run inside random base64 (an encrypted value, a sealed secret) | `"payload": "q8Fz...AIzaSy...Lm0="` | **full severity** | A bare run is demoted only on a PNG or JPEG header; random bytes produce one with probability about 4 in 2^32, roughly once in a billion runs (C4). |

### 2.3 Abuse, per decision

**D-abuse: hiding a key in a fake image payload.** A motivated author writes
`data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...` + the key + more base64,
1024 characters in all. The rule demotes it to `low`. What the author gets:

- The finding is still reported, in every format, with the reason
  `data-uri-binary-payload` and the decoded family. Under `--fail-on low` it
  blocks. In a pull request it is in the diff and in the output.
- The author has not gained anything over what is already free: base64
  encoding the key, which hides it completely from every pattern scanner
  today, costs less than building a fake PNG header around it and leaves no
  finding at all. The demotion only applies to a key that is still present
  in plaintext but wrapped in a deliberately crafted encoded object, and
  using it requires the application to read the raw payload at a known
  offset, which is the same deliberate-disguise class as encoding.

Accepted and documented as the boundary (THREAT_MODEL paragraph, section
11.3). A whole-payload validity check (that every byte decodes and the PNG
chunks are well formed) would raise the cost a little and still be
satisfiable by a real PNG with the key inserted and re-padded; it is not
proposed (open point 3).

**G-abuse: hiding a key among decoys.** An author adds 500 JWT-shaped decoys
and one real token to the same column. Grouping does not lower anything:
the decoys and the real token share the rule and the severity, so they form
one group at that severity, every member is in `blocking_matches`, and the
run blocks. A member at a different severity, or demoted when the rest are
not, is never in the same group (5.2), so a real `critical` cannot be listed
under a group of `low` locations. What the author gains is that a reviewer
sees one line instead of 501. What the reviewer can do is unchanged: accept
the file through `baseline --write` (which writes one entry per member, so
it accepts the real token along with the decoys) or exclude it through
`ignore.paths`. In a pull request neither is available to the author: the
baseline and config come from the base ref. A later new member is a new
finding (section 5.6). Accepted and documented: accepting a group accepts
every member, and a reviewer cannot tell a real member from a decoy by its
shape, exactly as with 501 separate lines.

**N-abuse: renaming.** Nothing in either rule reads a file name, an
extension or a path, so renaming changes nothing. Pinned by tests (A18, A22).

**C-abuse: steering by control files.** No config key, flag, environment
variable, attribute or file in the tree changes any threshold, table or
reason in this design (section 7). A head-side `.vault-guard.json` that adds
one is an unknown key and, under `--trust-base`, a proposal.

### 2.4 Rejected properties

- **Skip instead of demote.** A skipped match leaves no trace, cannot be
  turned back on by `--fail-on low`, and cannot be argued with. The plan
  allowed either; a demotion keeps every finding visible and keeps the gate's
  strictest setting meaningful.
- **Entropy of the surrounding run.** The candidate in the brief: demote when
  the run around the match is as random as the match. It gives no positive
  evidence that the run is encoded media rather than an encrypted secret or
  a pasted blob, and an author meets it by appending random characters. A
  decoded signature is positive evidence for the accidental case, and the
  rule is no weaker against the deliberate case (2.3).
- **The declared media type alone.** `data:image/png;base64,` followed by a
  payload that decodes to text would be demoted on a label the author
  writes. The name proposes, the bytes must agree, as in 1.11.0.
- **The file's extension** (`.svg`, `.csv`, `.ipynb`). Forbidden by the
  1.10.0 and 1.11.0 rule, and unnecessary: the content properties are
  sufficient and also cover the same shapes in files with any name.
- **A JWT's `exp` claim in the past.** An expired token is a weaker leak,
  and decoding the payload is cheap. Rejected because it makes the verdict
  depend on the clock: the same tree would turn from blocking to passing as
  time passes, and a run's verdict should depend on the tree and the
  controls only (open point 10).
- **A minimum count of identical values.** Grouping does not require the
  values to differ or to be equal; it reports how many distinct values there
  are (5.2). Requiring distinct values would split a column that repeats one
  real key into many groups; requiring equal values would not group F17.

---

## 3. The encoded-payload demotion

### 3.1 Definitions

- **Alphabet.** The union of the standard and URL-safe base64 alphabets:
  `A-Z`, `a-z`, `0-9`, `+`, `/`, `-`, `_`. Padding `=` is NOT in it.
- **Run.** A maximal span of alphabet characters in the decoded text of one
  copy. It ends at any other character, including `=`, a quote, whitespace,
  a newline, `\`, `.`, `,` and `%`.
- **`data:` payload.** A run whose first character immediately follows a
  case-insensitive `;base64,` that is itself part of
  `data:<type>/<subtype>[;param=value]*;base64,`, read backwards from the run
  start over at most 256 characters. `<type>/<subtype>` is the declared media
  type, lowercased, parameters ignored.

### 3.2 The rule

A match is demoted when ALL of C1 to C4 hold. The check runs per match,
never per rule, so there is no rule list to maintain.

- **C1. Inside one run.** Every character of the match is in the alphabet,
  so the match lies inside exactly one run. C1 is judged on the FULL match,
  `offset` to `offset + matchLength`, which is the whole of `match[0]`
  including any key name or prefix, never only the captured value
  (`secret-scanner.ts:722-728`). The alphabet includes `-` and `_`, so a
  prefixed token such as `sk-ant-...`, `ghp_...` or `sk_live_...` can satisfy
  C1. A match containing any other character (the dots of a JWT, the `://`
  and `@` of a DSN, the spaces of a PEM header, the `.` of `SG.`, `dp.`,
  `.apps.`, the `=` or `:` of an assignment) never qualifies.

  Consequently, with no list kept in code (the check is per match):
  - **Can be demoted** (every match is alphabet-only): `anthropic`,
    `openai`, `openai-project`, `openai-svcacct`, `openai-admin`,
    `huggingface`, `replicate`, `groq`, `openrouter`, `xai`, `perplexity`,
    `fireworks-ai`, `langsmith`, `stripe`, `stripe-test`, `aws-access`,
    `gcp-api-key`, `github-token`, `github-pat`, `gitlab-token`,
    `bitbucket-token`, `slack-token`, `resend-api`, `mailgun-api`,
    `npm-token`, `supabase-token`, `supabase-secret`, `vercel-blob`,
    `planetscale`, `databricks-token`, `notion-token`, `figma-token`,
    `newrelic-api`, `shopify-admin`, and any `extra_patterns` rule whose
    match happens to be alphabet-only.
  - **Never demoted** (every match holds a character outside the
    alphabet): `jwt-token`, `postgresql-url`, `mysql-url`, `mongodb-url`,
    `redis-url`, `ssh-private-key`, `slack-webhook`, `discord-webhook`,
    `sendgrid-api`, `doppler-token`, `airtable-pat`, `gcp-oauth`,
    `gcp-service-account`, `azure-storage`, `sentry-dsn`, `paypal`, every
    context-anchored rule (`aws-secret-context`, `mistral`, `together-ai`,
    `deepseek`, `cloudflare-token`), `bearer-token` (its space), and the
    generic assignments (`api-key-generic`, `secret-generic`,
    `password-in-code`).

  There are no exemptions by rule: a vendor key is judged by the same four
  conditions as any other match. One property helps here: a key carrying
  `-` or `_` spliced into a standard-alphabet payload (one that uses `+` or
  `/`) makes the run mixed, so C4 cannot decode it and the key keeps its
  severity.
- **C2. Strictly interior.** The run has at least one alphabet character
  before the match's first character and at least one after its last. A key
  flush against a quote, a comma, `=` padding or the end of the payload is
  not interior.
- **C3. Far longer than any key.** The run is at least `MIN_RUN = 1024`
  characters. The longest value-bearing token any built-in rule matches in
  practice is well under 300 characters (an `sk-proj-` key is at most 216 by
  its own bounds), so a run of 1024 is not a credential, whatever it holds.
- **C4. Decodes to binary media.** Decode the run's head: the first
  `min(length, 5464)` characters, truncated to a multiple of 4, as standard
  base64 when the run contains no `-` or `_`, as URL-safe base64 when it
  contains no `+` or `/`. A run with both pairs is not decoded and C4 fails.
  Take the first 4096 decoded bytes (`SNIFF_BYTES`). Then:
  - **`data:` payload.** The declared media type maps to an extension
    through the table in 3.3, and `confirmsBinary(ext, head)`
    (`packages/core/src/utils/binary-type.ts:249-268`) returns true: the
    row's signature at its offset, no byte-order mark, and the 1.11.0
    non-text evidence for that signature kind. A type outside the table
    (every `text/*`, `image/svg+xml`, `application/json`,
    `application/javascript`, `application/xml`,
    `application/octet-stream`, an empty type) fails C4.
  - **Bare run** (no `data:` prefix). The head begins with one of the
    signatures in `BARE_RUN_SIGNATURES`, a frozen named list of exactly two
    formats, and carries the 1.11.0 evidence for a binary signature (a NUL,
    a control byte, or invalid UTF-8; the signature's own `89` or `FF`
    supplies it):
    - **PNG**: `89 50 4E 47 0D 0A 1A 0A` at offset 0 (8 bytes);
    - **JPEG**: `FF D8 FF` followed by one of the marker bytes `E0` (JFIF),
      `E1` (Exif), `DB` (quantisation table) or `EE` (Adobe) at offset 0
      (4 bytes).

    No other row confirms a bare run. The binary table holds about 17 rows
    with a non-printable signature byte, several of them two bytes long
    (`FF FB` and the other MP3 frame syncs, AAC's `FF F1` and `FF F9`,
    gzip's `1F 8B`); taken together a random decoded head matches one of
    them with probability about 9 in 65536, roughly once in 7300 random or
    encrypted runs, which is far too often for a rule whose job is to say
    "this is media". PNG's 8 bytes match random data with probability
    2^-64 and the four JPEG headers with probability 4 in 2^32, about once
    in a billion runs. PNG and JPEG are also what bare runs in practice
    hold (notebook outputs, JSON fixtures, avatar fields). Every other
    format is demoted only inside a `data:` URI that declares it
    (open point 2, ruled).

When C1 to C4 hold the match's severity becomes `low` and it carries a
demotion record (section 4.2). When any fails, nothing changes.

### 3.3 Declared media types

| Declared type | Row |
|---|---|
| `image/png` | `.png` |
| `image/jpeg`, `image/jpg`, `image/pjpeg` | `.jpg` |
| `image/gif` | `.gif` |
| `image/x-icon`, `image/vnd.microsoft.icon` | `.ico` |
| `image/webp` | `.webp` |
| `image/bmp` | `.bmp` |
| `image/tiff` | `.tiff` |
| `image/avif`, `image/heic`, `image/heif` | `.avif`, `.heic`, `.heif` |
| `application/pdf` | `.pdf` |
| `font/woff`, `application/font-woff`, `application/x-font-woff` | `.woff` |
| `font/woff2` | `.woff2` |
| `font/ttf`, `application/x-font-ttf`, `application/x-font-truetype` | `.ttf` |
| `font/otf`, `application/x-font-opentype` | `.otf` |
| `application/vnd.ms-fontobject` | `.eot` |
| `audio/mpeg` | `.mp3` |
| `audio/wav`, `audio/wave`, `audio/x-wav` | `.wav` |
| `audio/ogg` | `.ogg` |
| `audio/flac` | `.flac` |
| `audio/mp4` | `.m4a` |
| `audio/webm` | `.weba` |
| `video/mp4` | `.mp4` |
| `video/webm` | `.webm` |
| `video/ogg` | `.ogv` |
| `application/zip` | `.zip` |
| `application/gzip` | `.gz` |

The table is a frozen constant beside the binary table, built the same way
(`FrozenMap`, `binary-type.ts:138-154`). It reuses the 1.11.0 rows, so a
signature or evidence fix there applies here too. `image/svg+xml` is never in
it: an SVG is text and can hold anything.

### 3.4 Why these four conditions

- **C1 and C2 separate a substring from a token.** A credential in a file is
  a token: a quote, an `=`, a comma, whitespace or a line end sits on each
  side. A coincidental hit in a payload is a substring with payload
  characters on both sides. C2 is also what keeps the accidental paste case
  (a key glued onto the end of a payload) at full severity.
- **C3 makes the run, not the match, the object.** A 1024-character token is
  not any credential format this tool knows; a run that long is an encoded
  object.
- **C4 is the positive evidence.** It is what the entropy candidate lacked:
  the run is not just random-looking, it decodes to the first bytes of a
  known binary format, which is what an embedded image, font or recording
  is. For a `data:` URI it also has to be the format the URI declares, so the
  label alone cannot demote, and the bytes alone cannot demote under a text
  label.
- **The bare-run case is stricter** because nothing proposes a format: only
  the PNG and JPEG headers count, which random or encrypted bytes produce
  about once in a billion runs. A short signature (two bytes) would be
  produced by chance about once in a few thousand runs, so it is not
  evidence of anything without a declared type beside it.
- **Under a declared type, only that type's row counts.** A
  `data:image/png;base64,` payload whose bytes are a real JPEG is not
  demoted (A26): the label and the bytes must agree, not merely both be
  binary.

### 3.5 Known limits, kept on purpose

- **Line-wrapped base64** (MIME bodies, PEM bundles, base64 wrapped at 76
  characters in CSS) breaks into runs shorter than 1024 and is never
  demoted. Its coincidental hits stay at full severity, as today.
- **A JSON encoder that escapes `/` as `\/`** breaks a payload into runs at
  every `/`. In standard base64 a `/` appears about once in 64 characters,
  so the first run rarely reaches 1024 characters, and the later runs start
  mid-stream and fail C4. Such a payload is in practice never demoted, and
  its coincidental hits stay, as today.
- **A text-typed base64 payload** (`data:application/json;base64,`, an inline
  source map) is never demoted, so a coincidental hit in it stays at full
  severity. Decoding it and scanning the decoded text would be new coverage,
  not a demotion (open point 4).
- **Compressed streams with no table row** (zlib's `78 9C`, raw deflate) are
  not media for C4; their coincidental hits stay (open point 12).

---

## 4. Severity

### 4.1 Demoted to what

To `low`, the existing level, not a new one.

- A new level (`info`, `needs-review`) would change the severity union in
  `SecretMatch` (`packages/core/src/types.ts:14`), the `--fail-on` values
  (`fail-on.ts:37-43`), the SARIF level mapping (`scan-output.ts:498`), the
  baseline's severity rule (`baseline.ts:336`) and the umbrella's severity
  union, which maps an unknown level to `info` and marks it derived
  (`src/normalize.ts:350-363` in conductor). Every consumer would need a
  release to read it.
- `medium` would keep the F17 SVG blocking under the default gate, which is
  the complaint.
- `low` is where every existing downgrade lands (path context, in-file test
  regions, `gcp-oauth`, `sentry-dsn`), so there is one rule for an adopter to
  learn: `--fail-on low` blocks on everything the scanner lowered.

The "needs review" marker is the demotion record (4.2): it is data on the
finding, not a severity.

### 4.2 The record

A demoted match carries:

```
demotion: {
  from: "critical",                 // the severity before this step
  reason: "data-uri-binary-payload" | "base64-binary-run",
  family: "image",                  // the binary family C4 confirmed
  format: ".png",                   // the row that confirmed it
  media_type: "image/png",          // only for a data: payload
  run_length: 812004                // characters in the run
}
```

`from` is the severity after the rule table, the override, dedupe and the
in-file test step. The path step and the in-file test step only ever lower
rules in the low-precision set (`path-downgrade-ids.ts:4-15`), and no rule
in that set can satisfy C1 (3.2), so the two never act on the same match: a
demoted match is never path-downgraded, and the order of the two steps does
not matter.

**A match already at `low` is not demoted** and carries no record: when a
`severity_overrides` entry has set the rule to `low`, the step is a no-op
and is skipped, so `demoted_matches` never counts a match whose severity did
not change.

### 4.3 The fail-on floor, made explicit

> The adopter's `--fail-on` (or `fail_on`, or the default) is applied to the
> demoted severity, exactly as to any other. A demoted match blocks under
> `--fail-on low` and does not block under `medium`, `high` or `critical`.
> `blocking_matches` counts it when, and only when, `low` meets the gate.

Nothing in this design changes the exit-code rules. Exit 1 is still "a
match at or above the gate", computed per match after the baseline
(`scan.ts:651-682`).

### 4.4 Order

The new step runs inside `SecretScanner.scanContent`, after
`applyInlineTestSeverity` (`secret-scanner.ts:754-758`), so:

- dedupe still ranks overlapping matches by their declared severities, for
  the same reason the in-file test step runs after it;
- every caller of `scanContent` gets it: the CLI in every mode, the MCP
  `scan_text`, `scan_file` and `scan_workspace` tools, `SecretScanner.scan`,
  the VS Code extension, `baseline --write`;
- it runs inside the budget span (`content-source.ts:485-491`), so its cost
  is measured, and it is deterministic, so the re-time comparison
  (`sameMatches`, `:459-468`) is unaffected.

The path step runs after it, unchanged.

**Dedupe, then demote, without losing a displaced match.** Dedupe keeps the
higher-ranked of two overlapping matches and drops the other
(`secret-scanner.ts:899-909`). If the winner is then demoted, the match it
displaced may be one that would not have been demoted: for example a
`bearer-token` match (`Bearer ` plus the start of a payload) that overlaps a
`critical` `gcp-api-key` slice inside the payload. Demoting the winner must
not leave the run with less than dedupe alone would have reported. So dedupe
also returns, for each kept match, the matches it displaced; for each kept
match that is demoted, every displaced match that would NOT itself be
demoted is restored at its own severity, and the restored matches are
deduped among themselves (and against the kept non-demoted matches) by the
existing rule. A displaced match that would also be demoted stays dropped:
the demoted winner already reports that span. Pinned by U12.

### 4.5 Baseline interactions

The baseline reader keys on the rule and the value (content fingerprint) or
on position plus file digest, never on severity, and an entry suppresses a
match only when the match's current severity is no higher than the severity
the entry recorded (`baseline.ts:332-339`). So:

- an existing entry recorded at `critical` suppresses the same match after
  it is demoted to `low`: upgrading never resurrects a baselined finding;
- an entry written for a demoted match records `low` (the writer records the
  severity it saw, and only writes findings that would block, so only under
  `--fail-on low`). If the content later changes so that the match is no
  longer demoted, the match is `critical` again and that entry does not
  suppress it.

**The legacy positional list, and the critical refusal.** `baseline --write`
also writes a positional fingerprint for every accepted value-bearing match
into the top-level `fingerprints` list, for 1.9.x runners that read only that
list (`packages/cli/src/commands/baseline.ts:315-329`). That list has no
severity rule: without an `entries` list the reader applies it as a bare
set (`filterResultsByBaseline`, `packages/core/src/baseline.ts:220-241`,
called at `:300-301`); the severity check at `:332-339` applies to entries
only. And the writer's refusal of critical findings without
`--include-critical` (`baseline.ts:307` in the CLI) reads the match's
current severity, which after a demotion is `low`. Unchanged, 1.12.0 under
`--fail-on low` would accept a demoted `critical` key without
`--include-critical` and write its positional key, and a 1.9.x runner (or
any reader of a baseline with no `entries`) would then suppress the same
match at `critical`. Two changes close it:

- **Demoted matches are left out of the positional list**, as header-only
  matches already are (`baseline.ts:315-318`). Their `entries` record, with
  its severity rule, is the only key written for them.
- **The `--include-critical` refusal reads `demotion.from`** when a
  demotion record is present: a match whose severity before demotion was
  `critical` is refused without the flag, exactly as it would have been in
  1.11.0.

With both, a demotion cannot be laundered into a baseline entry that hides
the full-severity finding from any reader, old or new. Pinned by A16.

**The intended cost.** A runner older than 1.12.0 reading a baseline that
1.12.0 wrote does not demote, so it sees the match at its full old severity.
1.9.x finds no positional key for it and reports it; 1.10.0 and 1.11.0 find
its `entries` record at `low` and their severity rule refuses to let a `low`
entry suppress a `critical` match. Either way an older runner reports a
demoted match at its full severity and, under its gate, blocks. That is
deliberate: a mixed fleet blocks rather than lets an older reader hide a key
it would have judged critical. The remedy is to upgrade every runner that
reads the baseline to 1.12.0.

No fingerprint changes: `fingerprintForMatch` and
`contentFingerprintForMatch` (`match-fingerprint.ts:18-22`, `:53-60`) read the
path, rule, position and value digest only.

---

## 5. Grouping

### 5.1 What "data file" means: content, not name

Grouping applies to a copy of a file when its decoded text has one of two
shapes. Neither reads the name.

- **Delimited.** The copy has at least 20 non-empty lines, and for one
  delimiter from `,`, tab, `;`, `|`, at least 90 percent of its non-empty
  lines split into the same number of fields `k`, with `k >= 2`. Fields are
  split per line with RFC 4180 quoting (a delimiter inside double quotes does
  not split; a doubled quote is a literal quote). A quoted field that spans
  lines breaks the count on the lines it spans, which only lowers the share.
  Two kinds of line never count as regular, though they stay in the share's
  denominator, because they are what source code looks like:
  - under EVERY delimiter, a line that splits into exactly two fields of
    which the last is empty (one trailing delimiter, so `x = 1;` under `;`).
    An empty last field with `k >= 3` still counts: a CSV with an empty last
    column is ordinary;
  - under the TAB delimiter only, a line whose split has an empty first
    field (indentation, so tab-indented code at any depth). Under comma,
    semicolon and pipe an empty first field is ordinary data (a sparse
    leading id or category column) and the line counts. The cost: a TSV
    whose first column is mostly empty is not called delimited and does not
    group, which costs presentation only.

  A code fixture pins the exclusions (A27), and a sparse-first-column CSV
  pins that they stop there (A29).
  When several delimiters qualify, the one with the highest share wins, ties
  in the order listed. The lines with `k` fields are the **regular lines**.
- **Long line.** A line of 65,536 characters or more. Every such line is a
  long line.

**Why content.** An extension-only trigger is forbidden by the 1.10.0 and
1.11.0 rule, and would group repeated findings in a source file named
`.csv` while missing a data file named `.txt`, `.dat` or with no extension.
The two shapes are what makes repeats in a data file noise: a regular table
where one column holds tokens, or a minified document where one key repeats.
Grouping changes no severity and no verdict (5.4), so a content property
that is occasionally wrong (a Markdown table, a generated fixture array)
costs presentation only.

### 5.2 Membership

Within one copy, matches form a group when they share:

- the rule;
- the effective severity;
- whether they are demoted (all carry a demotion record, or none does);
- the copy (`source` and, for a conflicted path, `stage`);
- the **slot**: for a delimited copy, each match lies entirely within one
  field of a regular line, and they share that field's index (the column);
  for a long-line copy, each match lies on a long line (slot `long-line`).

and there are at least `G = 5` of them **among the matches actually reported
after the baseline** (5.6). Values may repeat or differ; the group reports
how many distinct value digests it holds. A match that fits no slot, or whose
slot has fewer than five reported members, is reported on its own exactly as
today.

Severity and demotion status are part of the key so that a group's listed
locations are always representative of every member. Without them, a column
of six demoted image slices and one real `critical` key would print as one
`critical` group whose first five locations are all `low`, pointing the
reviewer away from the key. With them, the six slices form a `low` group and
the key is its own line (A3).

### 5.3 What a group carries

- the rule, the slot (delimiter and column, or `long-line`), the copy;
- `members`: the count;
- `distinct_values`: distinct `valueDigest`s among members (members of a
  rule with no value digest count as one value each);
- `severity`: the members' shared severity;
- `demoted`: whether the members carry a demotion record (all do, or none
  does);
- the first five member locations (line and column), in file order;
- `group_id` and `members_digest` (5.5).

### 5.4 Grouping, not hiding

- **Every member stays a finding.** Each is still a separate entry in JSON
  `results[].matches[]` with its own severity and fingerprints; grouping adds
  fields, it never removes an entry.
- **The exit decision is computed per member, as today.** If any member
  meets the gate the run exits 1. `blocking_matches` and `summary.secrets`
  count members. A group does not block "once": it adds all of its blocking
  members to the count, so the umbrella's reconciliation (1.4) holds without
  any change on its side.
- **A group never mixes severities.** Its members share one effective
  severity and one demotion status (5.2), so the group's severity is every
  member's, and a stronger match beside it is always its own line or its
  own group.

### 5.5 Identity

```
group_id       = sha256("vg-group-v1" NUL relpath NUL rule NUL severity NUL demoted NUL slot NUL source NUL stage)
members_digest = sha256(the members' baseline keys, sorted, joined by NUL)
```

`relpath` is the content root relative path the content fingerprint uses
(`contentRelPath`, `match-fingerprint.ts:39-42`), so moving the display root
does not move a group id (the rule in INVARIANTS, "a fingerprint never reads
the displayed path"). A member's baseline key is its content fingerprint for
a value-bearing rule, its root-relative positional fingerprint otherwise.

`group_id` names the slot: the same column of the same file keeps the same
id as rows come and go. `members_digest` changes whenever a member is added,
removed or changes value, so a consumer that wants to know "is this the group
I reviewed" compares it.

### 5.6 Baselining a group

**A group is never a baseline key.** The reader is unchanged: it looks every
match up by its own key (`applyBaseline`, `baseline.ts:295-350`), and a group
id is in its own hash domain (`vg-group-v1`), so a `group_id` pasted into
`entries` matches no member and suppresses nothing (test A15b).
`baseline --write` writes one entry per member, through its existing rules
(critical members refused without `--include-critical`, only blocking
findings, outer-tracked files only).

Groups are formed **after** the baseline, from what remains. So:

- 500 members baselined, then one new distinct token added to the same
  column: 499 or 500 are suppressed by their own entries, the new one is not;
  it is reported, alone (fewer than five remain), at its own severity, and
  blocks under the default gate;
- a group of 500 where 497 are baselined shows three single findings;
- under `--trust-base` the baseline is the base ref's, so a pull request that
  adds members cannot have them baselined.

### 5.7 SARIF: one result per member

Decided: SARIF keeps **one result per match**, exactly as today, and each
member of a group gains `properties`:
`vault-guard/group` (the `group_id`) and `vault-guard/group_size`.

Why not one result per group with related locations:

- **Dismissals.** GitHub code scanning keys an alert, and its dismissal, on
  the result's fingerprints. A group result keyed on the slot would let one
  dismissal cover every future member of that column; keyed on the member
  set, every row change would close the alert and open a new one.
- **Pull-request annotations.** A group result has one primary location. A
  new secret added at row 4012 of a group whose primary location is row 2
  would sit in an alert outside the diff, which is exactly where a reviewer
  does not look. A per-member result for row 4012 is in the diff.
- **Upgrade churn.** Every existing per-match alert would close and a group
  alert open on the first 1.12.0 upload.
- **The umbrella reads JSON** (1.4), so this choice does not affect it.

The cost: code-scanning volume for a grouped file is unchanged until the
adopter baselines or excludes it. The noise reduction this release delivers
is in the text output, in the JSON group summary, and in any reader that
uses `group_id` (open point 6).

---

## 6. Where it runs

### 6.1 One module in core

`packages/core/src/utils/data-shape.ts`, new:

- `runAround(text, offset, length)`: the run containing a match (start, end)
  or undefined when C1 fails. Run boundaries are found by ONE linear sweep
  of the copy, done lazily the first time any match passes the cheap C2
  test (alphabet characters on both sides), which records every run of
  `MIN_RUN` characters or more as a sorted interval list; each lookup is a
  binary search in that list. Scanning outward from each match instead
  would cost the run's length per match, which is quadratic on a 32 MiB run
  packed with matches. A cost test (U13) pins this.
- `encodedPayloadDemotion(text, match)`: C1 to C4; returns the record or
  undefined.
- `MEDIA_TYPE_ROWS`: the 3.3 table, frozen.
- `dataShape(text)`: the 5.1 classification (delimited with its delimiter,
  `k` and the regular lines; the long lines), computed once per copy.
- `groupSlot(shape, text, match)`: the 5.2 slot or undefined.
- Constants: `MIN_RUN = 1024`, `GROUP_MIN = 5`, `GROUP_LISTED = 5`,
  `LONG_LINE = 65536`, `DELIMITED_MIN_LINES = 20`, `DELIMITED_SHARE = 0.9`.

`binary-type.ts` gains `BARE_RUN_SIGNATURES` (the frozen two-entry list of
3.2: PNG, and JPEG with its four marker bytes) and `confirmsBareRun(head)`,
which tests only that list, with the same evidence rule as a binary
signature in `confirmsBinary`. It never iterates the full table.

### 6.2 In the scanner

`SecretMatch` (`types.ts:1-31`) gains two optional fields:

- `demotion?: { from, reason, family, format, media_type?, run_length }`;
- `groupSlot?: { basis: 'column', delimiter, column } | { basis: 'long-line' }`.

`scanContent` sets both after `applyInlineTestSeverity`. `dataShape` runs
only when the copy produced at least `GROUP_MIN` matches of one rule, so a
clean file pays nothing. The demotion check runs only for a match whose
neighbouring characters are both in the alphabet (the cheap form of C2),
which is rare outside payloads.

### 6.3 Forming groups

`formGroups(results)` in `packages/core/src/scan-output.ts`, called by
`formatJson`, `formatSarif`, `displayScanResults`
(`packages/cli/src/utils/scan-utils.ts:1207-1251`) and the MCP tools, always
on the post-baseline results (`scan.ts:651`), keyed by file, source, stage,
rule and slot. It is a pure function of the results, so every surface forms
the same groups.

### 6.4 What does not change

The file set, the binary skip, the size limit, the budget and its re-time,
`dropHeaderOnlyTwins` (`content-source.ts:649-676`), the baseline reader
rules, the inline-directive tally, the exit-code rules. The baseline writer
changes in two lines only (4.5).

### 6.5 Merging copies keeps the higher severity

`mergeCopies` (`content-source.ts:612-641`) reports one finding per
`(rule, valueDigest)` across the blob and the disk copy, keyed by
`valueKey` (`:600`), and keeps the blob's copy. Until now the two copies of
one value always had the same severity. With a content demotion they can
differ: the same key bytes can sit inside a confirmed PNG payload in the
blob and inside a payload whose header an unstaged edit replaced on disk.
The merge therefore keeps, of two matches with the same key, the one with
the higher severity; a tie keeps the blob's, as today. So a value that is
`critical` in any copy is reported `critical`, with that copy's `source`.
Pinned by U14.

---

## 7. Trust boundary and pull-request mode

- **No control value comes from the scanned tree.** `MIN_RUN`, the alphabet,
  the media-type table, the binary table, `GROUP_MIN`, `LONG_LINE`, the
  delimited thresholds and the reasons are constants in the published
  package. None is a config key, flag or environment variable, and none is
  read from any file in the tree. A head `.vault-guard.json` that tried to
  add one is an unknown key, and under `--trust-base` a proposal either way.
- **Nothing reads a control from the head under `--trust-base`.** The base
  config's `severity_overrides` and `fail_on` apply as today; the demotion
  runs after the override, so a base override that raises `gcp-api-key` is
  still demoted inside a confirmed payload, and the base `fail_on` is the
  floor (4.3).
- **What the rule reads is content.** The bytes around a match are the bytes
  being judged: the HEAD blob in pull-request mode, the index blob in a plain
  scan and `--staged`. A pull request controls content by definition; 2.3 is
  why a content change buys the author nothing over encoding.
- **Attributes cannot steer it.** The blob is read without attributes (1.10.0
  design, section 2); a head `.gitattributes` can only add a disk read, whose
  matches are judged on their own bytes.
- **The baseline** is the base ref's under `--trust-base` (INVARIANTS, "A
  pull-request run never takes its baseline from the head"); groups are
  formed after it, and a group id is never a key (5.6).

---

## 8. Output surfaces

### 8.1 Text

Each new element is printed only when it applies, so a run with no demotion
and no group prints byte for byte what 1.11.0 prints (test U9).

A demoted finding, on its usual line, with the reason appended:

```
  <icon> assets/logo.svg:1:403118  low  gcp-api-key  <masked>  (demoted from critical: inside an 812004-character data:image/png;base64 payload that decodes to a png image)
```

A group, as one line in place of its members:

```
  <icon> data/users.csv:2:41  high  jwt-token  <masked>  and 499 more in column 7 of this delimited file (500 matches, 500 distinct values; lines 2, 3, 4, 5, 6, ...)
```

For a long-line group the phrase is `on lines over 65536 characters`. The
masked value is the first member's.

The headline keeps counting matches, and says how many are grouped when any
are: `Found 512 secrets (500 of them in 1 group)`. After the list, at most
two notes:

```
3 finding(s) were demoted to low because they sit inside encoded media; --fail-on low blocks on them.
Grouped findings show their first 5 lines; --format json lists every match.
```

### 8.2 JSON

Per match (only when it applies):

| Field | Meaning |
|---|---|
| `demotion` | The 4.2 record. `severity` is already the demoted one. |
| `group_id` | Present when the match is a member of a formed group. |

Per file entry, `results[].groups` (only when the file has a group):
`[{ group_id, rule, basis, delimiter?, column?, source?, stage?, members,
distinct_values, severity, demoted, first: [{ line, column }],
members_digest }]`.

`run`, every field always present, zero included (the existing rule for
counts):

| Field | Meaning |
|---|---|
| `demoted_matches` | Reported matches carrying a demotion record. |
| `demoted_by_reason` | `{ "data-uri-binary-payload": n, "base64-binary-run": n }`, both keys present, summing to `demoted_matches`. |
| `match_groups` | Groups formed. |
| `grouped_matches` | Matches that are members of a group. |

Unchanged: `summary`, `results[].matches[]` entries and their order,
`fingerprint`, `content_fingerprint`, `fail_on`, `blocking_matches`.

### 8.3 SARIF

One result per match (5.7). A demoted result's `level` follows its
effective severity (`note` for `low`, `scan-output.ts:498`) and its
`properties` gain `vault-guard/demoted_from` and `vault-guard/demotion_reason`;
a member gains `vault-guard/group` and `vault-guard/group_size`. The run
properties carry the four `run` counts of 8.2. `partialFingerprints` are
unchanged. A test asserts SARIF and JSON carry equal counts.

### 8.4 MCP

`scan_text`, `scan_file` and `scan_workspace` get the demotion through
`scanContent`, and their embedded JSON and SARIF documents get every field of
8.2 and 8.3 through the shared formatters. Their `summary` objects
(`packages/mcp/src/server.ts:233`, `:296`, `:347`) gain `demoted_matches` and
`match_groups`; `total_matches` keeps counting matches.

### 8.5 VS Code extension

It scans buffers through `scanContent`, so a demoted match arrives at `low`
and is shown at the extension's existing level for `low`. The diagnostic
message gains the reason in the same words as the text line.

### 8.6 The umbrella's text line

Unchanged in form: `vault-guard: findings (N, M blocking)`. `N` is still the
number of matches; `M` drops by the demoted matches whose earlier severity met
the gate. The umbrella's reconciliation holds (1.4, 5.4). Reading
`results[].groups` to collapse its listing, and carrying `demotion` into a
finding's `details`, are the umbrella's own follow-up items (open point 13);
neither is needed for correctness, because the umbrella maps only fields it
already reads.

---

## 9. Real-artifact validation

Part of the implementation PR, not a follow-up. Recorded in
`bench/real-repos/2026-10-NN-1.12.0.json` (the date of the run), with the
method added to `bench/real-repos/README.md` and `run.cjs` extended under a
`--design-2026-10-17-data-files` switch rather than copied.

### 9.1 Repositories

The four from the 1.10.0 and 1.11.0 runs (facebook/react, urllib3/urllib3,
gitleaks/gitleaks, Yelp/detect-secrets) at the commits the 1.11.0 run used,
to show nothing moved where there is little encoded media; plus:

- **jakevdp/PythonDataScienceHandbook**: notebooks whose committed outputs
  hold `image/png` base64 strings with no `data:` prefix (the bare-run case),
  in volume.
- **fastai/fastbook**: a second notebook corpus of the same kind, so the
  bare-run count is not one repository's accident.

  That either repository holds bare PNG or JPEG runs of 1024 characters or
  more in volume is this author's expectation, not a measurement. Fallback
  rule: if a repository's `R_media` for bare runs is under 10 MB at its
  clone head, it is replaced by another public notebook repository found by
  code search (query recorded) that clears 10 MB, and the record names both.
- **fivethirtyeight/data**: hundreds of CSV files in varied dialects
  (quoted fields, embedded commas, semicolons), to measure what the
  delimited classifier calls a data file on real tables, and its cost.
- **Two chosen by search**, because this author has not verified a public
  repository for either: one public repository with a committed CSV holding a
  column of JWT-shaped values, and one with an SVG, HTML or CSS file carrying
  a `data:` payload of 100 KB or more. The implementer finds them with GitHub
  code search and records the query, the repository, the file and the clone
  head. If none is found for a shape, the record says so and that shape is
  covered by the synthetic set (9.4) and by the operator's dogfood counts
  (9.5) only.

Before running, the implementer records per repository, from the clone
head: tracked files classified delimited or long-line by `dataShape`, and the
total characters of runs of 1024 or more that decode to binary media
(`R_media`), split by bare run and `data:` payload. Clones are at depth 1,
`origin` removed, `clone_head` recorded.

### 9.2 Builds and commands

Published 1.11.0 and the implementation branch. Per build and repository,
three runs each, interleaved, median wall time: `scan . --format json` and
`scan . --trust-base <clone_head> --format json` on the existing
`vg-bench` branch. Recorded: the run counts, `demoted_matches`,
`demoted_by_reason`, `match_groups`, `grouped_matches`, and every finding as
rule, file, line, offset, severity, source, fingerprints, demotion record and
group id (never the value).

### 9.3 Expected, as formulas

Per repository, let `F11` be the 1.11.0 finding list and `F12` the branch's,
each keyed by (rule, file, line, offset, source, stage, fingerprint,
content fingerprint), severity left out. Let `D` be the branch's findings with
a demotion record, and `sev11(f)` a finding's severity in 1.11.0.

- `F12 = F11 + Rst`, as multisets, after the source swaps of `Swp` are
  applied to `F11`. Demotion and grouping add and remove nothing; the two
  sanctioned differences come from the rules of 4.4 and 6.5, and the branch
  logs each one in the record (a bench-only log, not an output field):
  - `Rst`: matches restored because the dedupe winner that displaced them
    was demoted (4.4, U12). 1.11.0 never reported them. Each is logged with
    the demoted winner it was displaced by, and must not itself be
    demotable.
  - `Swp`: findings whose reported copy moved from the blob to the disk copy
    (or between conflict stages) because the merge now keeps the
    higher-severity copy (6.5, U14). Same rule, value and position; only
    `source` (and `stage`) differ, so they count as the same finding once
    the swap is applied. Each is logged with both copies' severities.
  Clean depth-1 clones have no disk edits and no conflicts, so `Swp` is
  expected empty on every public repository; `Rst` is expected empty or
  tiny.
- For every `f` outside `D`: severity unchanged.
- For every `f` in `D`: `sev12(f) = low`, `sev11(f)` is not `low`, and
  `demotion.from = sev11(f)` (a demotable rule is never path-downgraded,
  4.2, and a match already at `low` is never demoted).
- `blocking_matches(branch) = blocking_matches(1.11.0) - |{ f in D :
  sev11(f) meets medium }|` under the default gate.
- `summary.secrets`, `files_scanned` and every other 1.11.0 run count:
  unchanged.
- `demoted_matches = |D|`; `demoted_by_reason` sums to it.
- `grouped_matches <= summary.secrets`; every group has at least five
  members, all on regular lines of a delimited file or on long lines.
- For `gcp-api-key`, the coincidence rate of 1.2 predicts
  `E = 1.96e-8 * R_media(standard alphabet)` demoted hits. The record states
  `E` beside `|D_gcp|`. `|D_gcp| > E + 3 * sqrt(E) + 3` is investigated before
  release: it means something other than coincidence is being demoted.
- On the four 1.10.0 repositories, `D` and the groups are expected empty, or
  every entry is explained in the record.

**An empty `D` is not evidence that the demotion works.** `E` is small: 100
MB of standard-alphabet media predicts about two `gcp-api-key` hits, so a
public run can show `|D| = 0` with the rule entirely broken. What the public
run proves is the other direction, that nothing outside the predicted shape
moved (the multiset, severity and count formulas above). That the rule
demotes what it should is proved by the synthetic fixtures of section 10
and by the operator's dogfood counts (9.5).

`dataShape` and C4 are the branch's own code, so the formulas above prove
consistency, not correctness. The independent evidence is
`demotion_explanations`: for every entry of `D` (or 20 chosen at random when
there are more), the run decoded outside vault-guard (`base64 -d`, then
`file -`) and what it is, read by hand; and for every group, a hand check
that the file is a table or a minified document. Added after reading the
files, as the 1.11.0 `mismatch_explanations` were.

### 9.4 Release blockers

- A finding added or lost: `F12` differs from `F11 + Rst` after the `Swp`
  swaps (9.3). A restoration or a swap that is in the log, with its cause,
  is not a regression; one that is not in the log is.
- A severity change outside `D`.
- An entry of `D` whose hand-decoded run is not the media its record names.
- The planted-secret corpus: `node bench/run.cjs --assert` with precision and
  recall unchanged from 1.11.0, AND a new per-fixture check that every
  positively labelled fixture keeps the severity 1.11.0 gave it. No real
  secret in that set may lose its blocking severity.
- Two planted cases, each with a key built at run time, in plain,
  `--trust-base` and `--staged`, and through MCP `scan_workspace`, must be
  found at full severity, not demoted and not grouped:
  - **P1**: one `gcp-api-key` in one cell of a 1000-row, 8-column CSV whose
    other columns hold distinct 40-character base64 tokens and one column of
    JWT-shaped tokens (which do group);
  - **P2**: a key inside a `data:` URI whose payload decodes to text: once as
    `data:text/html,<script>...key...</script>` in an HTML file, and once as
    `data:application/json;base64,` followed by a run of over 1024
    characters that decodes to JSON text, with the key pasted raw in its
    middle.
- Plain-scan wall time on any of the four 1.10.0 repositories or on
  fivethirtyeight/data over 1.10 times 1.11.0's, median of three, on a quiet
  machine.

### 9.5 The private dogfood shapes

Run by the operator and recorded as counts only, with no names or paths.
Expected: the repository with the 800 KB SVG reports the `AIza` hit at `low`
with `demotion.reason = data-uri-binary-payload`, and no longer blocks on it
under the default gate; each scraped-CSV repository reports one group per
token column (24 to 48 members in all), still blocking under the default
gate, with `blocking_matches` equal to 1.11.0's.

---

## 10. Test plan

Fixtures are temporary git repositories with real commits, driven through
`scanCommand` in-process except where a row says otherwise. Keys are built at
run time, never the documentation example key. Encoded media is synthetic:
the minimal valid header for the format followed by seeded pseudo-random
bytes, base64-encoded in the test. Every fixture whose subject might be
demoted or grouped also holds a clean `src/ok.ts`, so no row passes through
"nothing was scanned". Every row names the mutation it must kill; the
implementer applies each mutation once and records the red run in the
implementation PR.

### 10.1 Adversarial fixtures

| id | Fixture | Before (1.11.0) | After | Mutation killed |
|---|---|---|---|---|
| A1 | P1: one `gcp-api-key` in one CSV cell, 1000 rows. Plain, `--trust-base`, `--staged`. | exit 1, `critical` | exit 1, `critical`, no `demotion`, no `group_id` | Demotion applied to delimited files (A1a, red: `low`); `GROUP_MIN` set to 1 (A1b, red: a `group_id` on a single match). |
| A2 | A CSV column of 500 JWT-shaped tokens with distinct values. Default gate; `--fail-on critical`. | exit 1, 500 lines, `blocking_matches` 500 | default: exit 1, one text line, `match_groups` 1, `grouped_matches` 500, `blocking_matches` 500, 500 entries in `results[].matches[]`; `--fail-on critical`: exit 0 | Group counted once in `blocking_matches` (A2a, red: 1); members removed from `matches[]` (A2b, red: 1 entry); group not formed (A2c, red: 500 text lines). |
| A3 | A CSV column of 6 cells, each a long base64 PNG with an `AIza` run inside (demoted), plus 1 cell, placed after them, holding a plain `gcp-api-key` (critical). | 7 criticals | two text lines in the same column: one group of 6 at `low`, `demoted: true`, listing the six slices; and the critical key as its own single line with no `group_id`; exit 1 | Severity or demotion status left out of the group key (red: one group of 7 whose five listed locations are all demoted slices). |
| A4 | The F17 shape: a one-line SVG of 800 KB whose `data:image/png;base64,` payload holds an `AIza` run in its middle. Default gate; `--fail-on low`. | exit 1, `critical` | default: exit 0, finding `low`, `demotion` with `from: critical`, `reason: data-uri-binary-payload`, `media_type: image/png`; `--fail-on low`: exit 1 | Demotion implemented as a skip (A4a, red: no finding under `--fail-on low`); record missing (A4b); `blocking_matches` computed on the earlier severity (A4c, red: exit 1 under default). |
| A5 | P2a: `data:text/html,<script>var k='<key>'</script>` in an HTML file. | `critical` | `critical`, no demotion | Any `data:` URI demoted without C4 (red). |
| A6 | P2b: `data:application/json;base64,` with a 2048-character run that decodes to JSON text, the key pasted raw in its middle. | `critical` | `critical`, no demotion | C4 decided by the base64 shape alone (red). |
| A7 | `data:image/png;base64,` declared, payload of 2048 characters that decodes to ASCII text, the key in its middle. | `critical` | `critical` | Declared media type trusted without the decoded signature (red). |
| A8 | `data:image/svg+xml;base64,` payload of 4096 characters (decodes to SVG text), key in its middle. | `critical` | `critical` | `image/svg+xml` mapped to any row, or `image/*` accepted by prefix (red). |
| A9 | Real PNG payload, the key appended flush against the closing quote; and the key flush against `==` padding. | `critical` | `critical` both | C2 removed (red on both). |
| A10 | Notebook-shaped JSON: `"image/png": "<base64 PNG of 50 KB with an AIza run inside>"`. File named `.json`, and again named `.txt`. | `critical` | `low`, `reason: base64-binary-run`, `format: .png`, both names | Bare runs not handled (A10a, red: `critical`); demotion keyed on the extension (A10b, red on `.txt`). |
| A11 | A bare 8 KB run of seeded random base64 with an `AIza` run inside. The seed is chosen and asserted so the decoded head begins with none of the binary table's signatures, so the row does not depend on luck. | `critical` | `critical` | Entropy or length used in place of C4 (red: `low`). |
| A11b | Bare runs of 4 KB, `AIza` inside, whose decoded heads begin with an MP3 frame sync (`FF FB`), an AAC header (`FF F1`, and again `FF F9`) and a gzip header (`1F 8B`), each followed by seeded random bytes. | `critical` | `critical`, each | The bare-run check iterating the full binary table instead of `BARE_RUN_SIGNATURES` (red on each: these two-byte signatures match about 9 in 65536 random heads). |
| A12 | A bare run whose decoded head is `GIF89a` or `%PDF-` followed by binary bytes, `AIza` inside. | `critical` | `critical` | Printable-signature rows accepted for bare runs (red). The same payloads with `data:image/gif;base64,` and `data:application/pdf;base64,` ARE demoted (A12b). |
| A13 | Run length boundary: a PNG payload of exactly 1023 characters and of exactly 1024, `AIza` in the middle of each. | `critical` both | 1023: `critical`; 1024: `low` | `MIN_RUN` off by one, or removed (red on one side). |
| A14 | A run mixing `+` and `_`, PNG-like head, `AIza` inside. | `critical` | `critical` | Mixed-alphabet runs decoded (red). |
| A15 | Baseline a group: a CSV column of 20 JWTs, `baseline --write`; then commit a 21st distinct JWT in the same column. Plain and `--trust-base` (base holds the 20-entry baseline). | n/a | `baseline --write` writes 20 entries; the next run: exit 1, one match, not grouped, `baseline_suppressed` 20 | A group key written or honoured by the baseline (red: exit 0). |
| A15b | A15 with the group's `group_id` hand-added to `entries` as a fingerprint and no member entries. | n/a | exit 1, `baseline_suppressed` 0 | A group id accepted by the reader (red). |
| A16 | A demoted `gcp-api-key` (from `critical`). (a) `baseline --write --fail-on low` without `--include-critical`. (b) The same with `--include-critical`; then the payload's header is replaced with random bytes so C4 fails, and the next run is read three ways: by the 1.12.0 reader with `entries`; by the legacy reader on the same file with `entries` removed (`applyBaseline` with `entries` null, the 1.9.x path); and by a subprocess run of the published 1.9.1 CLI on that tree, where it is installed in CI. | n/a | (a) refused as critical, nothing written; (b) one `entries` record at `low`, the match's positional key ABSENT from `fingerprints`; each of the three later reads: exit 1, `critical`, not suppressed | Refusal reading the demoted severity (A16a, red: written); demoted match written into the positional list (A16b, red: the legacy and 1.9.1 reads suppress it); entries severity rule bypassed (A16c). |
| A17 | `--trust-base`: head adds a `.vault-guard.json` with `severity_overrides: { "gcp-api-key": "critical" }`, an unknown `content_demotion: false` key, and a `.gitattributes` line `*.svg -text`, on top of A4. | n/a | same demotion as A4, the config and attributes proposals listed, exit 0 under the base's default gate | Any head control read by the demotion or grouping (red). |
| A18 | A2's CSV content saved as `data.txt` and as `data` (no extension); a source file `rows.csv` whose lines vary in field count, holding 6 JWTs. | n/a | `data.txt` and `data` grouped; `rows.csv` not grouped (6 single lines) | Extension used as the data-file trigger (red on either). |
| A19 | A minified JSON document of one 200 KB line holding 30 JWT-shaped tokens. | 30 findings | one group, `basis: long-line`, 30 members | Long-line basis missing (red). |
| A20 | Quoted CSV: fields with embedded commas and doubled quotes, 30 rows, JWTs in column 3. | n/a | one group, `column` 3 | Naive split on the delimiter (red: wrong column or no group). |
| A21 | A4's tree with a config `severity_overrides: { "gcp-api-key": "low" }`; and A4's tree with the SVG moved under `docs/`. | override: `low`; `docs/`: `critical` | override: `low`, no `demotion` record, `demoted_matches` 0; `docs/`: `low` with the record, as in A4 | A no-op demotion recorded and counted (red: `demoted_matches` 1 on the override tree); demotion keyed on the path (red if the `docs/` copy differs from A4). |
| A22 | Every mode on A4 and A10: plain, `--trust-base`, `--staged`, a named target, MCP `scan_workspace`, `scan_file`, `scan_text` (content only). | n/a | same severity and record in each | Demotion placed in a caller instead of `scanContent` (red on the MCP and named-target rows). |
| A23 | Re-time: the clock seam returns 6000 then 100 ms on A4's file. | n/a | `scan_budget_retimed` 1, same matches and records as A4 | Demotion depending on anything outside the text (red: `sameMatches` fails, exit 2). |
| A24 | An inline `vault-guard: ignore-line` on a payload line of A4. | `inline_suppressed` 1 | `inline_suppressed` 1, `inline_suppressed_critical_vendor` 1 (the rule's own severity, as today) | Tally read after demotion (red: critical vendor count 0). |
| A26 | `data:image/png;base64,` whose payload is a real JPEG (header `FF D8 FF E0` and seeded bytes, 4 KB), `AIza` inside. | `critical` | `critical` | Any binary signature accepted under a declared type, instead of that type's row (red: `low`). |
| A27 | Code that looks delimited: a 100-line TypeScript file where every line ends in one `;`; a 100-line tab-indented Makefile; each holding 6 JWT-shaped tokens. | 6 findings each | 6 single findings each, no group | Empty-edge-field lines counted as regular (red: one group). |
| A29 | A 30-row comma CSV whose first column is empty on 25 rows (`,cat,eyJ...,x`), JWT-shaped tokens in column 3 (index 2) on every row. | 30 findings | one group of 30, `column` 2 | Empty-first-field exclusion applied under the comma delimiter (red: under 90 percent regular, no group). |
| A28 | `data:` URIs with parameters: `data:image/png;name=logo.png;base64,` and `data:image/png;charset=binary;base64,` with a PNG payload, `AIza` inside; and `DATA:IMAGE/PNG;BASE64,`. | `critical` | `low` with `media_type: image/png`, each | Parameters or case not handled in the `data:` prefix parser (red: `critical`). |

### 10.2 Unit and contract tests

| id | Test | Mutation killed |
|---|---|---|
| U1 | `runAround` on boundaries: each non-alphabet character listed in 3.1 ends a run; `=` ends a run; a match containing `.` returns undefined. | `=` or `.` in the alphabet. |
| U2 | Head decode: run lengths 0 to 7, 5463, 5464, 5465 decode to `floor(min(n, 5464) / 4) * 3` bytes, truncated to 4096. | Off-by-one in the head window. |
| U3 | `MEDIA_TYPE_ROWS`: every listed type maps to its row; `image/svg+xml`, `text/plain`, `application/json`, `application/octet-stream` and an empty type do not; types are matched lowercased with parameters ignored (`IMAGE/PNG;name=a`). | A type missing or added; case-sensitive match. |
| U4 | `confirmsBareRun`: the PNG header and each of `FF D8 FF E0`, `E1`, `DB`, `EE` confirm; `FF D8 FF C0` does not; the minimal header of every other binary-table row does not; `BARE_RUN_SIGNATURES` has exactly two entries and is frozen. | A row added to the list, or the JPEG marker byte dropped (red on `FF D8 FF C0`). |
| U5 | `dataShape`: 19 versus 20 lines; 89 versus 90 percent; `k = 1` never delimited; tab and pipe tables; a Markdown table; a 65,535 versus 65,536 character line. | Each threshold off by one. |
| U6 | `group_id` and `members_digest` formulas against a fixed vector; `group_id` equal across two display roots (`scan .` from the root and from a subdirectory). | Display path used in the id. |
| U7 | Umbrella contract: for A2, A3 and A4, `blocking_matches` equals the number of `results[].matches[]` entries whose `severity` meets `run.fail_on`. | Any change that makes the per-match severities disagree with the gate. |
| U8 | JSON and SARIF: the four run fields present at zero on a tree with no demotion and no group; SARIF run properties equal JSON; SARIF result count equals JSON match count on A2; `partialFingerprints` identical to 1.11.0 on A2 and A4. | A field emitted only when non-zero; one SARIF result per group; fingerprints moved. |
| U9 | Text: a clean run and a run with ordinary findings print byte-identical to 1.11.0 on the existing pinned fixtures; A2 prints one line naming `column 7`, `500 matches` and five line numbers; A4 prints the reason. | New lines printed when nothing applies. |
| U10 | MCP summaries carry `demoted_matches` and `match_groups`; `total_matches` counts matches on A2. | `total_matches` counting groups. |
| U11 | Cost: a 30 MB delimited CSV with no matches does not run `dataShape` (spy), and A2's CSV classification stays under 5 percent of its scan time on the CI machine. | `dataShape` run on every copy. |
| U12 | Dedupe then demote: `Bearer ` followed by a 2 KB PNG payload, built so the `bearer-token` match covers an `AIza` slice that dedupe would prefer (`critical` over `high`). | The restoring step removed (red: only the demoted `low` slice is reported, the `high` bearer match is lost); a displaced match that would itself be demoted restored (red: a second `low` match on the same span). |
| U13 | `runAround` cost: one PNG payload run of at least 8 MiB packed with 1,000 `AIza` slices, and the same run with 10,000. The demotion step over 10,000 slices takes at most 20 times its time over 1,000 (linear is 10 times, quadratic 100), and the sweep runs once per copy (spy). | Outward scan per match (red: quadratic, the ratio explodes); sweep repeated per match (red on the spy). |
| U14 | `mergeCopies`: the same key bytes demoted in the blob (confirmed payload) and not demoted on disk (header replaced in an unstaged edit), and the reverse. Both cases report one finding, `critical`, from the copy that holds it at `critical` (`source: worktree`, then `source: index`); with equal severities the blob's copy is kept, as today. | Blob copy kept regardless of severity (red: the `critical` disk copy reported as `low`). |

---

## 11. Release shape

### 11.1 CHANGELOG draft for 1.12.0

```
## [1.12.0] - YYYY-MM-DD

**Minor.** A key-shaped match that is a slice of an embedded image, font or
recording is reported at low with the reason, instead of at its rule's
severity, and many matches of one rule in one column of a data file are
shown as one grouped finding. Under the default gate (medium) and under
--fail-on high or critical, a finding demoted this way no longer blocks. No
finding is removed, no fingerprint changes, and --fail-on low still blocks
on every demoted finding.

### Changed

- A match whose every character is base64, that sits strictly inside a run
  of at least 1024 base64 characters, and whose run decodes to the header of
  a known binary format is lowered to low. For a data: URI the decoded bytes
  must be the format its declared media type names (image/png, font/woff2,
  audio/mpeg and the others in the design); for a run with no data: prefix
  they must be a PNG or JPEG header, and nothing else. Until now such a
  match was reported at its rule's severity: one coincidental AIza run
  inside an embedded PNG was a critical gcp-api-key finding. What can newly
  stop blocking: those findings, under --fail-on medium (the default), high
  and critical. Under --fail-on low they block as before. A key that stands
  alone, is delimited on either side, sits at either end of a payload, or
  sits in a payload that decodes to text or to random bytes keeps its full
  severity. The decision reads only the bytes around the match, never a file
  name or a path, and no config key, flag or file in the tree changes it.
  The boundary: a key deliberately spliced inside a crafted image payload is
  reported at low, with its reason, rather than at its rule's severity.
- In a file whose content is a delimited table (at least 20 lines, 90
  percent of them with the same number of fields) or on lines of 64 Ki
  characters or more, five or more matches of one rule in the same column
  (or on such lines) are shown as one finding in the text output, with the
  count, the number of distinct values and the first five lines. Every match
  is still reported in JSON and SARIF, still counts toward
  run.blocking_matches, and still decides the exit code. A group's members
  share one severity and are either all demoted or none, so a stronger
  match in the same column is always shown on its own line. The baseline
  still works per match: a new value in a baselined column is reported.
- baseline --write treats a demoted match by its severity before demotion
  when deciding whether --include-critical is needed, and leaves demoted
  matches out of the top-level fingerprints list that 1.9.x runners read,
  so an older runner can never suppress the full-severity finding. The
  intended cost: a runner older than 1.12.0 (1.9.x through that list, 1.10
  and 1.11 through their baseline severity rule) reports a demoted match at
  its full old severity and blocks on it. Upgrade every runner that reads
  the baseline.

### Added

- JSON: a demotion record on each demoted match (from, reason, family,
  format, media_type, run_length); group_id on each grouped match;
  results[].groups; and run.demoted_matches, run.demoted_by_reason,
  run.match_groups and run.grouped_matches, always present. The same counts
  in SARIF run properties, and the demotion and group as result properties.
- MCP: demoted_matches and match_groups in the tool summaries.

Unchanged: summary.secrets, run.blocking_matches as a count of matches,
every fingerprint, the baseline format and the reader's rules, the exit
codes, the SARIF result count.
```

### 11.2 README wording

After the paragraph that ends "gate on `blocking_matches`, not
`summary.secrets`" (`README.md:280-294`), add:

```
One more downgrade is made on content rather than on the path. A match
that is a slice of an embedded image, font or recording (it sits strictly
inside a base64 run of at least 1024 characters, and that run decodes to
the header of a binary format: for a data: URI, the format the URI
declares; otherwise a PNG or JPEG header) is reported at low with the
reason beside it. This is the one
place a vendor-anchored rule is lowered, and only because the bytes show
the match is not a key: a key in a CSV cell, in a plaintext data: URI, at
the end of a payload, or in a payload that decodes to text keeps its full
severity. --fail-on low blocks on these too.

Many matches of one rule in one column of a delimited data file, or on very
long lines, are printed as one grouped line with a count. They are still
separate findings in JSON and SARIF, each counts toward blocking_matches,
and a baseline accepts them one by one, so a new value in the same column
is reported on its own.
```

The "Scripting & CI" section gains the four `run` fields in its list of
always-present counts. The implementer greps `README.md`, `docs/RULES.md`,
`docs/MCP.md`, `docs/GITHUB_ACTION.md` and `docs/PRODUCT_SCOPE.md` for
"downgrad", "severity" and "blocking_matches" and updates every hit in the
same PR.

### 11.3 THREAT_MODEL

A table row under the CLI trust boundaries:

```
| File contents (encoded media) | A demotion as a hiding place: a key planted inside a fake image payload to be lowered | A demotion needs every character of the match in the base64 alphabet, the match strictly inside a run of at least 1024 characters, and the run decoding to a binary format header (the declared one for a data: URI, otherwise PNG or JPEG only). It lowers to low, never removes, records the reason, and --fail-on low blocks on it. Nothing in the tree configures it. |
```

And a paragraph after "What the binary skip guarantees, and its boundary":

```
#### What the content demotion guarantees, and its boundary

A finding is lowered only on the bytes around it, never on a file name, a
path or a value from the scanned tree, and it is lowered, never removed. A
key that stands alone or is delimited keeps its severity wherever it sits.
The boundary: an author who builds a fake binary header around a key inside
a long base64 run gets that key reported at low instead of at its rule's
severity. That is a deliberate change to the content, the same class as
base64-encoding the key, which hides it from every pattern scanner
completely and costs less; the demoted finding is still reported with its
reason and still blocks under --fail-on low. Grouping changes no severity
and no verdict; accepting a group into the baseline accepts each member,
and a reviewer cannot tell a real member from a decoy by its shape.
Design: docs/design/2026-10-17-data-file-false-positives.md, section 2.
```

---

## 12. `docs/INVARIANTS.md`

### 12.1 Appended

```
## A content demotion lowers a finding, never removes it, and says why

The rule: a match is lowered to low only when every character of it is in
the base64 alphabet (A-Z, a-z, 0-9, +, /, -, _; not =), it sits strictly
inside a run of such characters at least 1024 long (at least one run
character on each side), and the run's first 4096 decoded bytes confirm a
binary format: for a data: URI, the row its declared media type maps to in
MEDIA_TYPE_ROWS, through confirmsBinary; for a run with no data: prefix, one
of the two headers in BARE_RUN_SIGNATURES (PNG's 8 bytes, or JPEG's FF D8 FF
with an E0, E1, DB or EE marker), never another row. The check is on the
full match, and a match already at low is not demoted and carries no
record. The match keeps every fingerprint and carries a demotion record
(from, reason, family, format, media_type, run_length). The gate is applied
to the demoted severity: --fail-on low blocks on it, medium, high and
critical do not. The step runs in SecretScanner.scanContent after the
in-file test step, so every caller gets it and dedupe still ranks declared
severities. Nothing reads a file name, a path, a config key, a flag, an
environment variable or a file in the tree; the thresholds and tables are
constants. A displaced overlapping match that would not itself be demoted
is restored when the dedupe winner is demoted, and mergeCopies keeps the
higher-severity copy of a value. A demotion cannot be laundered through the
baseline: an entries record written at low never suppresses the same match
at a higher severity; baseline --write leaves demoted matches out of the
legacy top-level fingerprints list, which has no severity rule; and its
--include-critical refusal reads demotion.from.

Boundary: a key planted inside a crafted binary payload is reported at low.
That is a deliberate content change, the same class as encoding the key,
which no pattern scanner detects.

Enforced by: packages/core/src/utils/data-shape.ts and the call in
scanContent; BARE_RUN_SIGNATURES and confirmsBareRun in binary-type.ts;
the two writer lines in packages/cli/src/commands/baseline.ts. Tests: the
A1 to A14 (with A11b), A16, A17, A21 to A24, A26 and A28 fixtures and U4,
U12 to U14 of the 2026-10-17 data-file design, by their final test titles.
```

```
## Grouping is presentation: every member is a finding

The rule: five or more reported matches of one rule in one copy, in the same
column of the regular lines of a delimited copy or on lines of 65536
characters or more, that share one effective severity and one demotion
status, are shown as one group. The data-file shape is decided on content
only; a line with exactly two fields and an empty last one is never
regular, and under the tab delimiter only, neither is a line with an empty
first field. Every member stays an entry in JSON
results[].matches[] and a SARIF result, counts toward run.blocking_matches
and summary.secrets, and decides the exit code as before; a group never
mixes severities, so its listed locations stand for every member. Groups
are formed after the baseline, from what it left.
A group id is never a baseline key: the reader looks up each match by its
own key, and baseline --write writes one entry per member.

Enforced by: formGroups in packages/core/src/scan-output.ts, used by every
formatter and by displayScanResults; applyBaseline unchanged. Tests: A2, A3,
A15, A15b, A18 to A20, A27, A29, U7 and U8 of the 2026-10-17 data-file design, by
their final test titles.
```

The implementer replaces the test sentences with the real test titles once
they exist, so the citation check in `pnpm lint` can verify them.

### 12.2 Amended

"Vendor-anchored rules are not downgraded in docs or markdown" gains one
sentence after its rule paragraph: "This is a rule about path context. The
one content step that lowers a vendor-anchored rule is the encoded-payload
demotion (see 'A content demotion lowers a finding, never removes it, and
says why'), which reads only the bytes around the match and never the
path."

---

## 13. Open points

Each has a recommended default; the implementer proceeds on the default
unless the operator rules otherwise.

1. **Demote to `low`, not a new level and not `medium`.** Default: `low`
   (4.1). `medium` keeps F17 blocking by default; a new level is a breaking
   change for every consumer of the severity union, the umbrella included.
2. **Bare runs: PNG and JPEG only.** Ruled in review: a frozen named list
   of PNG's 8-byte header and JPEG's `FF D8 FF` plus a marker byte (3.2),
   because the two-byte signatures in the full table match random heads
   about once in 7300 runs. Every other format is demoted only inside a
   `data:` URI that declares it. Widening the list needs a signature of at
   least four bytes and a 9.1-style measurement.
3. **No whole-payload validity check.** Default: none. It raises the cost of
   2.3's abuse slightly, is still satisfiable, and costs a full decode per
   demoted match.
4. **Decoding text-typed base64 `data:` payloads and scanning the decoded
   text.** That would find keys that are invisible today. Default: not in
   1.12.0; raise as its own item, since it adds findings that can turn green
   runs red and needs its own real-repository run and its own offset
   mapping.
5. **An opt-out key** (a base-side `content_demotion: false`). Default: none
   in 1.12.0; `--fail-on low` is the existing strict setting. If one is
   added later it must be read only from the base ref under `--trust-base`,
   and may only make the scan stricter.
6. **SARIF one result per member** (5.7). Default: keep. Revisit only with a
   design that keeps per-member dismissal and puts a new member in the diff.
7. **Thresholds**: `MIN_RUN` 1024, `GROUP_MIN` 5, five listed lines,
   `LONG_LINE` 65,536, 20 lines and 90 percent for a delimited copy.
   Default: as stated; the 9.1 run records how many files each threshold
   catches so a later change has a number to argue with.
8. **NDJSON and repeated JSON keys** as a group basis. Default: not in
   1.12.0; NDJSON lines are short and irregular, so neither shape catches
   them, and they stay as single findings.
9. **Line-wrapped base64** (MIME, PEM bundles) is never demoted (3.5).
   Default: accept.
10. **JWT expiry as a demotion.** Default: rejected (2.4), because the
    verdict would change with the clock.
11. **A reason on path downgrades.** Path downgrades lower to `low` with no
    record today. Default: a small separate item, so a reviewer can disagree
    with those too.
12. **zlib and raw deflate** are not in the binary table, so their payloads
    are not media for C4. Default: not added in 1.12.0.
13. **The umbrella reading `groups` and `demotion`.** Default: the umbrella's
    own item, after 1.12.0 ships; nothing here depends on it, and its
    reconciliation is unaffected.
14. **Baseline size.** Accepting a 5000-row token column writes 5000 entries.
    Default: accept; an entry per member is what keeps a new member visible,
    and `ignore.paths` is the declared alternative for a file that is pure
    data.
15. **JPEG marker list for bare runs.** Ruled: keep the four markers `E0`,
    `E1`, `DB`, `EE`. Excluded on purpose, and therefore not demoted (so
    reported at full severity, the safe direction): `E2` (ICC profile),
    `ED` (Photoshop APP13), `EC` (Ducky), `FE` (comment), and every other
    APPn. The widening option is any APPn (`E0` to `EF`) plus `DB` and
    `FE`, 18 markers, about 18 in 2^32 for a random head. Default: not now;
    consider it only if a recorded run shows bare JPEG runs with those
    markers producing hits.
