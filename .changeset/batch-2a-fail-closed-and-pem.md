---
'@vaultcompass/vault-guard': patch
'@vaultcompass/vault-guard-core': patch
'@vaultcompass/vault-guard-mcp': patch
'@vaultcompass/vault-guard-telemetry': patch
---

**A directory or pull-request run that cannot vouch for every file now exits 2
instead of 0. This can turn a previously green run red.**

Until now only `scan --staged` failed closed. A directory scan (and the Action's
pull-request mode) exited 0 and printed "No secrets found" over a file it could
not read, a file whose scan exceeded the per-file budget (5000 ms), or a named
target that did not exist among several (`check a.ts missing.ts`). All of these
now exit 2, in every output format (text, JSON, SARIF), and the message on
stderr names the file and the reason. For a file found by a directory or
pull-request scan it also gives the exact exclude to add (an entry containing a
question mark says the question mark matches any single character); for a file
named explicitly on the command line it says to check the path or stop passing
it. In JSON the same facts are in `run.unscannable` (file, kind, exclude when
there is one). In pull-request mode a tracked file that cannot be examined on
disk is included.

**Files are scanned whole up to 32 MiB.** The limit is the same one `--staged`
already applied to a blob, now judged on the raw blob size. A file above it is
not scanned; it makes the run exit 2 with the exclude to add, unless the config
already declares it. For library users, `scanTextFileAsync` and
`scanTextFileSync` in core now throw above 32 MiB instead of partly scanning, and
their `maxLineUtf16Units` option is gone.

If a file is meant to be skipped, say so in the config. Add it to
`ignore.paths` in `.vault-guard.json`, written relative to the scanned
directory and anchored with a leading slash. The message prints the entry as a
JSON string, ready to paste, for example:

```json
{ "ignore": { "paths": ["/data/large-export.json"] } }
```

On a pull-request run the config is read from the base ref, so land the entry
there first; a pull request that adds its own exclude only proposes it. A file
excluded this way is never opened, the run exits on the findings alone, and the
number is reported (`run.config_ignored_files` in JSON and SARIF, an `Excluded by
config ignore: N` line in text). Binary-extension skips are now counted too
(`run.binary_files_skipped`), as is the walk's type filter on a plain directory
run (`run.type_filtered_files`).

**PEM private key detection is broader.** The check that a `-----BEGIN ...
PRIVATE KEY-----` header is followed by key material now judges the text between
the header and its END marker, and recognises keys pasted commented out,
quoted and concatenated across lines, as a YAML or TOML list, flattened onto one
line, with markup or escaped line breaks, and behind long armor headers. This
also fixes a regression introduced in 1.9.0 for Python bytes literals. Prose and
public keys beside a mention of the header are still not reported.

Also: `scanFileListAsync` no longer defaults its context root to the process
working directory; a short `dckr_pat_` example value in API reference docs is no
longer reported by the generic secret rule; the Action's install and audit text
checks are judged per line; docs/INVARIANTS.md corrected where an audit found
its claims false or stale.
