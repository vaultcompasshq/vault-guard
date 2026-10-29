# vault-guard

vault-guard blocks a commit, a pull request, or an AI editor's proposed edit
that contains a credential: a vendor API key, a database URL with a
password, a private key. It scans files as they are now, not git history.

```bash
npm install -g @vaultcompass/vault-guard
```

---

## Why

A pasted key arrives as an ordinary edit. It is a few characters in a
config file or a test fixture, it does not look different from the lines
around it, and nobody reads a generated diff closely enough to spot it.
vault-guard sits at the three points a credential passes through on its way
into a repository: the edit an agent proposes (an MCP server exposes
`scan_text`, `scan_file` and `scan_workspace`, so a client can ask before
applying), the staged diff (a pre-commit hook running `vault-guard scan
--staged`), and the checkout in CI (a GitHub Action that writes SARIF for
code scanning).

It catches credentials that have a shape it can recognise: vendor key
formats, database connection URLs, SSH private keys, JWTs, and generic
`api_key` or `secret` assignments whose value clears an entropy gate. The
vendors are listed under [What it detects](#what-it-detects) and the rules
with their severities are in [docs/RULES.md](./docs/RULES.md).

It does not read Git history. A key that was committed months ago and
deleted since is invisible to a working-tree scan, and finding it is
Gitleaks' or TruffleHog's job rather than this tool's; that boundary is
deliberate and [docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md) records it
as such. It does not check whether a key it found still works, does not
look inside dependency trees or published tarballs, and does not judge
whether a package is malicious. The miss it will make most often is a
credential with no distinctive prefix or format, held in a plainly named
variable, at an entropy the generic rules let through.

---

## Quickstart

### 0. One-command setup (recommended)

From your repository root:

```bash
vault-guard init
```

Creates `.vault-guard.json`, a GitHub Actions workflow, local agent guardrail files under
`.vault-guard/`, and a pre-commit hook. Preview changes first:

```bash
vault-guard init --dry-run
```

Init never overwrites existing files: resolve conflicts manually. To undo:

```bash
vault-guard init --revert
```

Merge `.vault-guard/mcp-snippet.json` into your editor MCP config (see step 1).

### 1. Protect your AI editor (MCP)

Add to your MCP config (`~/.cursor/mcp.json`, `claude_desktop_config.json`, etc.):

```json
{
  "mcpServers": {
    "vault-guard": {
      "command": "npx",
      "args": ["-y", "@vaultcompass/vault-guard-mcp"]
    }
  }
}
```

The form above installs the latest version each time the editor starts. To pin one, use the same config with the version in the package argument:

```json
      "args": ["-y", "@vaultcompass/vault-guard-mcp@1.12.1"]
```

vault-guard exposes `scan_text`, `scan_file`, and `scan_workspace` tools. Your AI agent can call them before applying any edit that touches secrets.

See **[docs/MCP.md](./docs/MCP.md)** for the full tool reference.

### 2. Block secrets at commit time

```bash
vault-guard install-hook
```

Installs a hook that runs `vault-guard scan --staged` before every commit. Honors `core.hooksPath` (including globally-configured hook paths). When husky 9 already owns `core.hooksPath` (its generated `.husky/_` directory), the default `native` manager detects this automatically and installs into the same tracked `pre-commit` file husky's own shim runs -- no `--manager husky` needed. This also works when the package that owns husky's `.husky` is a monorepo subdirectory rather than the repo root (`core.hooksPath` like `packages/app/.husky/_`): the tracked hook lands at `packages/app/.husky/pre-commit`, matching where husky actually runs it. **Run `install-hook` (and `init`) from the git repository root, never from a package subdirectory** -- they refuse outright otherwise. Supports all major managers:

```bash
vault-guard install-hook --manager native     # default: Git hooks / hooksPath
vault-guard install-hook --manager husky      # .husky/pre-commit
vault-guard install-hook --manager lefthook   # lefthook-local.yml
vault-guard install-hook --manager precommit  # .pre-commit-config.yaml (only if absent)
```

**Windows:** `scan`, `check`, MCP, and CI workflows are supported on Windows,
by calling the CLI. **The composite Action is Linux and macOS only**: it
installs the scanner globally and adds `<prefix>/bin` to `PATH`, which is where
npm puts the shims on those platforms and not where it puts them on Windows. On
a `windows-latest` runner, run the CLI directly rather than
`uses: vaultcompasshq/vault-guard@…`.
Native hook install writes a POSIX `pre-commit` script (Git for Windows runs it
via `sh`, same as Git Bash) plus an optional `pre-commit.cmd` for clients that
call `.cmd` hooks directly. `git.exe` does not use the `.cmd` file.
Husky/Lefthook/pre-commit managers still use their own runners. CI runs
`pnpm test:windows` (core + CLI unit tests, excluding hook/proxy integration).

Emergency bypass (discouraged): `git commit --no-verify`.

### 3. Scan a repo or file

```bash
vault-guard scan .
vault-guard scan --staged          # staged files only (fast, for CI / hooks)
vault-guard check src/api.ts       # single file

# Pull-request mode: config and baseline come from the base ref, the head tree
# is what gets scanned. See "Pull requests" under CI below. Never in a hook.
vault-guard scan . --trust-base origin/main
vault-guard check --trust-base origin/main

# Accept the findings already on your default branch (see "Baseline" below).
vault-guard baseline                 # dry run: print what would be accepted
vault-guard baseline --write         # write .vault-guard.baseline.json at the repo root
```

**What a directory scan looks at.** Inside a git repository a plain scan takes
its files from git, so it scans the same tracked files pull-request mode does:

| Run | File set | Content read from |
|---|---|---|
| `scan .` outside git | Filesystem walk; `.gitignore` and vendored directory names (`node_modules`, `vendor`, `dist`, `build`, ...) are skipped at any depth. | Disk. |
| `scan .` inside git | Tracked files, **whatever `.gitignore` says**, plus untracked files `.gitignore` does not exclude. Vendored names are skipped only as a direct child of the scan root for tracked files, at any depth for untracked ones. Checked-out submodules and untracked nested repositories are scanned the same way. | Tracked files: the index (staged) blob, plus the disk copy when it differs, has a `filter` attribute, or is marked skip-worktree or assume-unchanged. Untracked files: disk. |
| `scan --staged` | The files in the index, read from the index. | The index blob. |
| `scan . --trust-base <ref>` | The HEAD tree (`git ls-tree -r HEAD`). | The HEAD blob, plus the disk copy when it differs from HEAD or has a `filter` attribute. |

Tracked content is read from git, so a `.gitattributes` transform
(`working-tree-encoding`, `eol`, `filter`) cannot change what is judged.

`.gitignore` controls what git will add, not what is already committed, so a
committed `.env` is scanned in every mode. Only `.gitignore` files are read for
untracked files, never `.git/info/exclude` or a global excludes file, so the
result is the same on every machine. Whether a target is inside git is decided by
a `.git` entry at or above it; once one is found, a git failure (a missing git, a
`safe.directory` refusal, a corrupt repository) is exit 2 with git's message,
never a quiet fall back to the walk. A tracked file missing from the working tree
(deleted locally, or left out by a sparse checkout) is counted as
`tracked_files_missing`; any other tracked file that cannot be examined is exit 2.

**Machine-readable output** (SARIF for GitHub Code Scanning, or JSON):

```bash
vault-guard scan . --format sarif
vault-guard scan . --format json
```

### What fails the build

Findings at or above the **`--fail-on` threshold** produce exit code 1, and
**only** findings do. Everything below the threshold is still reported (text,
JSON, SARIF) but does not break the gate. Tools that wrap vault-guard read
exit 1 as "secrets found".

Exit code **2** means vault-guard could not complete the scan and is refusing to
call the result clean. It is raised in two ways.

The run could not start, or stopped outside the scan itself: an invalid
`.vault-guard.json`, an invalid `--fail-on` or `--format` value, a usage error
such as an unknown option, `--staged` outside a git repository, `git diff
--cached` failed, `--trust-base` named a ref whose control inputs it could not
read, a directory or pull-request scan whose target resolved to no files at
all, or an unexpected fatal error (`--help` and `--version` still exit 0). No
JSON or SARIF document is written in these cases, because a document reporting
zero findings would be a claim the run did not earn.

The scan ran, but a file it should have scanned was not. This applies to
directory, pull-request and `--staged` scans alike:

| Cause | How to clear it |
|-------|-----------------|
| A file could not be read (permissions). In pull-request mode this includes a tracked file under a directory that cannot be entered | Fix the file, or declare it in `ignore.paths` |
| The file is over the 32 MiB whole-file limit (judged on the raw bytes on disk or in the index) | Declare it in `ignore.paths` |
| The file's scan used more than 5000 ms of CPU time on two passes, so its result is not trusted | Fix the file, or declare it in `ignore.paths` |
| A tracked file is missing on disk, as a sparse checkout produces (pull-request mode) | Check out the file, or declare it in `ignore.paths` |
| A path named to the `check` command, which takes several, does not exist (`check a.ts missing.ts`) | Check the path, or stop passing it |

Here the JSON or SARIF document **is** written, and the exit is still 2. stderr
names each file, the reason, and the exact entry to add, printed as a JSON
string ready to paste:

```json
{ "ignore": { "paths": ["/data/large-export.json"] } }
```

The entry is relative to the scanned directory (the repository root for
`--staged`) and anchored with a leading slash. On a pull-request run
(`--trust-base`) the config is read from the base ref, so the entry has to land
there first; a pull request that adds its own exclude only proposes it. A file
excluded this way is never opened and is counted, not hidden.

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
at any size; anything scanned as text is limited to 32 MiB. Two known limits
remain: a file whose first bytes are a valid binary header followed by text is
skipped (that is a change to the content, like encoding a secret), and
ISO-2022-KR text, which uses the SO and SI control bytes, is skipped when named
`.bin` with no declared `working-tree-encoding`. See
[docs/THREAT_MODEL.md](./docs/THREAT_MODEL.md), "What the binary skip
guarantees, and its boundary".

Every JSON and SARIF run states what it declined to open, even at zero:
`config_ignored_files` (excluded by the config's `ignore` list),
`binary_files_skipped` (skipped because the extension and the file's first
bytes agree on a binary format, with a per-format breakdown in
`binary_files_skipped_by_family`), `binary_type_mismatch_scanned` (files with
a binary extension whose bytes are text, scanned as text),
`binary_worktree_copies_skipped` (working-tree copies confirmed binary whose
file was otherwise scanned; it counts disk copies only, and a skipped blob
beside a scanned disk copy is counted as a mismatch, not a skipped copy),
`scan_budget_retimed`
(files re-timed once after a slow first scan, then trusted) and, on a
directory or pull-request scan, `type_filtered_files` (dropped by the walk's
extension, lockfile and generated-file filters). Text mode prints each of these
lines when it is non-zero. When a file was not scanned, JSON adds `run.unscannable_files`
and `run.unscannable` (each entry has `file`, `kind` of `read_error`,
`too_large` or `scan_budget`, and `exclude` when a config entry can name the
file); SARIF adds `unscannable_files` and marks the invocation
`executionSuccessful: false` with one notification per file. If you pipe SARIF
to `upload-sarif`, see **[docs/GITHUB_ACTION.md](./docs/GITHUB_ACTION.md)** for
how to guard that step.

Either way there is no `✅ SUCCESS` line. Exit 2 takes precedence over exit 1,
so gate on **any** non-zero exit rather than on 1 alone: a run that did not scan
every file cannot report a complete finding set.

```bash
vault-guard scan .                      # default: fail on medium and above
vault-guard scan . --fail-on critical   # only criticals block
vault-guard scan . --fail-on low        # block on anything (pre-1.4.0 behaviour)
vault-guard scan . --fail-on none       # advisory mode: report, never fail
```

The default is `medium` because the scanner deliberately downgrades findings to
`low` where they are usually not real leaks: generic patterns inside
`__tests__/`, `docs/`, `*.example` files, and public identifiers such as GCP
OAuth client IDs and Sentry DSNs. Only the low-precision generic patterns are
downgraded there. **Vendor-anchored rules (Anthropic, OpenAI, Stripe, AWS,
GitHub, Slack and the rest) keep their normal severity in documentation and
markdown too**: a live key pasted into `CLAUDE.md`, `AGENTS.md`, a README or a
docs page is still a live key, so it blocks. Write example keys in docs with the
documented placeholder words (`EXAMPLE`, `test`, ...) or in a shape that does
not match a vendor rule. Test and docs context is judged on the path **relative
to the scan root**, so the directories a checkout happens to live under (a
runner workspace named `docs`, a temp directory named `loadtest`) never count.
Set `"fail_on"` in `.vault-guard.json` to
change it repo-wide. The JSON `run` block reports both `fail_on` and
`blocking_matches`; gate on `blocking_matches`, not `summary.secrets`.

One more downgrade is made on content rather than on the path. A match
that is a slice of an embedded image, font or recording (it sits strictly
inside a base64 run of at least 1024 characters, and that run decodes to
the header of a binary format: for a `data:` URI, the format the URI
declares; otherwise a PNG or JPEG header) is reported at `low` with the
reason beside it. This is the one place a vendor-anchored rule is lowered,
and only because the bytes show the match is not a key: a key in a CSV
cell, in a plaintext `data:` URI, at the end of a payload, or in a payload
that decodes to text keeps its full severity. `--fail-on low` blocks on
these too.

Many matches of one rule in one column of a delimited data file, or on very
long lines, are printed as one grouped line with a count. They are still
separate findings in JSON and SARIF, each counts toward `blocking_matches`,
and a baseline accepts them one by one, so a new value in the same column
is reported on its own.

Structured output includes a `run` block (timing, files/bytes scanned, active pattern count, diagnostics). See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

---

## Part of the Vault & Compass guardrails

<!-- guardrails-family: shared block, keep it identical in dep-guard, vault-guard, intent-guard and conductor -->
The Vault & Compass guardrails are three gates over an AI-assisted coding
session, plus an optional umbrella: [dep-guard](https://www.npmjs.com/package/@vaultcompass/dep-guard)
checks what comes in (hallucinated package names, typosquats, tampered
lockfile entries),
[vault-guard](https://www.npmjs.com/package/@vaultcompass/vault-guard) checks
what goes out (credentials about to be committed), and
[intent-guard](https://www.npmjs.com/package/@vaultcompass/intent-guard)
checks the change against what was approved (drift from a frozen intent
contract, and change budgets). Each one installs, configures and runs on its
own;
[conductor](https://www.npmjs.com/package/@vaultcompass/conductor) is the
optional umbrella that runs them from one policy file, one hook and one
report, beside two scanners you install yourself:
[gitleaks](https://github.com/gitleaks/gitleaks) for secrets anywhere in git
history and [osv-scanner](https://github.com/google/osv-scanner) for known
vulnerabilities. conductor scans nothing itself and installs nothing that
is not its own.
<!-- /guardrails-family -->

---

## What it detects

- AI/ML API keys (Anthropic, OpenAI, Groq, OpenRouter, xAI, Perplexity, Mistral, DeepSeek, Together, Fireworks, LangSmith, HuggingFace, Replicate)
- Backend platforms (Supabase, Vercel Blob, PlanetScale, Doppler, Databricks, Cloudflare)
- Payment processors (Stripe live + test, PayPal)
- Cloud providers (AWS access keys, context-anchored AWS secret keys, GCP, Azure storage)
- Database URLs (PostgreSQL, MySQL, MongoDB, Redis)
- Version control tokens (GitHub classic + fine-grained PATs, GitLab, Bitbucket)
- Communication (Slack webhooks + tokens, Discord webhooks)
- SaaS tokens (Notion, Airtable, Figma)
- SSH private keys, JWTs, and entropy-gated generic `api_key` / `secret` assignments

Full rule reference with severities: **[docs/RULES.md](./docs/RULES.md)**.

Note: `sk_live_` / `sk_test_` are used by both Stripe and Clerk and there is no
reliable discriminator in the key body, so a Clerk secret key is reported under
the `stripe` rule id. The finding is correct; only the vendor label may be off.

---

## How it compares

vault-guard is **not** a history miner. It targets fast working-tree checks (the IDE, pre-commit gate, and CI on the checkout) and is designed to be composed with dedicated history scanners, not to replace them.

| Feature | vault-guard | Gitleaks | TruffleHog | detect-secrets | GitHub Secret Protection | GitGuardian |
|---|---|---|---|---|---|---|
| Working-tree / staged-file scan | Yes | Yes | Yes | Yes | Push/PR focused | Yes |
| Git history mining | No | Yes | Yes | No | Hosted scanning | Yes |
| MCP / AI-agent scanning | Local MCP | No | No | No | Yes | Yes |
| GitHub Action (SARIF output) | Yes | Yes | No | No | Native platform | Yes |
| Pre-commit hook installer | Yes | Partial | Documented, no installer | Yes | No | Yes |
| Entropy gating on generic patterns | Yes | Partial | Yes | Yes | Provider-pattern focused | Yes |
| Config ignore paths / baselines | Yes | Yes | Inline ignore comments only; no baseline file | Yes | Platform-managed | Yes |
| Local-only / no account required | Yes | Yes | Yes | Yes | No | No |

For credentials in Git history use **[Gitleaks](https://github.com/gitleaks/gitleaks)** or **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** alongside vault-guard. They are complementary, not competing.

Since 1.10.0, each release that changed the scanner has been compared with the previous one on four to eleven public repositories, with every changed finding checked by hand, and the 1.12.1 patch was checked for drift on three (`bench/real-repos/`). That is a regression check, not an accuracy score.

---

## Recommended stack

Use vault-guard as the **local AI-edit firewall**, then compose with history scanners:

| Layer | Tool | Role |
|---|---|---|
| AI edits + staged files + CI checkout | **vault-guard** (MCP, pre-commit, Action) | Fast working-tree gate; no account |
| Git history / deep local scan | [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline history + strong pre-commit rules |
| Verified / live-key audit | [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Confirm credentials still work |

vault-guard does **not** mine Git history: see [docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md). Pairing with Gitleaks/TruffleHog is the recommended production setup, not a competing choice.


---

## CI: GitHub Action

```yaml
jobs:
  secrets:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # Required by the upload step. Without it the default token is read-only
      # and the upload fails with a 403 that has nothing to do with the scan.
      security-events: write
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          # Required on pull requests: pull-request mode reads the config and
          # the baseline from the base branch, which a shallow clone does not have.
          fetch-depth: 0
      - uses: vaultcompasshq/vault-guard@v1.12.1
        id: vault-guard
        with:
          path: .
          format: sarif
          sarif-output: vault-guard-results.sarif
      - uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9 # v4.37.0
        # Guarded on the output being non-empty: a run that could not scan at
        # all writes no document, and handing that empty file to the uploader
        # fails the job with a parse error on top of the real message. And not
        # on exit 2: an incomplete scan's document covers only the files it
        # scanned, and uploading it would close alerts in the files it did not.
        if: always() && steps.vault-guard.outputs.results-file != '' && steps.vault-guard.outputs.exit-code != '2'
        with:
          sarif_file: ${{ steps.vault-guard.outputs.results-file }}
```

The uploader is pinned to a commit rather than to a tag, because it runs in your
repository with your `security-events: write`. `vault-guard init` scaffolds this
same workflow, permissions and pin included.

No `version` input in that example, because the default is the scanner version
this Action tag shipped with. Leaving it out is the recommended shape: the tag
then decides the scanner, and there is one pin to bump instead of two that can
disagree.

**The Action tag and the scanner version are separate numbers, and they do not
have to match.** `vaultcompasshq/vault-guard@v1.12.1` installs
`@vaultcompass/vault-guard@1.12.1` -- this is a package release, so the two move
together. They are still allowed to come apart: `vaultcompasshq/vault-guard@v1.7.4`
installed `@vaultcompass/vault-guard@1.7.0`, because that release changed the
Action and nothing in the scanner, so there was no new scanner to publish. Read
the tag as "which version of the workflow step", not as "which version of the
scanner".

### Where the scanner comes from

The Action installs `@vaultcompass/vault-guard` from the registry into a prefix
under the runner temp and calls that copy by absolute path. It never runs the
checkout's own `node_modules`, and never starts npm with the checkout as its
working directory, so neither a committed `.npmrc` nor a package the head's
lockfile put in `node_modules` can decide which program does the scanning. Up to
and including `@v1.7.0` it ran `npx` from inside the checkout, and either of
those two files was enough for a pull request to choose the program that judged
it.

`version` no longer accepts a dist-tag, and no longer defaults to `latest`. Two
reasons. A tag means the scanner judging a pull request is whichever one the
registry served that morning rather than one decided in the workflow file. And
npm reads a value beginning with a dot, or ending in `.tgz`, as a PATH rather
than a version, which on a run that started inside the checkout was one
committed file away from the tree handing over its own scanner. **If you were
relying on the old `latest` default, remove the input**; a dist-tag is refused
with a message saying so.

The install step refuses npm older than **10.5.2**. Below that floor `npm audit signatures` reports a clean install of these packages as tampered, because the client's own bundled keys are stale. Installing Node 22 is not enough on its own: **Node 22.0.0 ships npm 10.5.1**. Node **20.13.0** and later, and 22.1.0 and later, carry a usable npm. The step checks the client it actually found and names that version when it refuses.

Details: **[docs/GITHUB_ACTION.md](./docs/GITHUB_ACTION.md)**. Branch protection setup: **[docs/GITHUB_BRANCH_PROTECTION.md](./docs/GITHUB_BRANCH_PROTECTION.md)**.

### Pull requests: the rules come from the base branch

**On a pull-request run, every control input comes from the base ref and the
head tree is the thing scanned.**

Without that, a pull request could turn the scanner off in the same commit that
carried the secret, and nothing in the output would say so. Measured on a
scratch repository, each of these on its own turned exit 1 into exit 0:
`ignore: {"paths": ["**"]}` added to `.vault-guard.json`, a `severity_overrides`
entry setting the matching rule to `off`, `"fail_on": "none"`, a
`.vault-guard.local.json` **swapped in for** the committed `.vault-guard.json`,
a `.vault-guard.baseline.json` rewritten to carry the fingerprint of the finding
being added, a `.gitignore` covering the file the key sits in, and the key
committed under a directory named `vendor`.

The local-config one needs the swap. The two filenames are tried in order within
a directory, so a `.vault-guard.local.json` added beside an existing
`.vault-guard.json` never wins; deleting the committed file in the same commit
is what hands the run to the added one.

The Action passes `--trust-base origin/$GITHUB_BASE_REF` on pull-request events
by default, through the step's `env` block rather than by substituting an
expression into a shell script. You can run the same judgment locally:

```bash
vault-guard scan . --trust-base origin/main
```

What changes in that mode:

- `.vault-guard.json`, `.vault-guard.local.json` and the baseline are read from
  the ref with `git show`. Nothing is checked out and nothing is written.
- A control input the head changed is printed as a proposal and **not applied**:
  `config changed in this pull request (2 patterns added to ignore, fail_on
  lowered)`. The parenthesis names every top-level config setting the head
  changed, including `entropy_threshold`. A control input that exists only in
  the head is a proposal too, and the run uses the defaults it would have used
  with no config at all. Any other `.vault-guard.json`,
  `.vault-guard.local.json` or baseline file the head added or changed, at any
  depth, is listed by path as `other control files changed in this pull
  request`: this run never reads it, but a scan from another directory would.
- The file set is the **HEAD tree** (`git ls-tree -r HEAD`), so a `.gitignore`
  added by the pull request cannot hide a file that is already committed, and
  `git rm --cached` cannot either. Untracked and merely-staged files are **not**
  scanned in this mode: they are not part of the tree the pull request is
  proposing, and the index is local state the base ref says nothing about. Use
  `vault-guard scan --staged` for the pre-commit job of checking the index.
  Since 1.10.0 a plain `vault-guard scan .` inside git scans the same tracked
  files (plus untracked files that are not ignored), so a committed `.env` is no
  longer clean on push and blocking on pull requests.
- The vendored-directory names (`vendor`, `dist`, `node_modules`, …) are
  anchored to the scan root, so a committed `src/vendor/` is scanned. The run
  prints how many directories it skipped, in yellow when that number is not
  zero, because a root-level vendored name still mutes by design.
- The run also prints how many files it skipped by extension or name (`.min.js`,
  `.lock`, `.map`, lockfiles). Those filters are unchanged: a key committed as
  `src/leak.min.js` is still skipped. What changed is that the run now says so
  rather than reporting clean in silence.
- Inline `vault-guard: ignore-line` directives are content, not configuration,
  so they are still honoured. A directive that hid a critical vendor-anchored
  finding gets its own count beside the total.
- A ref that will not resolve is **exit 2** with one line on stderr and nothing
  scanned. So is a ref that resolves to `HEAD`'s commit, or to a different
  commit carrying `HEAD`'s tree, which is what a merge ref looks like when the
  base has not moved. A missing base is never a reason to fall back to trusting
  the pull request.

Outside pull-request mode nothing changes. A pre-commit hook and a local
`vault-guard scan .` are already inside the trust boundary and must never pass
the flag.

**There is no action input that turns pull-request mode off**, and that is a
decision rather than an omission. On a same-repo `pull_request` event GitHub
runs the workflow file from the pull request head, so an off switch on the
action would be settable by the pull request it exists to judge: the boundary
would ship with its own off switch on the untrusted side. Base-ref judging is
the floor; the only kind of change the input accepts is a tightening. If you
need 1.6.0 behaviour while you arrange `fetch-depth: 0`, stay pinned to
`vaultcompasshq/vault-guard@v1.6.0` until you are ready, which is a choice a
maintainer makes on a protected branch -- knowing what it costs: **every tag
before `@v1.7.1` installs its scanner with `npx` from inside the checkout**, so
a pull request can choose the program that scans it. Pinning back trades that
boundary for time on a one-line checkout change.

**The workflow file itself has to be protected, deliberately.** On a same-repo
`pull_request` event GitHub runs the workflow from the pull request head, so the
job that runs this gate is as editable as any other file in the branch. No flag
can detect a job the pull request deleted. Make the check **required by name in
branch protection**, or move the gate into a **reusable workflow on a protected
ref** and call it. See
**[docs/GITHUB_BRANCH_PROTECTION.md](./docs/GITHUB_BRANCH_PROTECTION.md)**.

**Requiring a human to approve a config change is repository configuration, not
a vault-guard setting**, and there is deliberately no flag for it. Add a
`CODEOWNERS` entry for the control files and require code-owner review on the
protected branch:

```
# .github/CODEOWNERS
/.vault-guard.json           @your-org/security
/.vault-guard.local.json     @your-org/security
/.vault-guard.baseline.json  @your-org/security
```

It lives there because a setting that could relax the gate has to sit somewhere
the pull request cannot write. An in-repo knob for this would be the
vulnerability wearing a settings label: a pull request would simply flip it in
the same commit. Base-ref judgment is the floor and is always on; a required
human approval can only make the gate stricter.

---

## Configuration

Create `.vault-guard.json` at your repo root:

```json
{
  "fail_on": "medium",
  "ignore": {
    "paths": ["fixtures/**"]
  },
  "severity_overrides": {
    "jwt-token": "low"
  },
  "extra_patterns": [
    { "id": "my-internal-key", "regex": "INT-[A-Z0-9]{32}", "severity": "critical" }
  ]
}
```

`init` no longer ignores test trees by default. Ignoring `**/__tests__/**`
means the scanner never looks there, which is how a vendor-anchored key
committed to a test file can slip past the hook entirely. Instead, test trees
are scanned, and the low-precision rules (generic assignments, DSNs, JWTs, PEM
private keys) are downgraded to `low` there.

**Vendor-anchored rules are not downgraded in test files at all.** That is the
point of the change, and also its cost: a vendor-shaped token in a test blocks
whether or not it is live, because the scanner cannot tell a real `sk-ant-` /
`ghp_` / `AKIA` string from a convincing fabricated one. Build fake tokens from
fragments joined at runtime, or use the documented placeholder words
(`EXAMPLE`, `test`, …). Keep a `fixtures/**`-style ignore only for directories
that hold deliberately-planted credential fixtures (a scanner's own
true-positive corpus).

JSON Schema for editor autocomplete: **[schemas/vault-guard-config.json](./schemas/vault-guard-config.json)**.

> **Upgrading to 1.7.0.** The config schema is now checked on **every** load, not
> only when you run `vault-guard config validate`. Through 1.6.0 an unrecognised
> top-level key was silently dropped and the scan carried on; from 1.7.0 it fails
> the run with the validation message. Realistic keys that were tolerated and are
> now refused include `$schema`, `comment` and `version`. Run
> `vault-guard config validate` once after upgrading, and delete or rename
> anything it names. Only the keys documented above are accepted.

> **Also upgrading to 1.7.0.** If your CI workflow runs on `pull_request`, add
> `fetch-depth: 0` to `actions/checkout`. Pull-request mode reads the config and
> the baseline from the base branch, and a shallow clone does not have it, so the
> scan exits 2 rather than falling back to trusting the pull request. There is no
> input that turns pull-request mode off, on purpose: on a same-repo
> `pull_request` event GitHub runs the workflow file from the pull request head,
> so an off switch would be settable by the pull request it judges. If you are
> not ready to change the checkout, stay pinned to
> `vaultcompasshq/vault-guard@v1.6.0` until you are -- but know the trade: every
> tag before `@v1.7.1` installs its scanner from inside the checkout it scans,
> so a pull request can choose the program that judges it.

> **Also moving to `@v1.7.1`.** It is an action-only release: the tag moves, the
> npm packages stay at 1.7.0. Two things change in a workflow. The `version`
> input takes an EXACT version now and refuses a dist-tag, so **delete
> `version: latest`** if you have it -- the default is the scanner this tag
> shipped with. And the `results-file` output is empty when the scan wrote no
> document, so a chained `upload-sarif` should be guarded on it rather than run
> unconditionally. Pinning `@v1.7.0` keeps the old Action, the one that installs
> its scanner from inside the tree it scans.

**Baseline**: accept the findings that already exist, so only new ones fail the
gate. Pull-request mode scans the whole head tree, so without a baseline every
finding already on the default branch blocks every unrelated pull request.

```bash
vault-guard baseline              # dry run: lists what would be accepted, writes nothing
vault-guard baseline --write      # writes .vault-guard.baseline.json
vault-guard baseline --write --include-critical
vault-guard baseline src/ --write # accept only under src/ (run from the root)
```

- It runs the same plain scan as `vault-guard scan`, with the working-tree config
  and the effective `fail_on`, and accepts **every finding that would block, in
  tracked files only**. A finding in an untracked file is never written, not
  even its name; the command prints `untracked files with findings: N` instead.
- It prints one line per accepted finding (`file:line`, rule, severity), then
  `kept N, added N, dropped N (no longer found)`, plus `converted N` when it
  upgrades a file that had only the old `fingerprints` list.
- **Critical findings are refused** unless you pass `--include-critical`: they
  are listed as `not accepted: critical, rotate and remove instead`, the rest is
  still written, and the command exits 1. Rotate a critical key rather than
  accepting it.
- **Where it writes.** When the target is inside git, always
  `.vault-guard.baseline.json` at that repository's root, and `--write` refuses
  to run from any other directory (exit 2, naming the root). Outside git it says
  `not a git repository` and writes in the current directory. Files of a
  submodule or of an untracked nested repository are never accepted: they are
  another repository's history.
- **A path argument merges.** `baseline src/ --write` re-examines only `src/`:
  entries for files outside it are kept untouched and counted as `N entries
  outside the scanned path kept`, never reported as dropped.
- Exit codes: 0 written (or dry run), 1 written with critical findings refused,
  2 could not run (an incomplete scan writes nothing). `--trust-base` and
  `--staged` are refused.
- Nothing else writes the file: not `scan`, not `check`, not `init`, not the
  hook, not the Action.
- **Never through a link.** A `.vault-guard.baseline.json` (or
  `.vault-guard.json`, `.vault-guard.local.json`) that is a symlink, even one
  pointing nowhere, is refused: `scan` and `baseline` exit 2 before scanning,
  `config validate` exits 1. `baseline --write` writes a temporary file beside
  the baseline and renames it into place, so a link is replaced, never written
  through. Replace a linked baseline with the file itself.
- **Accepted from the committed content.** Inside git the baseline accepts
  findings in the index (staged) version of each tracked file; a finding that
  exists only in an uncommitted edit is listed as `uncommitted working-tree
  edits with findings: N` and not accepted. Marker-only entries take their
  `file_digest` over the committed bytes.

**The baseline pull request is itself red.** Under `--trust-base` the baseline
comes from the base branch, so the pull request that adds it is judged without
it, and a pull request can never accept its own findings. Land it while the gate
is advisory, or merge it knowingly. After that, commit changes to the file
through review (see the CODEOWNERS example above).

The file keeps two lists:

```json
{
  "version": 1,
  "comment": "Written by vault-guard baseline --write; ...",
  "fingerprints": ["<positional sha256>"],
  "entries": [
    { "fingerprint": "<content sha256>", "rule": "jwt-token",
      "file": "data/rows.csv", "line": 7187, "severity": "high", "count": 1 }
  ]
}
```

- **`entries`** is what 1.10.0 and later match on, and only that list when it is
  present. An entry's key is the file's path from the repository root, the rule
  and a digest of the matched text, not the line, so moving a finding keeps it
  accepted while a different value, a rename or a copy into another file is a new
  finding. An entry suppresses at most `count` matches, so a pasted second copy
  surfaces, and only while the finding's severity is no higher than the recorded
  one, so a rule raised later surfaces again. For rules that match only a fixed
  marker (`ssh-private-key`, `gcp-service-account`) the entry is bound to the
  whole file instead: it carries a `file_digest`, a SHA-256 over the file's raw
  bytes, and any change to the file (a new key behind the same header, or only
  converting LF line endings to CRLF) re-surfaces it. A malformed `entries` list
  suppresses nothing and raises a `baseline.invalid` warning; it never falls back
  to `fingerprints`.
- **`fingerprints`** is the positional list (path, rule, line, offset, length)
  that 1.9.x reads, so a runner pinned to 1.9.x keeps working with the same
  file. It applies neither `count` nor the severity bound, and marker-only
  findings are left out of it, so a 1.9.x runner keeps showing them.

A committed digest lets someone confirm a guessed low-entropy secret. The
plaintext already sits in the same repository and its history, so the added
exposure is an entry that outlives a history rewrite; `--write` regenerates the
file and drops stale entries. See **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

**Inline suppression:**

```ts
const key = "sk-ant-..."; // vault-guard: ignore-line
// vault-guard: ignore-next-line
const alsoFine = "...";
```

Suppressions never happen silently. Every run states how many findings the
baseline and inline directives hid: the text summary prints a `Suppressed:`
line (even at zero), and JSON and SARIF carry `run.baseline_suppressed` and
`run.inline_suppressed`, with a `suppression.inline` diagnostic naming the
suppressed line numbers.

---

## Opt-in token telemetry, statusline and suggest-model

Optional local Anthropic token logging (`vault-guard proxy`), `statusline` and `suggest-model`: see [docs/token-telemetry.md](./docs/token-telemetry.md).

## VS Code / Cursor extension

Inline diagnostics for open files, not yet published: see [docs/vscode-extension.md](./docs/vscode-extension.md).

---

## Scripting & CI (stable JSON output)

`--format json` prints one JSON object on stdout (diagnostics on stderr; parse stdout only):

```bash
node packages/cli/dist/cli-entry.js scan /path/to/project --format json
```

Parse `summary.secrets`, `results`, and `run` as documented in **[docs/PRODUCT_SCOPE.md](./docs/PRODUCT_SCOPE.md)**.

**`results[].file` is repository-relative**: relative to the scan root (the directory you
scanned, or the repository root for `--staged`), with forward slashes on every platform, and
the same in text output, JSON and SARIF. It never carries your home directory or user name.

```json
{ "results": [ { "file": "src/config.ts", "matches": [ { "type": "aws-access", "line": 12 } ] } ] }
```

Scanning `/work/app` from another directory gives `src/config.ts`, not `/work/app/src/config.ts`.
A path that is not under the scan root cannot come from the command line (it takes one target),
but a programmatic caller that formats such a path gets it back unchanged (absolute) rather than
as a `..` traversal. Fingerprints are not derived from this display path, so baselines written
before this change still match.

**If you are building a pass/fail gate, read `run.blocking_matches`, not `summary.secrets`.**
`summary.secrets` is a raw count of every finding in `results`, including ones below the
`--fail-on` threshold; it does not reflect the gate. `run.blocking_matches` is the count of
findings at or above the effective `fail_on` threshold and is exactly what drives vault-guard's
own exit code. An integrator gating on `summary.secrets` will fail builds that vault-guard itself
considers passing.

**Also check `run.unscannable_files`.** It is the number of files the run should have scanned
and did not vouch for: unreadable, over the 32 MiB limit, over the per-file CPU-time budget twice, a
tracked file missing on disk, or a path named to `check` that does not exist. `run.unscannable` lists
each one with its `kind` and, where possible, the `ignore.paths` entry that would declare it.
When it is present the process exits 2, and a `blocking_matches` of 0 means "nothing found in
what was scanned", not "nothing there".

**Fields added in 1.10.0**, all additive:

- `run.file_set`: `git` (a plain scan inside git), `walk` (outside git), `head-tree`
  (`--trust-base`) or `index` (`--staged`).
- `run.tracked_ignored_files_scanned` and `run.tracked_nested_vendored_scanned`
  (on `git` and `head-tree` runs): tracked files that `.gitignore` matches, and
  tracked files under a nested vendored directory, that were scanned. Text mode
  prints each only when it is not zero.
- `run.tracked_files_missing` (on `git` runs): tracked files not in the working
  tree. `run.vendored_dirs_skipped` is now also stated on `git` runs.
- `run.baseline_entries`: entries loaded from the baseline's `entries` list.
- `matches[].content_fingerprint`: the content key a baseline entry uses, for
  rules whose match holds the secret. `matches[].fingerprint` keeps its
  positional meaning. SARIF adds it as `partialFingerprints["vault-guard/v2"]`
  beside `vault-guard/v1`.

**Fields added in 1.12.0**, all additive, and the four `run` counts always
present, zero included:

- `run.demoted_matches` and `run.demoted_by_reason` (`data-uri-binary-payload`
  and `base64-binary-run`, both keys present): matches lowered to `low` because
  they sit inside encoded media. Each such match carries a `demotion` record
  (`from`, `reason`, `family`, `format`, `media_type` for a `data:` URI, and
  `run_length`); its `severity` is already the demoted one, so the gate and
  `blocking_matches` read it as they read any other.
- `run.match_groups` and `run.grouped_matches`: groups formed in data files,
  and the matches in them. A member keeps its own entry in `results[].matches[]`
  and gains `group_id`; the file gains `results[].groups`. Grouping is
  presentation only: `summary.secrets` and `blocking_matches` still count
  matches. SARIF keeps one result per match and adds `vault-guard/group` and
  `vault-guard/group_size` (and, on a demoted result, `vault-guard/demoted_from`
  and `vault-guard/demotion_reason`) to its properties. In JSON both
  `groups[].column` (the field index) and `matches[].column` are 0-based; the
  text line prints them plus 1, so field index 6 is shown as "column 7".

---

## Docker & Homebrew

- **Docker:** `docker/README.md`, image installs the published npm CLI.
- **Homebrew:** `packaging/homebrew/README.md`, optional tap workflow (npm remains canonical).

---

## Maintainer dogfood

Before tagging a release, install on a ship machine and smoke the real paths: the MCP server, the pre-commit hook, optional telemetry, and `pnpm bench` / `node bench/run.cjs --assert`.

## Development

Requires **Node.js 22+** and **pnpm 9+**. (Node 20 reached EOL April 2026.)

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install
pnpm build
pnpm test
pnpm lint
```

`pnpm test` at the root builds first, because some tests spawn the built CLI
from `dist/` and would otherwise test a stale build. See CONTRIBUTING.md.

Published packages: **`@vaultcompass/vault-guard`** (CLI), **`@vaultcompass/vault-guard-core`**, **`@vaultcompass/vault-guard-mcp`**, **`@vaultcompass/vault-guard-telemetry`**.

Run the precision/recall benchmark against the labeled fixture corpus:

```bash
node bench/run.cjs
```

---

Adopter feedback is a row in [FINDINGS.md](FINDINGS.md). How to change this repository is in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, built and maintained by [Vault & Compass](https://vaultcompass.io)
