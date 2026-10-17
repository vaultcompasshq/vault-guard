# Invariants

Cross-cutting properties this repository is supposed to hold, with the reason
each one exists and the thing that enforces it. An audit reads this file instead
of re-deriving a list from memory, and every new architectural decision appends
to it.

**This file is a claim, not a fact.** It was started during the 1.7.1
action-only release and covers the composite Action, the two version numbers
around it, and (in the final section) a set of scanner-core properties; it is not
yet a complete list of this repository's invariants, and saying so is more useful than implying coverage it does not
have. Every entry below names what enforces it, so a reader can check the claim
against the code rather than trusting the prose. An entry written in the same
change as the fix it describes deserves the most scrutiny, and these were.

---

## The scanner is itself a control input, and comes from outside the tree

Pull-request mode draws a line between a SUBJECT (the head tree) and a CONTROL
INPUT (`.vault-guard.json`, `.vault-guard.local.json`, the baseline), and reads
the control inputs from the base ref. That list was incomplete, and the missing
entry is the largest one: **the program doing the scanning**. A gate that reads
its config from the base branch and then runs a binary the head chose has moved
the decision, not removed it.

Through `@v1.7.0` the Action ran `npx --yes "@vaultcompass/vault-guard@${VG_VERSION}"`
with the checkout as its working directory. Two routes followed from that, and
both are decisions real npm makes about files the head controls:

- **A committed `.npmrc` repoints the registry.** npx in non-global mode reads
  project config from its cwd, and `--yes` means no prompt. A pull request
  adding one root file chooses which registry the scanner is fetched from.
  Both the global `registry=` key and the scope-specific
  `@vaultcompass:registry=` key do it; the second is quieter, because every
  other install in the workflow keeps working normally.
- **An installed copy wins outright.** `npx pkg@version` run in a tree whose
  `node_modules` already satisfies that spec runs the local copy and never
  contacts a registry. The version pin degrades from a choice of program to a
  satisfaction check on a package the head wrote, and any workflow with an
  install step before the gate hands that over.

**The rule: install the scanner from the registry into a prefix under the runner
temp, start npm from the runner temp, and call the result by absolute path.**
Not "install outside and run wherever": a composite step with no
`working-directory` runs at the workspace root, so npm would still start with
the head's `.npmrc`, manifest and lockfile under its cwd. Global mode is
documented not to read project config, which is a property of a version of npm
rather than of this repository, and is not what the boundary should rest on.

**Enforced by:** `packages/cli/src/__tests__/action/action-run-script.test.ts`
(runs both steps with npm stubbed, recording npm's argv, cwd and prefix),
`packages/cli/src/__tests__/action/action-path-validation.test.ts` (the steps
exist at all, and neither runs npx), and `bench/action-install.cjs` (real npm,
two local registries, both routes mounted). `bench/action-install.cjs` is NOT
run by any workflow: it is a manual harness, and its checked-in baseline
(`bench/baseline.action-install.json`) still records scanner 1.7.0. Treat its
results as evidence from the day somebody last ran it, not as a standing gate.

`scripts/test-action-path-validation.sh` also runs on a macOS runner, where the
jest suites do not, and what it carries is two different things. Its grep guards
read the real `action.yml`, and its per-step checks ask the real file through
`scripts/extract-action-step.cjs`, so neither can drift. Its `validate_path`,
`validate_version` and `validate_trust_base` functions are **hand copies** of
the ones in `action.yml`, kept there because the point is to run those idioms
under bash 3.2, and a copy can drift from its original: read a green run of that
file as "these idioms are portable", not as "action.yml still contains them".
The grep guards beside them are what keep the second claim true.

**What this does NOT cover**, and the comment in `action.yml` says so: a pull
request can edit the workflow file, because a `pull_request` run uses the
workflow as it is in the merge commit. Branch protection on the base branch with
review required for `.github/workflows/**` is the control for that, and nothing
the action does substitutes for it. The absolute binary path is likewise not
total: the shim starts with `#!/usr/bin/env node`, so the interpreter is still a
PATH lookup a cooperating workflow can influence.

## The scanner is installed without scripts, and verified before it is trusted

Two properties of the same step, and both follow from the scanner being a
CONTROL INPUT rather than an ordinary dependency.

`--ignore-scripts`, because this step runs on a runner holding the job's token.
Without it every package in the resolved tree gets arbitrary code execution
there on every run, which is a strange amount of trust to extend from the tool
whose job is deciding whether this repository can be trusted. It costs nothing
here: the only native dependency is `better-sqlite3`, it is an OPTIONAL
dependency of the telemetry package, and the store degrades when its bindings
are missing.

`npm audit signatures` after the install. **Read the next paragraphs before
relying on it**, because the obvious summary of this command is wrong and the
first version of this entry asserted three things it does not do.

WHAT IT DOES. It asks the registry for each name and version in the tree and
checks the registry signature served back. Every name and version, the scanner
included, has to be one npmjs currently serves with a valid signature. That
catches an unpublished, replaced or unsigned package at the moment of install,
and it fails closed under `set -eu`.

WHAT IT DOES NOT DO, each measured rather than reasoned. It does not read the
installed files: `pacote` refetches the manifest instead of hashing anything on
disk, so a tampered install is invisible -- appending a payload to the installed
binary and re-running the command exits 0. It does not defeat a compromised
registry, which signs what it serves. And a MISSING attestation is not a
failure, only a missing or invalid signature is, so it does not require
provenance despite these packages publishing it.

THE ROOT MANIFEST IS LOAD-BEARING. `npm audit signatures` audits the tree's
EDGES OUT, and a global install leaves `<prefix>/lib` with a `node_modules` and
no manifest, so the root declares nothing and the installed package sits on the
far end of no edge. Without a manifest the audit covers the dependencies and
SKIPS THE SCANNER, the one package the check exists for. Measured: 13 packages
installed, 12 audited without it, 13 audited and 5 attestations with it. The
first version of this step shipped without the manifest and recorded that 12 as
evidence the check worked -- the numbers disproved the claim in the same sentence
that made it, which is the failure this file exists to catch.

KNOWN CONSEQUENCE OF FAILING CLOSED: a consumer whose runner points npm at a
mirror or proxy that does not serve `/-/npm/v1/keys` installs fine and then
fails here with `EMISSINGSIGNATUREKEY`, and a sigstore or TUF outage does the
same to everyone at once. Written down in `docs/GITHUB_ACTION.md` rather than
left to be discovered from a red required check.

**Enforced by:** `action-run-script.test.ts` (the argv carries the flag, the
manifest is written declaring the version being installed, the audit is
recorded, and the audit comes after the install), the text guards in
`action-path-validation.test.ts`, and `scripts/test-action-path-validation.sh`,
which refuses any executable line that spells an install the way this file
spells installs (`install`, `i`, `add`, `ci`) without the flag, judged per line
with comments excluded. These are drift checks, not a parser: they catch the
spellings used in the file and the obvious variants, and a new spelling of an
install would need the pattern extended. The jest
suites run against a STUBBED npm, so they prove the action ASKS and say nothing
about what a real npm does when asked -- and that gap is precisely what hid the
missing manifest, since the stub laid down an empty `lib` where the real command
would have reported 12 of 13. Verified by hand against the registry at 1.7.0:
two global installs of `@vaultcompass/vault-guard@1.7.0`, one with
`--ignore-scripts` and one without, scanning the same clean tree, produce
byte-identical output apart from the `scannedAt` timestamp, both exiting 0. An
earlier version of this paragraph cited a byte count without naming the tree or
the flags, which nobody could reproduce.

## The scan path is absolute AND resolved, and that is one decision with two halves

The run step starts in the runner temp, so the scan root is built from
`GITHUB_WORKSPACE` rather than passed as a relative `.`.

It is then resolved with `pwd -P` before being handed over, because vault-guard
anchors a directory scan at its own process cwd: node reports that cwd with
symlinks resolved, while bash's `cd` keeps the logical path. Hand the scanner a
logical `/var/...` target while its cwd reads `/private/var/...` and every file
in the head tree falls outside the target by `path.relative`, so the run scans
**zero files and reports a clean result over nothing**. That is a green check
that scanned nothing, which is the worst failure shape a gate has.

It would be silent on a Linux runner, whose workspace path is canonical already.
It was found by `bench/action-install.cjs` on a macOS temp directory, where
`/var` is a symlink, before the release shipped.

The step then chdirs into that scan root, which is deliberate and separate from
where npm ran: vault-guard loads its config, resolves the trust base and
computes every reported path from its cwd, so a scanner left in the runner temp
would fail to resolve `origin/<base>` and exit 2 on every pull-request run,
blaming a `fetch-depth` the caller already set.

**Enforced by:** the `SCAN_ROOT` guards in
`packages/cli/src/__tests__/action/action-path-validation.test.ts` and
`scripts/test-action-path-validation.sh`, and by the `filesScanned` field
recorded per case in `bench/baseline.action-install.json` -- a run that scans
nothing shows up there as a number, not as a passing test.

## The output path is checked as a path, not as a string

`sarif-output` names a file the action WRITES, into a tree the head controls, so
the string rules are not the whole check. It may not resolve under `.github/`,
which holds the workflow file and the CODEOWNERS entry that decide how this gate
runs, and it may not resolve through a symlink at the file or at any directory
on the way to it -- checked before `mkdir -p`, so a refused run has not already
created directories through the link.

Every guard here compares strings, so every SECOND NAME for the same file has to
be normalised away first, to a fixed point: a `./` prefix, an interior `/./`, a
doubled slash, a different case (macOS filesystems are case-insensitive), and a
**trailing slash**. That last one is not only cosmetic: `test -L` FOLLOWS a
symlink when the path it is given ends in a slash, so `out.sarif/` and
`out.sarif` name the same file and only the first walked past the symlink guard,
after which `dirname` returned the workspace and the loop ended having checked
nothing. A value that normalises to nothing or to a single dot names a
directory, and is refused with the input's name rather than left to fail as a
shell redirect error deep in the run step.

**Enforced by:** the `.github/` and directory cases in
`action-path-validation.test.ts` only, and the behavioural symlink case (a real
link planted, asserting nothing was written through it) in
`action-run-script.test.ts` only, including the trailing-slash spellings.

## Only 0, 1 and 2 are verdicts, in the step's exit AND in its output

126 and 127 are what the SHELL produces when a binary is missing or not
executable, which is exactly what a failed install looks like from the run step.
They are re-raised as 2, could-not-run, because reporting them as 1 would invent
findings nobody found.

The `exit-code` OUTPUT carries the mapped code too, not the raw status. A caller
reads that output precisely to tell a verdict from a failure to reach one, and
publishing a 127 the documented contract says cannot happen is the same bug one
layer out. `results-file` is published only when the run wrote something, so a
chained `upload-sarif` can be guarded on one expression instead of failing on an
empty file with a parse error that buries the real message.

**Enforced by:** the exit-code cases in `action-run-script.test.ts`, including
one that never installs the binary at all and asserts the output reads 2.

## A verdict requires a report, and the exit code alone is not one

The status says what the scanner decided. Whether it wrote anything says whether
it got far enough to decide. When the report is empty the status must not be
read as a verdict at all, and both arms of reading it anyway are wrong, in
opposite directions.

Exit 1 with no report is not findings. Commander exits 1 on an unknown option
and writes the message to STDERR, so the teed report stays empty, and 1 is also
the findings code. That is a live failure rather than a theoretical one: a
consumer pinning a `version` older than the flags this tag passes had a
repository told it was carrying secrets by a scanner that never parsed its own
argv. Findings would have produced findings.

Exit 0 with no report is not a clean scan. Same inference on the arm that fails
OPEN: a clean scan prints its report, so nothing written means the scan did not
happen, and calling that clean passes a pull request nothing looked at.

Both are re-raised as 2 with a message that says no report was written and names
the version skew as the usual cause. This is deliberately keyed on the REPORT
and not on a list of known-bad exit codes: the failure that produced this rule
landed on 1, the most ordinary code there is, which is why the wildcard arm that
had exactly the right words for it never fired.

**Enforced by:** `action-run-script.test.ts`, which drives a stub that writes to
stderr only and exits 0 and 1 in turn, alongside a case asserting a report WITH
findings in it is still reported as findings.

Verified against the real binary at scanner 1.7.0: a clean scan writes 627 bytes
and exits 0, the `fixtures/release-smoke` leak writes 1830 bytes and exits 1,
and an UNKNOWN OPTION writes zero bytes to stdout, its message to stderr, and
exits 1. That last one is a stand-in for the reported failure rather than a
reproduction of it: it runs a made-up flag against a current scanner, not
`--trust-base` against an old one, which is a different way into the same
Commander code path at `lib/command.js:1829` (commander 12.1.0), where `error()` computes
`config.exitCode || 1`. Nobody has run an old scanner here, and this entry
should not be read as saying otherwise.

## The `version` input takes an exact version only

It defaults to the SCANNER version the Action tag shipped with, which is a
different number from the tag whenever an action-only release happens.

A dist-tag hands the choice of program to the registry on the morning of the
run. A charset check is not enough on its own: npm's specifier parser reads a
value beginning with `.` or ending in `.tgz` as a local path, so `.`, `..` and
`payload.tgz` resolve against a directory instead of the registry, and a value
that is not valid semver at all -- `01.7.0`, `1.7.00` -- falls back to being
treated as a dist-tag. The refusal message names the migration (`REMOVE the
input`), because `latest` used to be the default and a refusal with no
alternative in it is a wall.

**Enforced by:** the version cases in `action-path-validation.test.ts` (not in
`action-run-script.test.ts`, whose version cases are about the argv), and the SHAPE half
of the contract in `scripts/test-action-path-validation.sh`. That script checks
a hand-copied regex rather than the step itself, so it can run on the macOS
runner's bash 3.2. The copy has already cost once: it kept asserting `0.0.0` was
accepted, and stayed green, after the action started refusing it.

## The `version` input is checked for CAPABILITY, not only for shape

Passing the semver pattern proves the input names a version. It says nothing
about whether that version understands the arguments this tag is about to hand
it, and the input exists precisely so a consumer can pin a scanner OTHER than
the one the tag shipped with. Version skew is therefore a supported
configuration that can produce an unsupported argument vector.

The step declares the oldest scanner this tag can drive and refuses anything
below it, naming both numbers and the flag that set the floor. The floor is a
property of THE FLAGS THIS TAG PASSES rather than of the tag number: raise it in
the same commit that starts passing a newer flag. Today it is 1.7.0, set by
`--trust-base`.

The comparison is component by component and never textual, because `1.10.0`
sorts below `1.7.0` as a string and above it as a version, so a lexicographic
check would refuse the newer scanner the floor exists to keep.

**Enforced by:** the floor cases in `action-path-validation.test.ts`, which
include `1.10.0` on the accepted side and `1.6.9` on the refused side, plus a
case asserting the action never defaults to a version it would itself refuse.

## On a pull request, `version` may not pin BACKWARD

The floor above is flag compatibility, and it is not the control for version
choice: it admits everything at or above 1.7.0. On a same-repo `pull_request`
event GitHub runs the workflow file from the HEAD, so `version:` is written by
the pull request being judged. Once a second version exists, that is a bypass
with an innocent shape -- deleting a security step reads as deleting a security
step, while `version: 1.7.0` reads as version management.

So on a pull-request event the step refuses a version BELOW the scanner this
action tag ships, and accepts anything at or above it. Pinning FORWARD stays
allowed, which is the direction the input exists for. That rests on an
ASSUMPTION the rule does not enforce: that a newer scanner is at least as
strict. Nothing bounds a forward pin, so a version ahead of the tag scanner is
accepted whatever its rules turn out to be.

Four properties, each load-bearing:

- `VG_TAG_SCANNER_*` is a SEPARATE constant from `VG_MIN_*`. They hold different
  numbers (`VG_MIN` is 1.7.0 and `VG_TAG_SCANNER` is 1.10.0 in `action.yml`; they
  were equal when this entry was written, and the claim that they stay equal is
  false) and mean different things: the floor is the oldest scanner that
  understands this tag's flags, this is the tested scanner the tag ships. One
  constant serving both is how raising one silently raises the other.
- The comparison is against that hardcoded constant, never against anything
  derived from an input. `inputs.version` looks identical whether a consumer
  pinned the current version or the default supplied it, so the step cannot tell
  a pin from a default; the constant is the only source of truth. It is
  trustworthy because `action.yml` comes from the ref the consumer's workflow
  names, not from the pull request's tree.
- The event test is `GITHUB_BASE_REF` being non-empty, the same one the run step
  uses to decide whether to pass `--trust-base` under `auto`, rather than a
  second detector to keep in step. It rests on a PLATFORM GUARANTEE worth
  recording, because a same-repo pull request's author writes the workflow file
  and the obvious bypass is therefore `env: GITHUB_BASE_REF: ""` at job level:
  GitHub documents that the default `GITHUB_*` and `RUNNER_*` variables cannot
  be overwritten and that such an assignment is ignored
  (https://docs.github.com/en/actions/reference/workflows-and-actions/variables).
  The Validate inputs step DECLARES `GITHUB_BASE_REF: ${{ github.base_ref }}`
  in its own `env:` mapping (`action.yml`, the Validate step) and uses it to
  decide whether the run is a pull request. A step-level entry wins over a
  job-level one, and `github.base_ref` is read out of the event payload rather
  than out of anything a workflow author writes. The platform no-overwrite
  guarantee above is a second, separate line of defence, and neither is depended
  on as the sole control.
- Written accept-only-if, not refuse-if, for the same reason as the npm floor:
  `[` returns 2 on a malformed comparison and an `if` reads 2 as false, so a
  refuse-if shape turns an arithmetic error into permission.

**What this does NOT cover, stated because the obvious summary is wider than the
rule.** It closes pinning backward on a SAME-REPO pull request, and nothing
else.

- Not forks, and on forks the rule costs something rather than merely doing
  nothing. A fork's `pull_request` run uses the BASE repository's workflow file,
  so a fork author never writes the `version:` that judges them and there is no
  hole there to close. But `GITHUB_BASE_REF` IS set on a fork pull request, so
  the check fires anyway and judges the base repository's own trusted workflow
  file. Once a newer scanner ships, a maintainer's deliberate backward pin in
  that base workflow fails EVERY fork pull-request run: a pure false refusal, on
  a pin nobody untrusted wrote. The remedy is the same as for any consumer,
  which is to remove the `version:` input.
- Not a pull request that deletes the step, moves the `uses:` pin to an older
  action tag, or edits the job away. Those are workflow-file edits, and the
  control is branch protection with required review on `.github/workflows/**`.
  Nothing in `action.yml` can substitute for it.
- Not push events. The rule fires exactly where `GITHUB_BASE_REF` is set, which
  is `pull_request` and `pull_request_target`; push runs are out of scope and
  the flag floor remains their only version gate. Read that as scope, not as
  safety: a push to an UNPROTECTED feature branch runs that branch's own
  workflow file, written by the same author, with `GITHUB_BASE_REF` empty, so it
  is as author-controlled as a pull request and the rule does not cover it.
- It costs consumers something now. The tag scanner is 1.10.0 and older
  versions are published, so a `version:` input of 1.7.x, 1.8.x or 1.9.0 is refused on
  every pull request (and, per the fork bullet above, on forks too). The entry
  once said it cost nothing; that stopped being true when 1.8.0 shipped.

**Enforced by:** the `pinning the scanner backward on a pull request` cases in
`action-path-validation.test.ts`. The behavioural cases drive the real step text
with the tag-scanner constant advanced one minor version and assert the
replacement matched, so deleting the constant turns them red; that advanced
copy is a synthetic future, not the file as shipped. The unmodified file is
covered by the case `refuses a 1.8.x pin on a pull request against the file as
shipped`, which pins today's real gap between the two floors. Plus a drift case tying
`VG_TAG_SCANNER_*`, the `version` input's default and
`packages/cli/package.json` to one number, a case proving the flag floor answers
first for a version below BOTH, and the bash 3.2 mirror in
`scripts/test-action-path-validation.sh`, which also asserts every constant it
hand-copied still equals the one in `action.yml`.

## The Action tag and the scanner version are two numbers, and both get bumped

1.7.1 is the first release where they came apart: the tag moved, the four npm
packages stayed at 1.7.0. They are allowed to differ, and an action-only release
is the normal reason -- publishing an identical scanner purely to keep two
strings matching burns a version through a one-way trusted-publisher path. What
is not allowed is a document telling a reader to pin one number while an example
next to it pins the other.

**The rule: when either number moves, grep for BOTH.** The places that carry one
or the other, as of 1.7.1:

- `action.yml`, the `version` input's `default:` -- the SCANNER version
- `action.yml`, `VG_TAG_SCANNER_MAJOR/MINOR/PATCH` -- the SCANNER version again,
  as the constant the pull-request rule above compares against. It moves with
  the published packages, unlike `VG_MIN_*` next to it, which moves only when
  this tag starts passing a newer flag
- `scripts/test-action-path-validation.sh`, `TAG_SCANNER_*` and `MIN_*` -- the
  bash 3.2 hand copy of both, which that script now checks against `action.yml`
  rather than trusting
- `action.yml`, the `version` input's description, which names an example
- `packages/*/package.json` (four packages) -- the scanner version
- `docs/GITHUB_ACTION.md`, the inputs table's `version` default -- the scanner
- `README.md`, the `uses: vaultcompasshq/vault-guard@vX.Y.Z` example -- the TAG
- `README.md`, the prose about which scanner a tag installs -- both numbers
- `docs/GITHUB_ACTION.md`, every `uses:` example -- the tag
- `packages/cli/src/init/templates.ts`, `ACTION_TAG` -- the tag that
  `vault-guard init` scaffolds into a generated workflow
- `CHANGELOG.md`, the release heading and any migration line naming a tag
- `bench/action-install.cjs`, `PRE_FIX_REF` -- the tag the negative control reads
  its vulnerable `action.yml` out of, which must stay the release BEFORE the fix
- `packages/cli/src/init/templates.ts`, `UPLOAD_SARIF_SHA` and
  `.github/workflows/ci.yml`'s `upload-sarif@` pin -- one decision about which
  third-party commit this project trusts, spelled in two files: the scaffold
  hands it to every consumer's repository, where it runs with that repository's
  `security-events: write`. `init.test.ts` reads the workflow and asserts the
  constant matches, so bumping one and not the other goes red rather than
  shipping a consumer a commit nobody here chose
- `bench/baseline.action-install.json`, `scannerVersion` and the case ids  -- 
  the recorded run embeds both numbers, so a scanner bump or a new `PRE_FIX_REF`
  makes the baseline stale and `--compare` says so rather than a human noticing

The init template's pin used to be `v${readCliVersion()}`, derived from the CLI
package version. An action-only release is exactly where that breaks: it would
have scaffolded `@v1.7.0`, the pre-fix Action, into every repository
initialised after the release. It is a constant now.

**Enforced by:** `init.test.ts`, which asserts three things about that constant:
the generated workflow pins it rather than anything derived from the package
version; it is not BEHIND the package version by semver ordering (equal is legal
 --  a package release moves both numbers together); and it equals `v` plus the
newest `## [X.Y.Z]` heading in `CHANGELOG.md`, which is what catches a second
action-only release that moved the tag and the changelog and forgot the
scaffold. Plus the `defaults to the scanner version this repository publishes`
case in `action-path-validation.test.ts`, which ties the `version` input's
default to `packages/cli/package.json`. The rest of the list is a grep, not a
gate.

## Testing the Action derives every step's environment and cwd from action.yml

A harness with its own table of environment variables, or its own idea of a
step's working directory, asserts a property of the harness. The two lines that
carry the whole install boundary are "which directory is npm started in" and
"which prefix does it install under", and a harness that supplies those cannot
see them go missing.

The jest suites, `bench/action-install.cjs` and the shell script's own per-step
checks (through `scripts/extract-action-step.cjs`) all read the step script, the
step's `env:` mapping and its `working-directory:` out of `action.yml` through
one shared parser, `scripts/lib/action-steps.cjs`. A second copy of that parser
would drift, and the drift would be invisible: every caller would keep passing,
each against its own idea of what the file says.

That extends to values a harness might be tempted to know for itself. The
dogfood harness reads the install PREFIX out of the install step's `env:`
mapping rather than rebuilding `<runner temp>/vault-guard-action`: hardcoded,
the record would go on reporting an install under the runner prefix even after
`action.yml` moved it into the workspace, which is the one claim that record
exists to carry.

`VG_ACTION_FILE` points both suites at a mutated copy, so any of this can be
made to fail on demand. Both files honour it; one of them not honouring it would
produce a green run against a weakened file. Verified in this change by deleting
the install step from a copy of `action.yml` (8 tests red) and by removing
`working-directory` from the run step (2 tests red). Those counts were measured
when the entry was written and have not been re-measured since the suites
changed; treat them as the shape of the check, not as a current number.

## action.yml must parse and behave on bash 3.2

macOS ships bash 3.2, and GitHub's macOS runners do too. Two bug classes here are
invisible from Linux, where the broken spelling works:

- a `=~` pattern with `{1,256}` fails to COMPILE on the BSD regex engine
  (`RE_DUP_MAX` is 255), and a pattern that fails to compile does not match, so
  every path input including the default `.` was rejected;
- `${x,,}` and `${x^^}` are bash 4.0 case expansions and are a SYNTAX ERROR on
  3.2, so a step using one fails to parse entirely. The `.github/` comparison
  needs case folding precisely because macOS filesystems are case-insensitive,
  which is what makes this the likeliest place to reach for one. `tr` instead.

**Enforced by:** `scripts/test-action-path-validation.sh`, which the
`action-path-validation` CI job runs on `macos-latest` as well as
`ubuntu-latest`. It extracts each step's run script through
`scripts/extract-action-step.cjs` and runs `"${BASH}" -n` over it, so on the
macOS runner the whole file is parsed by the bash version the claim is about.

`"${BASH}"`, never a bare `bash`. A bare name is a PATH lookup, and on a machine
with Homebrew bash ahead of `/bin` the check ran under bash 5 while the script
itself ran under 3.2 -- the one guard against bash 4 syntax performed by a bash
that accepts it. A review demonstrated it with a `;&` case fallthrough, which is
legal in 4.0, a syntax error in 3.2, and passed the gate. That is
the enforcement; the textual guards against `${x,,}` and `${x^^}` here and in
`action-path-validation.test.ts` are a faster, narrower net that only ever
catches the idioms already on the list, and they name the bug when they fire.

---

# Scanner core

The entries above cover the composite Action. The entries below cover what the
scanner itself reports. The first four were written in the change that fixed the
audit finding each one describes, and the rest in 1.9.1, so weigh them
accordingly: verify the named code and test against this text before relying on
it. In the tests named below,
`silent-passes.test.ts` is `packages/cli/src/__tests__/silent-passes.test.ts` and
`path-severity.test.ts` is `packages/core/src/utils/__tests__/path-severity.test.ts`.

## Path context is judged relative to the scan root, never on the absolute path

Test, documentation and locale context (`docs`, `doc`, `website`, `tests`,
`examples`, `fixtures`, anything ending in `test`, `*.md`) lowers a finding's
severity. The Action scans an absolute `SCAN_ROOT` and `--staged` hands the
scanner absolute paths, so a checkout that lives under a directory called
`docs` (`/home/runner/work/docs/docs`) or `loadtest` (`/tmp/loadtest/repo`)
made every file in it a docs or test file, and a vendor-shaped key or a PEM
private key in `src/config.ts` was downgraded to `low` and exited 0. Scanning
`.` did not show it, which is why it survived.

**The rule:** context is judged on the file's path relative to a root, and the
root is, for one scan target, the git work tree containing the target
(`git rev-parse --show-toplevel` run from the target, or from its directory for
a file target). A target that is not in a git work tree uses the target
directory itself (its parent for a file target). `--staged` uses the repository
root. A file outside its root contributes only its basename. So the directories
above the git work tree, or above the target directory when there is no work
tree, never count. Directories BETWEEN the root and the file do count, which is
the point: `tests/` inside the repo is still a test directory. Consequently a
scan aimed at a subdirectory of a git repository (`scan repo/docs`) is judged
from the repo root, and `docs` counts; a scan of a plain directory is judged
from that directory, so `scan docs` outside git does not count `docs`.

**Enforced by:** `contextPathFor` in `packages/core/src/utils/path-parts.ts`
(symlinks resolved on both sides), called from `applyPathAwareSeverity`
(`path-severity.ts`) and from the doc-context suppression in
`SecretScanner.scanContent`. The CLI root is `resolveContextRoot` in
`packages/cli/src/utils/scan-utils.ts`, used per target by `scanFilesAsync` and
`scanFiles` and by `fix`; `scanCommand` passes the repository root explicitly for
`--staged`; the MCP workspace scan passes the workspace root. `resolveScanRoot`
is unrelated and only picks SARIF `%SRCROOT%`; it returns the cwd for an
in-tree target and must not be used for context. Tests, in
`silent-passes.test.ts`: `directory mode, absolute target: a PEM in
src/config.ts blocks under docs/ and loadtest/`, `ancestor cwd, relative target:
scan loadtest/docs/repo from the ancestor blocks`, `ancestor cwd, git repo
target: scan loadtest/docs/repo from the ancestor blocks`, `cwd is the
filesystem root, absolute target blocks`, `a file target from an ancestor cwd
blocks`, `check with an absolute file from an ancestor cwd blocks`, `directory
mode, cwd elsewhere: an absolute target outside cwd is judged from the target`,
`--staged: a PEM private key in src/config.ts blocks when the repo path contains
docs/ and loadtest/`, `fix passes the scanner the file's own root, not the
absolute path (fix prints no severity, so the call is pinned)`, and the
counter-case `a real test directory INSIDE the scan root still downgrades a PEM
fixture`. The PEM is the discriminating rule: a vendor key would pass these with
the root logic removed, because vendor rules are no longer downgraded in any
context path. Unit level, in `path-severity.test.ts`: `does not downgrade in
src/config.ts when the ROOT path contains docs and loadtest`, `still downgrades
a real tests/ directory inside the root`, `uses only the basename for a file
outside the root`.

**Scope:** the rule applies whenever a root is passed, which the CLI and MCP
always do. Library callers of `applyPathAwareSeverity` or `SecretScanner.scan`
should pass one too.

`scanFileListAsync` used to default its root to the process cwd, which is the
same ancestor bug for any caller that omitted `pathRoot`. From 1.9.1 an omitted
root is each file's own git work tree (memoised per directory), through
`resolveContextRoot`; `scan-file-list-path-root.test.ts` (`judges context from
the repository, not from an ancestor cwd`) pins it. `scanFiles` (sync) has no
production caller.

## A binary skip needs the extension and the bytes to agree

History. `--staged` reads each blob from the index. A blob containing a NUL
byte was skipped with a bare `return`: nothing recorded, nothing raised, so a
`.ts` file holding a key and one NUL byte printed "No secrets found" and
exited 0. Refusing such blobs (exit 2) was tried and rejected, because it broke
ordinary commits of fonts, images and lockfiles whose extension is not on the
binary list. Until 1.10.0 the skip that replaced it was by extension only, so
a text file named `credentials.png` or `dump.bin` was skipped unread in every
mode (design 2026-10-17, section 1.3). Until 1.9.1 it was also silent; from
1.9.1 it was counted (`run.binary_files_skipped`, and `run.type_filtered_files`
for the walk's type filter on a plain directory run).

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
scanTrackedCopies (content-source.ts); `isBinaryFile` and `BINARY_EXTENSIONS`
are deleted, and `shouldIgnoreFile` (file-utils.ts) no longer lists any binary
extension. Tests: `binary-type.test.ts` (U1 `%s signature %i: the minimal
valid header confirms` and `... its first signature byte flipped does not
confirm`, U2 `the excluded set is never a candidate`, U15 `R4 per signature
kind`, U3 `the window edge in the declared-label decode`);
`binary-content-agreement.test.ts`, one `describe` per fixture of the
2026-10-17 design's section 11.1, by their titles: `A1: config/credentials.mov
holding a key is scanned in every mode`, `A2: credentials.png holding a key is
scanned`, `A3: the extension is compared case-insensitively`, `A4: dump.bin of
UTF-8 text with no NUL is scanned`, `A21: dump.bin of NUL-separated records
(the env -0 shape) is scanned`, `A24: dump.bin in Windows-1252 (the set >
dump.bin shape) is scanned`, `A25: a printable signature with only invalid
UTF-8 after it is scanned`, `A22: a declared working-tree-encoding that
decodes means text`, `A5: a UTF-16LE notes.bin with a BOM is scanned`, `A6:
song.ogg of OggS followed by ASCII text is scanned`, `A7: the documented
boundaries, pinned`, `A8: a 40 MiB real-header .mp4 is skipped at any size`,
`A9: anything scanned as text over 32 MiB is exit 2, and the first stderr line
names it`, `A10: the LFS shape, with a local filter driver`, `A11: copies are
classified per copy`, `A12: no attribute is consulted by the classifier`, `U12:
a tracked image missing from the working tree`, `U17: skipBinary false scans
every file as text, with no classification` and `U18: named tracked symlinks,
each copy judged by the name of the bytes it holds`; `blob-head-read.test.ts` (U5); the U1 call-count test in
`blob-content-source.test.ts` (U6, with images and videos); `hook-environment.test.ts`
(`U14 (design 2026-10-17): --staged head reads in a commit -a hook use the hook's
index`); in `silent-passes.test.ts`, `a staged .ts file with a key and one NUL
byte exits 1 (a finding), not 0`, `a staged .woff2 containing a NUL does not exit
2` (now also asserting the font count), `a staged .png too short for the 8-byte
PNG signature is a mismatch, scanned as text, and still exits 0` and `a staged
.png with the full signature is skipped` (U11); and, for the MCP workspace scan,
`binary-and-budget.test.ts` in packages/mcp (U10, U16).

**Text is decoded in one place, and a BOM is honoured.** Skipping nothing on
content only helps if the content is read as what it is. Read as UTF-8, a UTF-16
file (PowerShell 5 `>` redirection writes UTF-16LE with a BOM) is garbage with a
NUL between every character, so a key in it never matched and the run passed. Every
path that turns bytes into scanned text now goes through `decodeTextBuffer` and
`packages/core/src/utils/text-decode.ts`: `SecretScanner.scan`
(directory and pull-request mode), `scanTextFileAsync` and `scanTextFileSync`,
and `readGitIndexFile` (`--staged`). `FF FE` decodes as UTF-16LE, `FE FF` as UTF-16BE,
`EF BB BF` is stripped, and the BOM is always removed so line and column numbers
describe the decoded text. Tests: `text-decode.test.ts` (`decodes UTF-16LE with a
BOM and drops the BOM`, `decodes UTF-16BE with a BOM and drops the BOM`, `strips a
UTF-8 BOM`, `SecretScanner.scan finds it in %s and reports line 2`, `scanTextFileSync
finds it in %s`, `scanTextFileAsync finds it in %s at line 2`)
and, in `silent-passes.test.ts`, `directory mode finds a key in a UTF-16LE
notes.txt` and its UTF-16BE, `src/a.ts` and `--staged` variants.

**Scope: supported encodings.** The decoder handles UTF-8 and UTF-16 with a BOM.
Tracked files inside a git repository are read from their blobs, so
`working-tree-encoding` cannot turn one into BOM-less UTF-16. The BOM-only
rule still governs untracked files and files outside git. The disk copy of
a tracked file that is scanned in addition to its blob is decoded by its
BOM first, then by its declared `working-tree-encoding` through an explicit
label map; an encoding outside the map is scanned as UTF-8 and reported as
a coverage line.
Text in any other encoding is read as UTF-8. Legacy encodings such as Latin-1 and
Shift-JIS keep ASCII key material intact, so key-shaped strings in them are still
matched. UTF-16 is recognised by its BOM only: guessing it from NUL density would
also fire on real binary blobs, so that is deliberately not done. The vscode
extension scans the text VS Code already decoded and does not use the shared
decoder.

## Vendor-anchored rules are not downgraded in docs or markdown

`DOCS_VENDOR_DOWNGRADE_IDS` used to drop Anthropic, OpenAI, Stripe, AWS, GitHub,
Slack and other vendor rules to `low` in any `.md`, `.mdx` or docs directory. A
live key pasted into `CLAUDE.md` or `AGENTS.md` (the files people paste into)
passed the gate. Operator ruling: a live provider key is a live key wherever it
sits.

**The rule:** docs and test paths downgrade only
`LOW_PRECISION_PATH_DOWNGRADE_IDS` (`password-in-code`, `api-key-generic`,
`secret-generic`, `bearer-token`, the four connection-string rules,
`ssh-private-key`, `jwt-token`). There is no vendor list to downgrade from. One
further ruling: `ssh-private-key` is downgraded on test and fixture paths
(throwaway PEMs live there) but NOT on documentation, markdown or locale paths.
A locale path is one with a `locales`, `locale`, `translations`, `translation`,
`i18n`, `lang` or `langs` directory on it; a two-letter file name alone is not.
On a locale path only `password-in-code`, `api-key-generic`, `secret-generic`
and `bearer-token` are downgraded; the connection-string rules,
`ssh-private-key` and `jwt-token` keep their severity. That ruling is only as good as the body check that
decides a hit is a key rather than prose naming the header
(`isPemHeaderWithoutBody`, `packages/core/src/utils/placeholder.ts`). The rule
reports a hit only when, in the text between the header and the END marker that
closes it (or the next BEGIN, or 8192 characters when neither exists), some line
qualifies. A line qualifies when, after each whitespace-separated token has the
surrounding comment, string-literal and list syntax peeled off by
`cleanPemToken` (same file; that function is the complete list), EVERY token
is base64 characters (with optional `=` padding), at least one token is 40
or more characters with a lowercase letter, an uppercase letter and a digit or
`+` or `/`, and those qualifying tokens are at least 85 percent of the line's
characters. Newlines written as `\n`, `\r\n`, XML character references
(`&#xA;`, `&#10;`, `&#13;`), `<br>` tags or `\u000a` / `\u000d` split lines. The END marker is not required.

This is a heuristic, not a proof. The earlier text here ("a real key body line
essentially always passes") was not true of the previous rule, and the rewrite
replaced it, with the shapes it now handles pinned as tests. The corpus that pins
both halves, the shapes that must be found and the
look-alikes that must not (a header beside prose, an ssh public key line, a
certificate block that follows a mention, a hex dump), is
`pem-body-corpus.test.ts` (core). A change to the heuristic has to keep both
halves green. A documentation line that is itself a lone 40+ character
mixed-case base64-looking token right after a header counts as a body.

**Enforced by:** `packages/core/src/utils/path-downgrade-ids.ts` no longer
exports a docs vendor set and defines `LOCALE_PATH_DOWNGRADE_IDS`, the
four rules a locale path may downgrade; `applyPathAwareSeverity`
downgrades a match when any context the path is in allows its rule: the
low-precision set on a test path, that set without `ssh-private-key`
(`DOCS_EXEMPT_IDS`) on a documentation path, and
`LOCALE_PATH_DOWNGRADE_IDS` on a locale path. Tests:
`silent-passes.test.ts` `a vendor key in NOTES.md still blocks`, `a vendor key in
CLAUDE.md still blocks`, `a vendor key in docs/x.md still blocks`, `a full-body
PEM private key in CLAUDE.md still blocks`, `a full-body PEM private key in
docs/runbook.md still blocks`, and the counter-cases `a PEM under tests/fixtures
still downgrades` and `a generic password assignment in docs still downgrades to
low`; `path-severity.test.ts` `keeps an anthropic key at critical in NOTES.md`
(and the CLAUDE.md, docs/x.md and website/page.mdx variants), `keeps a full-body
PEM private key at critical in CLAUDE.md` (and docs/runbook.md), `still
downgrades a PEM under a tests/ fixture directory` and `still downgrades a
generic api-key match in docs` (its "full-body PEM" cases use a synthetic match
with no body, so they pin the severity rule and not the body check); and, in
`pem-body-prose.test.ts` (core),
`prose that merely names the header in docs/setup.md is not critical` (and the
README.md and CLAUDE.md variants), `a copy of the CHANGELOG paragraph about the
PGP header is not critical`, `a real full-body PEM in docs/runbook.md still
blocks` (and CLAUDE.md), `a key embedded in JSON with escaped newlines still
blocks`, `a lowercase-only or letters-only 40+ run is not a body`, `a
whitespace-separated sentence is not a body`; `path-severity.test.ts` (`U14:
two-letter basenames outside a locale directory keep full severity`, `U14:
DSN, PEM and JWT rules are never downgraded on a locale path`, `U14: a PEM
under docs/locales is not downgraded`) and `dogfood-fp.test.ts` (`does not
treat src/en.json as a locale path`).

## Exit 1 means findings only

`scan` returned 1 for an invalid config, a missing git repository, an invalid
`--fail-on`, and an unexpected fatal error. Wrappers read 1 as "secrets found"
and 2 as "could not run"; a bad flag reported as a leak sends someone hunting
for a secret that is not there.

**The rule:** exit 1 is "the scan ran and found something at or above the gate".
Anything that is not a verdict on the tree is exit 2 (`COULD_NOT_RUN_EXIT`).

**Enforced by:** `COULD_NOT_RUN_EXIT` at the former `return 1` sites in
`scanCommand` (`packages/cli/src/commands/scan.ts`; there are seven returns of
the constant now, plus the literal 2 for a git failure and the shared
`INCOMPLETE_SCAN_EXIT`, all of them 2). Commander usage errors and
escaped throws are covered by `exitOverride` and `handleFatalError` in
`packages/cli/src/cli.ts`, which `cli-entry.ts` uses as its catch handler, and
an unknown `--format` value is rejected before scanning. Tests, in
`silent-passes.test.ts`: `an invalid config exits 2`, `--staged outside a git
repository exits 2`, `an invalid --fail-on exits 2`, `a fatal error exits 2`; in
`packages/cli/src/__tests__/integration/exit-codes-usage.test.ts`: `scan .
--bogus exits 2`, `an unknown --format value exits 2 instead of falling back to
text`, `a thrown non-ConfigError exits 2`, and the boundaries `scan --help exits
0`, `--version exits 0` and `-h, --help and the help subcommand exit 0 and print
usage`.

**Known gap:** the `init` command still sets exit 1 for an unknown `--manager`.
It is not a scan verdict, but it does not follow the rule either. `install-hook`
and the proxy's `--max-rpm` validation and errors also exit 1. The
`exit-codes-usage` suite needs a built `dist` and is skipped on Windows.

## Directory and pull-request mode fail closed, with a declared way out

Through 1.9.0 only `--staged` exited 2 over a file it could not read or whose
scan blew the budget. A directory or pull-request run exited 0 and printed
"No secrets found" over it, and `check a.ts missing.ts` exited 0 on the strength
of the one file that existed (only the all-missing case exited 2).

**The rule:** on every path (staged, directory, pull-request), a file that was
selected for scanning and could not be read or examined on disk (in pull-request
mode that includes a tracked file under a directory that cannot be entered, or
missing from the checkout), a file over the size limit, a scan that exceeded the
per-file budget, and (for the `check` command, which takes several paths) a
named path that does not exist each make the run exit 2,
with the output still emitted. In every output format (text, JSON, SARIF) the
message goes to stderr and names the file or target and the reason. For a file
selected from a directory or pull-request scan it also gives the `ignore.paths`
entry that would exclude it, printed as a JSON string that can be pasted into
the config as written (an entry containing a question mark carries a sentence
saying the question mark matches any single character there, so it may also
exclude a similarly named file); on a pull-request run it says the entry must be
on the base ref, because a change in the pull request is only a proposal. For a
file named explicitly on the command line, which the ignore list never filters,
it says to check the path or stop passing it. The same holds when nothing else
was scanned: the run still prints this message and a valid JSON or SARIF
document. The JSON run object carries the same facts in `run.unscannable` (file,
kind, and the exclude when there is one). In SARIF the run's invocation has
`executionSuccessful: false` and one error-level tool execution notification per
file, and the run properties carry the count as `unscannable_files` (the
per-file detail is in the notifications); a complete run never carries a failed
invocation. The MCP `scan_workspace` tool returns the same: JSON with
`unscannable_files` and `unscannable`, SARIF with `unscannable_files` and the
notifications. A file excluded through the config's `ignore` list is a DECLARED skip:
it is never opened, the run exits on the findings alone, and the number is
stated (`run.config_ignored_files` in JSON and SARIF; `Excluded by config
ignore: N` in text when N is not zero).

**The limits.** A file is read and scanned whole up to 32 MiB
(`MAX_SCAN_FILE_BYTES` in core, the one constant shared by directory mode, the
MCP scan and `--staged`, where it is applied to the raw blob size in the index
through the `git cat-file` output limit, which `readGitIndexFile` turns into the
same `FileTooLargeError` a file on disk produces). Above it the file is
unscannable: exit 2 with the same wording and exclude entry in every mode, never
partly scanned. `scanTextFileAsync` and
`scanTextFileSync` throw above it. `DEFAULT_SCAN_BUDGET_MS` is 5000 ms of CPU
time per copy, checked after the scan returns; a copy over it is scanned once
more from the same text and is untrusted only when the second pass is over
too, or the first was over twice the budget (the regex engine cannot be
interrupted), so it refuses to TRUST a slow result rather than bounding time.
There is no total-run budget. A copy confirmed binary and the walk's name
filter are removed before either number applies; a binary extension whose
bytes are text is subject to both.

**Where the exclude is read from.** `ignore.paths` and `ignore.patterns` in
`.vault-guard.json`, merged in `scanCommand` and matched with gitignore syntax
relative to the scanned directory (to the repository root for `--staged`). On a
pull-request run (`--trust-base`) the config comes from the BASE ref, so a pull
request cannot add its own exclude; in plain directory mode and `--staged` it is
the config of the tree being scanned, which is the user's own. An explicit file
target is never filtered by it.

**Enforced by:** `INCOMPLETE_SCAN_EXIT`, `scanIncomplete` and `reportIncomplete`
in `scanCommand`, `recordUnusableTarget` and `recordTooLarge` in
`scan-utils.ts`, the `unreadable` list of `getPullRequestFilesToScan`,
`excludePatternFor` and `formatExcludeEntry`; `directory-pr-fail-closed.test.ts`
(several targets with one missing, an unreadable file in directory and
pull-request mode, a tracked file under a directory that cannot be entered, a
head-tree file missing on disk, a scan that blows the budget through a mocked
clock, the declared exclude as a counted exit-0 skip, stderr in JSON and SARIF,
`run.unscannable`, SARIF `executionSuccessful` false in directory and
pull-request mode and absent on a complete run, a file target after a directory
target not recording the directory's missing file twice);
`oversized-files.test.ts` (a key at the top of an 11 MiB file,
a secret on a line over 1 MiB, a 33 MiB file refused with the hint, the same
file declared, an oversized file as the only candidate in text, JSON and SARIF,
a UTF-16 blob under the limit scanned when staged, and a staged 33 MiB blob
reported as too large with the exclude, in JSON and SARIF); `exclude-hint.test.ts`
(the printed entry, pasted as written, excludes the named file and not an
unrelated sibling for names with spaces, brackets, star, backslash, hash and
bang; a star entry does not exclude a sibling an unescaped star would match;
for a question mark the test states that a decoy differing at that
position is excluded too, and that the note says so); `directory-scan-unreadable.test.ts` (flipped from
exit 0 to exit 2); the MCP `server.test.ts` (`scan_workspace carries files it
did not scan into the embedded json and sarif documents`).

## JSON and SARIF file paths use forward slashes on every OS

A `file` value in JSON output and a SARIF artifact uri are POSIX-style on
Windows too (`src/a.ts`, never `src\a.ts`), because consumers match them against
repository paths and baselines fingerprint them. A POSIX filename that really
contains a backslash is rewritten to a different path by this conversion, which
is a known cost.

**Enforced by:** `toForwardSlashes` in `packages/core/src/scan-output.ts`, called
from the path relativiser; `packages/core/src/scanners/__tests__/scan-output.test.ts`
(the forward-slash cases; the comment beside them that says "platform-native" is
stale). `silent-passes.test.ts` reads findings from JSON for the same reason.

## Tracked files are scanned whatever `.gitignore` says, in every mode

Through 1.9.1 a plain directory scan dropped any file `.gitignore` matched, even
one already committed, while pull-request mode scanned it: a committed `.env`
was clean on push and blocking on a pull request. `.gitignore` governs what git
will add and says nothing about a file already committed.

**The rule:** inside a git work tree a plain directory scan's file set is the
tracked files plus untracked files that `.gitignore` does not exclude. The
tracked half is built by `getPullRequestFilesToScan`, the same function
pull-request mode uses, so vendored names are anchored to the scan root for
tracked files in both modes. Whether the target is inside git is decided by a
`.git` entry at or above it, never by asking git; once one is found, any git
failure is exit 2 quoting git, never a fall back to the walk. A tracked path
that `lstat` cannot examine is counted as missing only when git lists it as
deleted or skip-worktree AND the errno is ENOENT or ENOTDIR; anything else is
exit 2. `--staged` reads the index and pull-request mode the HEAD tree, and
neither consults `.gitignore`. Outside git the walk and the gitignore tester run
as before.

**Enforced by:** `getFilesToScanAsync`, `getGitFilesToScan` and `collectGitPaths`
in `packages/core/src/utils/file-utils.ts`; the `GitError` branch at the end of
`scanCommand`; `packages/cli/src/__tests__/integration/plain-git-file-set.test.ts`
(`T1: a tracked, gitignored .env is scanned and counted`, `T3: plain and
--trust-base scan the same path set over one committed tree`, `T9a/b: a .git is
present and git refuses: exit 2, git quoted`, `T18a: a tracked file under a
directory that cannot be entered exits 2`, and the rest of that file); the two
flipped before-state cases in `trust-base.test.ts` (`without the flag a
head-added .gitignore no longer mutes a tracked file`, `without the flag a
committed src/vendor is scanned`). Each named test was run against its
mutation and went red (design doc, section 8).

**Known gap:** the MCP `scan_workspace` tool gets the same file set, but no
test drives it inside a git repository.

## A pull-request run never takes its baseline from the head

Under `--trust-base` the baseline, like the config, comes from the base ref,
including its `entries` list. A head that adds an entry for its own new finding
produces the proposal line `baseline changed in this pull request (1 baseline
entry added)` and the finding still blocks.

**Enforced by:** `loadTrustedControls` in `packages/core/src/trust-base.ts`
(`baseline` and `baselineEntries` come from the base side only, and
`summariseBaselineChange` counts entries when present); the `controls` branch of
`baselineLoad` in `scanCommand`; `baseline-writer.test.ts` (`T11: a pull request
cannot baseline its own new finding`, red when the head baseline is read);
`baseline-entries.test.ts` (the `--trust-base` halves of T12 and T14, red when
the base-ref path is left on the positional set).

## Only `vault-guard baseline --write` writes the baseline

`scan`, `check`, `init`, the pre-commit hook and the Action never write
`.vault-guard.baseline.json`. The writer accepts only findings that would block,
in files the OUTER repository's own index tracks (never a file of a submodule
or of an untracked nested repository, which are scanned but are another
repository's history), refuses critical findings without `--include-critical`,
writes at the root of the repository the target is in and refuses from any
other cwd, keeps entries outside a scoped path untouched, and writes nothing
when the scan was incomplete.

**Enforced by:** `baselineCommand` in `packages/cli/src/commands/baseline.ts`
(the only `writeFileSync` of the baseline in the CLI); `outerTracked` in
`collectGitPaths` (`packages/core/src/utils/file-utils.ts`), which is what
fills `PlainFileSetInfo.trackedFiles`; `baseline-writer.test.ts` (`T10b: scan
never creates the baseline file`, `T16`, `T20`, `T24: an untracked file is never
written into the baseline`, `T24: files tracked only by an untracked nested
repository are never written`, `N1`, `N2: a scoped --write keeps entries
outside the scanned path`); `init.test.ts` (`prints a one-line baseline hint and
never writes a baseline`). T10b is mutation-tested: an independent reviewer
called the writer at the top of `scanCommand` and `T10b: scan never creates the
baseline file` went red. The nested-repository T24 case went red when every
listed tracked path was put back into `trackedFiles`.

## Pull-request mode does not scan submodule contents

A plain scan inside git recurses into a checked-out submodule and applies the
same rule there. Pull-request mode scans the HEAD tree only, where a submodule is
a gitlink with no content, so a key inside a submodule is not scanned under
`--trust-base`. Left as is on purpose (design question 6): scanning a submodule
in pull-request mode raises its own question of which base ref applies.

**Enforced by:** `listHeadTreeFiles` in `packages/core/src/trust-base.ts`
(gitlinks never enter the list); `plain-git-file-set.test.ts` (`T7a: a key
inside a checked-out submodule is found`) for the plain side. No test pins the
pull-request side.

## Tracked content comes from git, never through a checkout transform

Inside a git repository a tracked file's content is read from its blob by
object id: the HEAD tree entry under `--trust-base`, the index (stage 0)
entry in a plain scan and under `--staged`. `.gitattributes` transforms
(`working-tree-encoding`, `eol`, `filter`, `ident`) therefore cannot change
what is judged. The disk copy of a tracked file is scanned as well when
`git status` says it differs from that blob, when the file has a `filter`
attribute, or, in a plain scan, when the index marks it assume-unchanged
or skip-worktree and it is present on disk; it can add findings and never
removes one. A disk copy's BOM always decides its encoding; otherwise a
declared `working-tree-encoding` is used only through an explicit label
map, and an unsupported one is a reported coverage gap on that copy, not
a failure. Untracked files have no blob and are read from disk, so
BOM-less UTF-16 in an untracked file is still not detected. Blob reads use
at most two `git cat-file` processes per repository, and a blob's bytes are
released once the last path that reads it has been scanned, so memory is
bounded by the read window, not by the total tracked size. A git failure while
reading tracked content, or a blob missing from the object store, is exit
2 naming the file or quoting git; there is no fall back to the disk copy
alone.

**Enforced by:** `blob-reader.ts` and the content source in
`scan-utils.ts`; `blob-content-source.test.ts` (`F1: a head-side
working-tree-encoding does not hide a key under --trust-base`, `F2: the same
attribute does not hide a key in a plain scan`, `F6: a staged key whose
working copy was reverted is found by a plain scan`, `F5: an unstaged edit
that adds a key is found and labelled worktree`, `F5: under --trust-base a
disk copy edited after checkout is scanned and labelled worktree`, `F7: a
key behind a filter
driver is found from the working-tree copy`, `F8: a missing blob is exit 2
naming the file`, `F9: a failing cat-file is exit 2 quoting git`, `F18: a
key in a skip-worktree or assume-unchanged file is found from disk`, `F21:
an unsupported working-tree encoding is a coverage line, not exit 2`, `U1:
blob reads use at most two cat-file processes per repository`, `U21: a BOM
decides a disk copy's encoding before its declared label`);
`blob-reader.test.ts` (`holds no more blobs than the read window at once,
and none after the run`).

## Reading the blob does not move a fingerprint for an untransformed file

For a tracked file whose checkout applies no transform, the positional
fingerprint, the content fingerprint and the header-only `file_digest` are
the same whether computed from the blob or from the disk copy. Where a
transform applies, the baseline writer and reader both take `file_digest`
from the bytes kept from the scan, keyed by path and source, never from a
fresh read.

**Enforced by:** `blob-content-source.test.ts` (`U9: fingerprints from the
blob equal fingerprints from disk for an untransformed tree`, `U10: a
header-only entry written on a CRLF checkout matches on the next scan`);
`bench/real-repos/2026-10-12-1.10.0.json` (fingerprint sets per
repository).

## `.gitattributes` is a pull-request control file

Under `--trust-base` any added, removed, modified or retyped
`.gitattributes`, at any depth, between the base ref and HEAD is reported
as `Proposed, not applied: .gitattributes changed in this pull request`
with up to three paths, in text, JSON `trustBase.proposals` and SARIF
notifications. It never changes the exit code. Content is read from blobs,
so the head's attributes cannot change what was scanned.

**Enforced by:** `trust-base.ts` (the attributes diff-tree);
`trust-base.test.ts` (`F1: a head-side .gitattributes change is reported as
a proposal`, `F3: a nested .gitattributes change is reported`, `U13: a
symlinked .gitattributes at the head is reported as a shape change`, `U13:
an attributes proposal does not change the exit code`).

## Control files on disk are never read or written through a link

`.vault-guard.baseline.json`, `.vault-guard.json` and
`.vault-guard.local.json` are opened without following a symlink and must
be regular files; anything else, a dangling link included, is refused
naming the path: exit 2 from `scan` and `baseline` before any file is
scanned, exit 1 from `config validate`. No existence check runs first, so
a refused link stops the search walk instead of letting a parent
directory's file take over. `baseline --write` refuses a non-regular file
at its output path and writes by temporary file and rename, so it never
writes through a link. No `JSON.parse` message reaches a warning, JSON,
SARIF or `config validate` output; a baseline parse failure says `could
not be parsed as JSON` and the path, a config parse failure adds only a
line and column.

**Enforced by:** `readRegularFileNoFollow` in core; `baseline-writer.test.ts`
(`F10: baseline --write refuses a symlinked baseline and leaves the target
untouched`, `F10b: baseline --write replaces a link planted before the
rename instead of writing through it`, `F12: baseline --write refuses a
dangling symlink`); `baseline-symlink.test.ts` (`F11: scan refuses a
symlinked baseline with exit 2 and prints none of the target`, `F13: scan
refuses a symlinked config with exit 2`, `F14: a baseline parse error never
echoes file content`, `F19: a dangling config or baseline link is refused,
not treated as absent`); `config-validate.test.ts` (`F20: config validate
refuses a symlinked config and echoes none of it`); `read-no-follow.test.ts`
(`U15: a symlink fails at open, not at a separate lstat`).

## The hook installer never writes through a link

Every read of a hook file the installer may write (`.husky/pre-commit`, the
native `pre-commit` and `pre-commit.cmd`, `lefthook-local.yml`,
`.pre-commit-config.yaml`), in the installer and in `init`'s plan alike,
goes through the no-follow reader, and every write, create or append, goes
through the temporary-file-and-rename writer, keeping the file mode. A
link, a dangling one included, or a hook directory that is itself a link,
fails that installer step with a message naming the path and changes
nothing; `init` reports it as a `linked_hook` conflict and writes nothing.

**Enforced by:** `readHookFile` and `writeFileAtomically` in
`packages/core/src/scanners/pre-commit-hook.ts`, and `foreignHookConflict`
in `packages/cli/src/commands/init.ts`;
`pre-commit-hook-symlink.test.ts` (one link-to-an-outside-file case and one
dangling-link case per write site, and `a husky directory that is itself a
link is refused`); `init.test.ts` (a dangling and an outside link per
manager, for example `a dangling link at .husky/pre-commit is a linked_hook
conflict and nothing is written through it`).

## File-set git calls run with a clean git environment; `--staged` does not

Every git call that builds the plain or pull-request file set or reads its
content, for the outer repository as well as any submodule or nested
repository, runs with git's local-repository variables removed
(`GIT_INDEX_FILE`, `GIT_DIR`, `GIT_WORK_TREE` and the rest of `git rev-parse
--local-env-vars`, except `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`,
which carry configuration such as `safe.directory`) and
`GIT_OPTIONAL_LOCKS=0`, and with `GIT_NO_REPLACE_OBJECTS=1` so a
`refs/replace` substitute never stands in for a listed object. `--staged`
keeps the inherited environment for
every git call, `cat-file` included, because in a hook the inherited index
is what will be committed and a repository reached through `GIT_DIR` is
only reachable that way.

**Enforced by:** `cleanGitEnv` in core, and the blob reader's `env`
parameter; `hook-environment.test.ts` (`F16: a plain scan from a pre-commit
hook reads a submodule's own index`, `F17: a hook in one repository that
scans another lists the other repository through its own index`, which
pins the outer-listing rule with no submodule involved, `U17: --staged in
a commit -a hook still reads the hook's index`, `U20: --staged in a
GIT_DIR-only repository reads blobs through GIT_DIR`); `git-env.test.ts`
(`U16: the stripped list covers git rev-parse --local-env-vars except the
two config variables`).

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
collector the walk and scan paths write text-format lines to (`warn` in
`ScanOptions`, and the `warn` parameter of `getFilesToScanAsync`). Tests, in
`incomplete-first-line.test.ts`: `A18: the upgrade note is dropped on exit 2,
and every advisory line follows INCOMPLETE`, `A19: the control, with nothing
unscannable`, `A20 (a): an exit 2 reached after the scan with findings in hand
prints no note`, `A23: progress on a pipe`, `A23b: progress on a terminal`,
`A26: walk-time warnings outside git follow the INCOMPLETE block` and `A27:
path-not-found and invalid-path lines follow the INCOMPLETE block`; in
`scan-budget-retime.test.ts`, `A20 (b): the baseline readBytes seam throwing
after the scan prints no note, exit 2`; `report-incomplete.test.ts` (U9); and
`scan-clock.test.ts` in core (`the scan clock decision`, `a scan emits no
process warning`). Each asserts on stderr after the same
control-character and non-ASCII stripping the umbrella applies, so the
red-cross prefix does not matter; the first line then begins with
INCOMPLETE: after optional whitespace.

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

The per-thread clock is used on the Node lines recorded in
`THREAD_CPU_STABLE_NODE` (packages/core/src/utils/scan-clock.ts): 22.19.0 and
later on 22, 23.9.0 and later on 23, and every release of 24, 25 and 26, from
the Node API documentation of `process.threadCpuUsage` ("Added in: v23.9.0,
v22.19.0", no stability marking). Node 22.0.0 to 22.18.x, the low end of
`engines`, takes the fallback.

Enforced by: scanFileContent in content-source.ts and its clock seam
(scan-clock.ts); the CLI and MCP read the decision from the outcome and
compare nothing themselves. Tests: `scan-budget-retime.test.ts` in core and in
the CLI (`A13: 6000 then 100 is trusted on its findings, re-timed, no
INCOMPLETE`, `A14: 6000 then 6000 is exit 2, the reason says twice, first_ms
6000`, `A15: 12000 on the first pass is exit 2 with the scanner called once for
that copy`, `A16: a second pass with one extra match is exit 2, results
differed`, `A17a: per-thread, wall 10 s and CPU 50 ms: exit 0 on findings, no
re-time`, `A17b: fallback, process CPU 12 s and wall 10 s twice: exit 2,
elapsed_ms 10000, never 12000`, `U13: an ignore-line directive during a
re-time is counted once`), and the MCP `binary-and-budget.test.ts` (`the
budget re-time applies through the same seam`).
