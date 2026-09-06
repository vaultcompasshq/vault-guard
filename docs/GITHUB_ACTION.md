# GitHub Action (`action.yml`)

The composite action in the **repository root** runs the published
`@vaultcompass/vault-guard` CLI via `npx` after Node 22 is installed.

## Requirements

1. **`actions/checkout`** of your repository **before** this action (the action
   does not check out your code; it only installs Node and runs `npx`).
2. A **published** `@vaultcompass/vault-guard` version matching the `version`
   input (default `latest`).

## Inputs

| Input           | Default                     | Description |
|----------------|-----------------------------|-------------|
| `version`      | `latest`                    | npm dist-tag or semver for `@vaultcompass/vault-guard`. |
| `path`         | `.`                         | Subdirectory to scan, relative to workspace root. |
| `format`       | `sarif`                     | `sarif`, `json`, or `text`. |
| `sarif-output` | `vault-guard-results.sarif` | Output file path **under** `GITHUB_WORKSPACE`. |
| `trust-base`   | `auto`                      | Pull-request mode. `auto` passes `--trust-base origin/$GITHUB_BASE_REF` when that variable is set; any other value is used as the ref. There is deliberately no value that turns it off. |

## Pull requests

**On a pull-request run every control input comes from the base ref, and the
head tree is what gets scanned.** `.vault-guard.json`,
`.vault-guard.local.json` and `.vault-guard.baseline.json` are read from the
base with `git show`; a version of them that the pull request changed is
reported as a proposal and is not applied. Without this a pull request could
turn the scanner off in the same commit that carried the secret.

`auto` fires on exactly the pull-request events, because `GITHUB_BASE_REF` is
set only there. The ref reaches the CLI through the step's `env` block and a
bash array, never by substituting a `${{ }}` expression into a `run` body:
expressions are textual substitution performed before the shell parses the
script, which is how a crafted branch name would become a command.

**There is no `trust-base` value that turns pull-request mode off**, and that is
a decision rather than an omission. On a same-repo `pull_request` event GitHub
runs the workflow file from the pull request head, so an off switch on this
input would be settable by the pull request it exists to judge: the boundary
would ship with its own off switch, sitting on the untrusted side. Base-ref
judging is the floor. The only kind of change this input accepts is a tightening
(an explicit ref), and the human-approval tightening lives in repository
settings, where a pull request cannot write it. `trust-base: off` was accepted
in a pre-release build and is now refused by name, with an error saying so.

If you are not ready to add `fetch-depth: 0` to your checkout, stay pinned to
`vaultcompasshq/vault-guard@v1.6.0` until you are. That is a deliberate choice a
maintainer makes on a protected branch, which is exactly what an off switch in a
PR-controlled file is not.

Two requirements on the calling workflow, and neither can be met from inside
this action:

1. **`fetch-depth: 0` on `actions/checkout`.** The base branch has to exist
   locally for the base ref to resolve. Without it the scan exits 2 with a line
   naming the ref and saying to fetch the base. It does not fall back to
   trusting the pull request.

2. **The workflow file has to be protected deliberately.** On a same-repo
   `pull_request` event GitHub runs the workflow from the pull request head, so
   the job running this gate is as editable as any other file in the branch, and
   no flag can detect a job the pull request deleted. Make the check required by
   name in branch protection, or put the gate in a reusable workflow on a
   protected ref and call it. See
   [GITHUB_BRANCH_PROTECTION.md](./GITHUB_BRANCH_PROTECTION.md).

Requiring a human to approve a change to the config or the baseline is
repository configuration rather than an action input: a `CODEOWNERS` entry for
those paths plus required code-owner review. There is no in-repo knob for it on
purpose, because a knob that can relax the gate and lives in the file the pull
request controls is not a control at all.

```yaml
on: pull_request

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - uses: vaultcompasshq/vault-guard@v1.7.0
        with:
          format: sarif
```

## Output

| Output          | Description |
|----------------|-------------|
| `results-file` | Absolute path to the written SARIF/JSON file. |

## Example: fail the job on secrets

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
- uses: vaultcompasshq/vault-guard@v1.7.0
  id: vg
  with:
    version: latest
    format: text
    sarif-output: vault-guard.txt
```

When `vault-guard` exits non-zero, the step fails and the job turns red. No
extra wiring required.

## SARIF upload

Use `format: sarif` and pipe output is already written to disk by the action
step (`tee`). Chain `github/codeql-action/upload-sarif` as in the root
`README.md` example.

### Exit 2 leaves the SARIF file empty

Exit 2 means the run could not establish something it needed and scanned
nothing: a base ref it cannot read, a base config that fails validation, a
staged file it cannot read. There is deliberately no SARIF document in that
case, because a document reporting zero results would be a claim the run did
not earn. The action still `tee`s stdout, so the file exists and is **empty**.

An `upload-sarif` step with `if: always()` then fails on that empty file, and
its error is the one people read first, sitting on top of the real message
further up the log. Guard the upload on the file having content:

```yaml
      - uses: vaultcompasshq/vault-guard@v1.7.0
        id: vg
        with:
          format: sarif
      - name: Check for a SARIF document
        id: sarif
        if: always()
        shell: bash
        env:
          SARIF_FILE: ${{ steps.vg.outputs.results-file }}
        run: |
          set -euo pipefail
          if [[ -s "${SARIF_FILE}" ]]; then
            echo "present=true" >> "${GITHUB_OUTPUT}"
          else
            echo "present=false" >> "${GITHUB_OUTPUT}"
            echo "::notice::vault-guard wrote no SARIF document; see the scan step for why."
          fi
      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.sarif.outputs.present == 'true'
        with:
          sarif_file: ${{ steps.vg.outputs.results-file }}
```

The step output reaches the shell through `env` rather than being substituted
into the `run` body, for the same reason the base ref does.
