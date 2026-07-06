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

## Output

| Output          | Description |
|----------------|-------------|
| `results-file` | Absolute path to the written SARIF/JSON file. |

## Example: fail the job on secrets

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
- uses: vaultcompasshq/vault-guard@v1.0.0
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
