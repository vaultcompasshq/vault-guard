# Homebrew distribution

The supported install path today is **npm**:

```bash
npm install -g @vaultcompass/vault-guard
```

## Optional: org tap (`vaultcompasshq/homebrew-tap`)

1. Create a public tap repository (e.g. `github.com/vaultcompasshq/homebrew-tap`).
2. Add a formula that wraps the published npm tarball from
   `https://registry.npmjs.org/@vaultcompass/vault-guard/-/vault-guard-<version>.tgz`
   and set `sha256` from `curl -sL ... | shasum -a 256`.
3. Prefer Homebrew’s **`npm`** install strategy or a small wrapper script that
   delegates to `npx @vaultcompass/vault-guard`. Avoid vendoring the full
   monorepo into the formula unless you need offline builds.

After the tap exists:

```bash
brew tap vaultcompasshq/tap
brew install vault-guard
```
