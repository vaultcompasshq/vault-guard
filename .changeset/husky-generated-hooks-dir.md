---
'@vaultcompass/vault-guard': patch
'@vaultcompass/vault-guard-core': patch
'@vaultcompass/vault-guard-mcp': patch
'@vaultcompass/vault-guard-telemetry': patch
---

Fix the native pre-commit hook installing into husky 9's generated,
gitignored hooks directory instead of the tracked hook file.

Husky 9 sets core.hooksPath to .husky/_, a GENERATED directory that
husky's own prepare script rewrites on every `pnpm install`. The file git
actually runs there is a two-line dispatcher that sources husky's `h`
shim, which in turn execs the TRACKED .husky/<hookname> file. The prior
relative-hooksPath fix correctly resolved .husky/_ as the effective hooks
directory, but the default native manager then wrote vault-guard's hook
straight into that generated directory: init reported success, and the
hook worked until the next `pnpm install` silently wiped it. The same bug
made init's foreign-hook check read the generated dispatcher instead of
the tracked hook, so a repository already using husky 9 got a confusing
"Existing Husky pre-commit has no vault-guard stanza" conflict about the
wrong file.

The fix detects a husky-generated hooks directory (by its .husky/_ shape,
by the presence of husky's `h` shim, or by the dispatcher content of an
existing pre-commit file there) and, only for the native manager, installs
into the tracked .husky/pre-commit file the same way the husky manager
does, saying so in the output. `--manager husky` is no longer required in
this case. The foreign-hook check now resolves to the same tracked file,
so it names and inspects the right thing. Nothing is ever written under
the generated directory.

Proven the same way as the relative-hooksPath fix: a husky 9 layout built
by hand (dispatcher, a functional `h` shim, and the tracked hook), then a
real git commit driven through a stub vault-guard binary that exits
non-zero, asserting the commit is refused.
