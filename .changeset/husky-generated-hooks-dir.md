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

The fix detects a husky-generated hooks directory by directory SHAPE
alone: a resolved basename of `_` under a directory literally named
`.husky`. Only the native manager is affected, and only when that shape
matches; it then installs into the tracked .husky/pre-commit file the
same way the husky manager does, saying so in the output.
`--manager husky` is no longer required in this case. The foreign-hook
check now resolves to the same tracked file, so it names and inspects
the right thing. Nothing is ever written under the generated directory,
and husky 8 (core.hooksPath=.husky, no generated subdirectory) is
untouched by this change -- its shape never matches, so the existing
native install path keeps handling it exactly as before.

An earlier version of this detection also treated the presence of
husky's `h` shim, or dispatcher-shaped content in an existing
pre-commit file, as sufficient on their own to trigger the redirect.
Review (informed by the same fix regressing in two sibling repos) caught
that both are false-positive-prone taken alone -- an unrelated directory
that happens to contain a file named `h`, or a coincidentally
dispatcher-shaped foreign hook sitting somewhere that is not
`.husky/_`, would have been misdetected as husky and silently
redirected. Directory shape is now the only signal that may trigger the
redirect at all.

Also confirmed (with a scratch shell reproduction before writing the
regression test) that the generated hook script's existing status
handling -- `vault-guard scan --staged || { ... exit 1 }` -- stays safe
under husky's own `sh -e` re-exec of the tracked hook: because the scan
command is the first half of an OR list, POSIX exempts it from errexit,
so the "COMMIT BLOCKED" explanation always prints. A naive rewrite using
a bare `vault-guard scan --staged` line followed by `status=$?` would
NOT be exempt and would silently lose that explanation under `sh -e`;
proven wrong here on purpose, not shipped.

Proven the same way as the relative-hooksPath fix: husky 9 and husky 8
layouts built by hand, then real git commits driven through a stub
vault-guard binary (exit codes 1 and 2) on PATH, asserting both that the
commit is refused and that the stub's own announce line actually
appears in the output -- so a crashed hook can never be mistaken for a
real block.
