---
'@vaultcompass/vault-guard': patch
'@vaultcompass/vault-guard-core': patch
'@vaultcompass/vault-guard-mcp': patch
'@vaultcompass/vault-guard-telemetry': patch
---

Fix the native pre-commit hook installing to the wrong directory when
core.hooksPath is a relative path.

Git resolves a relative core.hooksPath against the working-tree root, not
against the .git directory. PreCommitHook.getEffectiveHooksDir resolved it
against .git instead, so a repository with husky 9 installed (which sets
core.hooksPath=.husky/_) had vault-guard init and install-hook write the
hook to .git/.husky/_/pre-commit, report success, and never actually run:
git looks for the hook at .husky/_/pre-commit and finds nothing there.

The fix resolves a relative core.hooksPath against git rev-parse
--show-toplevel instead. An absolute core.hooksPath is still used exactly
as given, and no core.hooksPath at all still resolves against the git
directory, which is unchanged and correct on its own: a linked worktree
or a submodule has a git directory that is not its working-tree root, and
an unset core.hooksPath has to keep pointing there.

Proven with a test that drives a real git commit through a stub
vault-guard binary that exits non-zero, rather than only asserting on the
installed path: with the hook actually reaching the place git reads it,
the commit is refused; before the fix it silently succeeded because the
gate was never really there. An existing test in this file had asserted
the old, wrong .git-relative location and has been corrected rather than
left in place.
