# Agent working rules (all AI seats: Codex, Claude, Cursor)

## Fewer, bigger PRs (operator directive, 2026-08-01)

CI minutes and review time are metered. Per-PR overhead (branch setup, gates, CI runs, review, merge) dominates when work arrives as many small PRs. Batch accordingly:

- Group small independent fixes, copy tweaks, doc updates, and link fixes into ONE PR. Do not open a PR per one-line fix.
- A separate PR is ONLY for work that needs its own review gate: auth, billing or money paths, regulated or legal copy, data-model or migration changes, anything with a security property.
- Per commit, run targeted tests for the files you touched plus typecheck and lint. Run the FULL test suite ONCE, immediately before opening the PR - not per commit.
- Never re-run CI to double-check a green local run. Local gates are the merge bar; hosted CI runs once as a byproduct.
- Merge in grouped windows when several PRs are ready, rather than merging one at a time through the day.
- Scope tests to blast radius, not diff size: if you touch a shared module, run its consumers' tests too.

## Standing conduct

- Never commit directly to the default branch. Feature branches and PRs always.
- Never use no-verify. A pre-commit hook failure is a finding, not an obstacle.
- Never read .env files or paste secret values into chats, commits, or docs. Variable names only.
- One task per session. No scope creep beyond the task you were given.
