# Issue triage (M7 — velocity)

Plan reference: triage every issue within **24 hours** for the first 90 days after public push.

## Daily habit (≤15 minutes)

1. Open [Issues](https://github.com/vaultcompasshq/vault-guard/issues) sorted by **newest**.
2. For each untriaged item:
   - Add **one label**: `bug`, `false-positive`, `false-negative`, `feature`, `question`, `docs`.
   - **Comment** even if brief: acknowledge + next step or need for repro.
3. Close only when reproduced + fixed, or duplicate, or out of scope (explain).

## SLA cheat sheet

| Type | First response |
|------|------------------|
| `false-positive` | Ask for file snippet (redacted) + pattern id from SARIF/JSON. |
| `bug` / crash | Ask Node version + `vault-guard --version` + minimal repro. |
| `feature` | “Noted — not committing to timeline in triage; linked to roadmap.” |

## Bots

Let Dependabot / CodeQL PRs auto-run CI; human approves or requests changes within 24h where possible.
