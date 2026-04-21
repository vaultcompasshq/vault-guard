# Screencast playbook (M7)

**Target length:** 75–90 seconds  
**Working title:** *“I asked the AI to add Stripe — Vault Guard caught it before commit.”*

## Before you record

- [ ] Clean demo repo with a **fake-shaped** Stripe key in a staged file (never use real secrets).
- [ ] Terminal font size 16+, high contrast theme.
- [ ] `vault-guard` on PATH; window title or prompt shows project name.
- [ ] Optional: VS Code with Vault Guard extension built for inline diagnostics.

## Shot list (story beats)

| Sec | Beat | Audio / narration |
|-----|------|-------------------|
| 0–8 | Title card or repo README on screen | “Vault Guard is the security and spend layer for AI-assisted coding.” |
| 8–25 | IDE: AI suggests adding a **Stripe-shaped live key** to `lib/billing.ts` (use a fake from your test corpus, never a real key). | “Here the assistant pastes a payment key into the tree.” |
| 25–45 | Run `vault-guard scan --staged` or rely on extension red squiggle | “Vault Guard flags it before it ever lands on main.” |
| 45–60 | `vault-guard install-hook` + failed `git commit` | “Wire the hook once — bad commits don’t ship.” |
| 60–75 | Quick flash: SARIF / Action one-liner or MCP `npx` line | “CI, MCP, editor — same engine.” |
| 75–90 | CTA: GitHub URL + star ask | “Open source on GitHub — star it if this saved you once.” |

## Post-publish checklist

- [ ] Upload to **Loom** or **YouTube** (unlisted OK at first).
- [ ] Add link to root **`README.md`** (top or “Adoption” section).
- [ ] Pin comment or tweet with one sentence + link.
- [ ] Drop link in **`docs/AWESOME_LISTS.md`** PRs where a demo strengthens the submission.

## Safe demo content

Use keys that match **test** patterns from the scanner docs (e.g. documented fake Stripe test shapes) or generate obviously fake literals that still trip **live** rules only in a throwaway repo — **never** record real credentials.
