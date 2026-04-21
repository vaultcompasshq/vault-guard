# Design partner outreach (M7)

**Goal (plan exit criteria):** five focused conversations on the calendar with people who ship AI-assisted code (staff engineers, security champions, OSS maintainers).

This file is a **template**. The repo cannot book your calendar; copy rows into Google Calendar / Linear / Notion and replace placeholders.

## Who to invite

- Maintains a TypeScript or polyglot monorepo with **real** CI.
- Uses **Cursor, Claude Code, Copilot, or similar** daily.
- Will give **honest** feedback in 25–30 minutes (not a sales call).

## Cold outreach (short email / DM)

Subject: `10m feedback — AI coding + secret scanning`

Body:

> Hi [Name] — we’re tightening **Vault Guard** (MIT), a scanner + hooks + MCP layer aimed at “AI pasted a key” failures.  
> If you have **25 minutes** in the next two weeks, I’d love a blunt walkthrough: does the hook/MCP story match how your team works?  
> No prep — screen share optional.  
> [your calendar link]

## Conversation agenda (25 min)

1. **2 min** — What AI tools does the team use? Where do secrets slip today?
2. **8 min** — Live or recorded demo: `scan --staged`, SARIF, MCP one-liner.
3. **10 min** — What would block adoption (noise, speed, CI, policy)?
4. **5 min** — Would they try it for a week? What metric would prove value?

## Five-slot calendar template

Block **30 minutes** each (25 + buffer). Fill when scheduled.

| # | Date (ISO) | Time (TZ) | Partner / org | Role | Notes | Done |
|---|------------|------------|---------------|------|-------|------|
| 1 | | | | | | ☐ |
| 2 | | | | | | ☐ |
| 3 | | | | | | ☐ |
| 4 | | | | | | ☐ |
| 5 | | | | | | ☐ |

## Follow-up

- Thank-you same day + link to repo + **one** concrete issue if they reported a bug.
- Ask only: *“If we fix X, would you try again?”* — not a testimonial obligation.
