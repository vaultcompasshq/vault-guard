# @vaultcompass/vault-guard-core

## 1.1.0

### Minor Changes

- fix(core): broaden OpenAI key detection with T3BlbkFJ watermark — adds svcacct/admin/legacy

  The previous `openai` pattern (`sk-[a-zA-Z0-9]{48}`) was a fixed 48-char match
  from the pre-2024 key format. Modern OpenAI keys use a `T3BlbkFJ` watermark
  (base64 for "OpenAI") and come in four formats, all of which were missed:

  - `sk-proj-` — project-scoped key (the current default)
  - `sk-svcacct-` — service-account key for non-human identities
  - `sk-admin-` — org-wide admin key (cannot call inference APIs)
  - `sk-` (legacy) — pre-project user key with watermark at positions 20 and 40+

  Each format now has its own rule entry (distinct blast radius). The legacy `sk-`
  catch-all uses a token-boundary lookbehind and requires the watermark, preventing
  short/benign `sk-` identifiers from triggering false positives.

  Per-format recall tests and bench fixtures (TP + FP guard) are included.
  `docs/RULES.md` is updated to reflect the four OpenAI entries.

- fix(proxy): parse Anthropic SSE usage so streaming records real tokens and cost

  The proxy previously recorded `inputTokens: 0, outputTokens: 0` for all streaming
  responses (the "proxy-stream" telemetry source). Streaming is how Cursor and Claude
  Code actually send requests, so the cost-tracking value prop was non-functional for
  real traffic.

  The stream path now tees a bounded copy of the SSE body (same 1 MB cap as the
  non-streaming path) and parses token usage from the Anthropic SSE event stream:
  `message_start` carries `input_tokens`; the last `message_delta` carries cumulative
  `output_tokens`. The cost is computed automatically from the existing `calculateCost`
  table. If the tee cap is exceeded, a new `proxy-stream-overflow` source is recorded
  so missing usage is visible in telemetry.

  A new pure module `proxy-sse.ts` contains the parser; it is unit-testable without
  spinning up an HTTP server. The existing integration test that previously asserted
  the broken `inputTokens: 0` has been updated to assert real token counts.
