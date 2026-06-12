# Plan: Audit remediation → first "release train" (1.1.0)

**Status:** SHIPPED — tag `v1.1.0`, npm `@latest` on all four packages (2026-06-11).

**Author:** Opus (security architect) · **Implementer:** Sonnet (lead dev)  
**Date:** 2026-06-11 · **Repo:** `vault-guard` (pnpm monorepo, branch `main`)

## Context

An external audit (and our own verification) confirmed 6 findings. As of `v1.0.6`
we have closed the two pure-hygiene findings (#2 source maps, #3 test helper in
tarball) and added a `check:pack` CI gate. Three findings remain open and the
release cadence itself is a flagged problem:

| # | Sev | Finding | Status |
|---|-----|---------|--------|
| 1 | High | Proxy records **0 tokens for streaming** responses (`proxy.ts` stream path). Streaming is the real traffic, so the cost/telemetry value prop is non-functional. | **OPEN — this plan** |
| 4 | Med | Premature 1.0 + churn (now 7 versions in a week). | **OPEN — this plan (process)** |
| 5 | Low | OpenAI pattern `/sk-[a-zA-Z0-9]{48}/` is fixed-length; misses current key formats (false negatives). | **OPEN — this plan** |
| 2,3 | Med | Hygiene | DONE (`v1.0.6`) |
| 6 | Low | ReDoS static-only | Acknowledged; out of scope |

**Goal of this plan:** fix the release *process* first (so we stop the churn),
then land the streaming fix (#1) and the OpenAI recall fix (#5) as **one
deliberate `1.1.0`** riding the new train — not three more same-day patches.

## Shared guardrails (read first)

- **Do not cut a release per task.** Everything here ships as a single `1.1.0`.
  Accumulate changes behind changesets; publish once at the end (Phase 4).
- The pre-commit hook runs `vault-guard scan --staged` and needs the global
  binary on `PATH`. If a clean rebuild drops the exec bit, run
  `chmod +x packages/cli/dist/cli-entry.js`. Never `--no-verify`.
- After any build, **`pnpm check:pack` must stay green** (no maps/test files).
- Node ≥ 22 expected; local may warn on v20 — fine for dev.
- TypeScript stays on 5.x. **Do not** attempt the TS6 upgrade (separately deferred).
- Keep functions small/pure where possible (testability). New parsing logic goes
  in its own module so it can be unit-tested without spinning up HTTP servers.
- Run `pnpm lint && pnpm test && node bench/run.cjs --assert` before opening the PR.

---

## Phase 0 — Release cadence & process (fixes #4)

**Why first:** #4 is a *process* defect. Doing the other fixes as another same-day
patch would re-commit the exact sin. Land the train, then ride it.

### 0.1 Add changesets (version + CHANGELOG automation, lockstep the 4 packages)

```bash
pnpm add -Dw @changesets/cli
pnpm changeset init
```

Edit `.changeset/config.json`:

```json
{
  "$schema": "https://unpkg.com/@changesets/config@3.0.0/schema.json",
  "changelog": "@changesets/cli/changelog",
  "commit": false,
  "access": "public",
  "baseBranch": "main",
  "updateInternalDependencies": "patch",
  "fixed": [
    [
      "@vaultcompass/vault-guard",
      "@vaultcompass/vault-guard-core",
      "@vaultcompass/vault-guard-mcp",
      "@vaultcompass/vault-guard-telemetry"
    ]
  ],
  "ignore": []
}
```

`fixed` keeps all four published packages locked to the same version (they already
move together). The private root + `vscode-extension` are not in the workspace
publish set, so they are ignored automatically.

Add root `package.json` scripts:

```json
"changeset": "changeset",
"version-packages": "changeset version",
"release:next": "pnpm build && pnpm check:pack && pnpm publish -r --tag next --no-git-checks"
```

> Keep the existing tag-triggered `release.yml` as the `@latest` publish path.
> Changesets handles **versioning + CHANGELOG**; the git tag still triggers the
> actual publish. Do not wire the changesets GitHub Action auto-PR in this pass —
> minimal change, no new bot surface.

### 0.2 Document the train in `CONTRIBUTING.md` (create if absent)

- One **minor** every 2–4 weeks; **patches only** for security/correctness.
- Risky work soaks on `@next` (`pnpm release:next`) before promotion to `@latest`.
- Every change adds a changeset (`pnpm changeset`) using Conventional-Commit-style
  summaries. No ad-hoc `version` edits in `package.json`.
- **Do not** reset to 0.x. We have public 1.x consumers; walking backward is a
  worse semver signal than slowing down. Stability comes from cadence, not renumbering.

### 0.3 Acceptance

- `pnpm changeset` runs interactively and writes a `.changeset/*.md`.
- `pnpm version-packages` bumps all four packages in lockstep and updates `CHANGELOG.md`.
- `.changeset/config.json` committed; no version bump committed yet.

---

## Phase 1 — Fix #1: streaming SSE token parsing (the High)

**File:** `packages/cli/src/commands/proxy.ts` (stream branch ~lines 323-339).
**Current behaviour:** pipes the stream, then records `inputTokens: 0,
outputTokens: 0, source: 'proxy-stream'`.

Anthropic streams usage across SSE events:
- `message_start` → `message.usage.input_tokens` (+ `cache_*` + an initial `output_tokens`)
- `message_delta` → `usage.output_tokens` (**cumulative; last one wins**)
- terminated by `message_stop`

### 1.1 Add a pure SSE usage parser (unit-testable)

New file `packages/cli/src/commands/proxy-sse.ts`:

```ts
export interface SseUsage {
  inputTokens: number;
  outputTokens: number;
  model: string | null;
}

/**
 * Extract token usage from a buffered Anthropic SSE stream. Pure + synchronous
 * so it can be unit-tested without HTTP. `input_tokens` arrives in
 * `message_start`; `output_tokens` is cumulative across `message_delta` events
 * (last value wins). Unknown/garbage lines are ignored.
 */
export function parseAnthropicSseUsage(raw: string, fallbackModel: string | null): SseUsage {
  let inputTokens = 0;
  let outputTokens = 0;
  let model = fallbackModel;

  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data:')) continue;
    const payload = trimmed.slice('data:'.length).trim();
    if (!payload || payload === '[DONE]') continue;

    let evt: {
      type?: string;
      message?: { model?: string; usage?: { input_tokens?: number; output_tokens?: number } };
      usage?: { input_tokens?: number; output_tokens?: number };
    };
    try {
      evt = JSON.parse(payload);
    } catch {
      continue;
    }

    if (evt.type === 'message_start' && evt.message) {
      if (typeof evt.message.model === 'string') model = evt.message.model;
      const u = evt.message.usage ?? {};
      if (typeof u.input_tokens === 'number') inputTokens = u.input_tokens;
      if (typeof u.output_tokens === 'number') outputTokens = u.output_tokens;
    } else if (evt.type === 'message_delta' && evt.usage) {
      if (typeof evt.usage.input_tokens === 'number') inputTokens = evt.usage.input_tokens;
      if (typeof evt.usage.output_tokens === 'number') outputTokens = evt.usage.output_tokens;
    }
  }

  return { inputTokens, outputTokens, model };
}
```

### 1.2 Tee the stream (bounded) and record real tokens

Replace the `if (stream) { ... }` block in `proxy.ts`. **Mirror the non-streaming
tee** so memory stays bounded by `MAX_TEE_BYTES` and the wire pipe is never blocked:

```ts
if (stream) {
  // Pipe to client immediately (bounded by the OS pipe, not us). Tee a bounded
  // copy purely to parse SSE usage events. On tee overflow we still deliver the
  // full stream and record a distinct source so missing usage is visible.
  pres.pipe(res);

  const teeChunks: Buffer[] = [];
  let teeLen = 0;
  let teeAbandoned = false;

  pres.on('data', chunk => {
    if (teeAbandoned) return;
    const b = chunk as Buffer;
    teeLen += b.length;
    if (teeLen > MAX_TEE_BYTES) {
      teeAbandoned = true;
      teeChunks.length = 0;
      return;
    }
    teeChunks.push(b);
  });

  pres.on('end', () => {
    const model = typeof bodyJson.model === 'string' ? bodyJson.model : null;
    if (teeAbandoned) {
      store.recordUsage({
        provider: 'anthropic', model, cwd,
        inputTokens: 0, outputTokens: 0, source: 'proxy-stream-overflow',
      });
      resolve();
      return;
    }
    const usage = parseAnthropicSseUsage(Buffer.concat(teeChunks).toString('utf8'), model);
    store.recordUsage({
      provider: 'anthropic',
      model: usage.model,
      cwd,
      inputTokens: usage.inputTokens,
      outputTokens: usage.outputTokens,
      source: 'proxy-stream',
    });
    resolve();
  });

  pres.on('error', () => resolve());
  return;
}
```

Add the import at the top of `proxy.ts`:

```ts
import { parseAnthropicSseUsage } from './proxy-sse';
```

> **Cost is automatic.** `TelemetryStore.recordUsage` computes `est_cost_usd` via
> `counter.calculateCost('anthropic', input, output)` when `estCostUsd` is
> undefined (store.ts:409-417). No cost code needed here.

### 1.3 Tests

**Unit** — new `packages/cli/src/__tests__/proxy-sse.test.ts`: feed a realistic
multi-event SSE string (a `message_start` with `input_tokens`, several
`message_delta`s with increasing `output_tokens`, a `message_stop`) and assert the
parser returns the final cumulative numbers + model. Add cases for: empty stream,
garbage `data:` lines, `[DONE]`, missing usage.

**Integration** — UPDATE the existing assertion in
`packages/cli/src/__tests__/integration/proxy-stream.test.ts:142-173`. It currently
asserts the *bug* (`expect(lastCall?.inputTokens).toBe(0)`). Change the SSE fixture
to include usage and assert real tokens:

```ts
const sseBody =
  'event: message_start\n' +
  'data: {"type":"message_start","message":{"model":"claude-3-5-sonnet","usage":{"input_tokens":1200,"output_tokens":1}}}\n\n' +
  'event: message_delta\n' +
  'data: {"type":"message_delta","usage":{"output_tokens":350}}\n\n' +
  'event: message_stop\ndata: {"type":"message_stop"}\n\n';
// ...
expect(result.body).toBe(sseBody);            // still byte-for-byte forwarded
const lastCall = recordSpy.mock.calls.at(-1)?.[0];
expect(lastCall?.source).toBe('proxy-stream');
expect(lastCall?.inputTokens).toBe(1200);
expect(lastCall?.outputTokens).toBe(350);
```

Add a second integration case asserting `proxy-stream-overflow` when the tee cap
is exceeded (mirror the existing overflow test).

### 1.4 Add a changeset

```bash
pnpm changeset   # minor; summary: "fix(proxy): parse Anthropic SSE usage so streaming records real tokens/cost"
```

### 1.5 Acceptance

- New unit test + updated integration test pass.
- `proxy-sse.ts` is the only new source file; `pnpm check:pack` stays green.
- Manual sanity (optional): point a real Claude/Cursor session at the proxy and
  confirm a non-zero `proxy-stream` row appears in `~/.vault-guard/usage.sqlite`.

---

## Phase 2 — Fix #5: OpenAI key recall + per-vendor recall tests (Low)

**File:** `packages/core/src/scanners/secret-scanner.ts` (lines 60-65 area).
Current: `['openai', { regex: /sk-[a-zA-Z0-9]{48}/g, severity: 'critical' }]`
plus `openai-project` for `sk-proj-`.

### 2.1 Verify current formats BEFORE editing the regex

Do not hardcode from memory — OpenAI key formats drift. Confirm the live set
(legacy `sk-`, `sk-proj-`, `sk-svcacct-`, `sk-admin-`, variable lengths/charset
incl. `-`/`_`) from current OpenAI docs, then design patterns accordingly.

### 2.2 Tighten/extend patterns without inviting false positives

Guidance (finalize against 2.1):
- Add discrete entries for `sk-svcacct-` and `sk-admin-` (prefix-anchored,
  `[A-Za-z0-9_-]{20,}`), like the existing `sk-proj-` entry.
- For legacy `sk-`, prefer a token-boundary + entropy gate over blindly widening
  length (a bare widened `sk-` flooded FPs is worse). Pattern shape:
  `/(?<![A-Za-z0-9_])sk-[A-Za-z0-9]{40,}/g` with `minEntropy` set, consistent with
  how `resend-api` was hardened in `v1.0.5`.
- Keep ordering so the more specific prefixed rules are not shadowed.

After editing, regenerate rules doc:

```bash
node scripts/gen-rules-doc.cjs   # docs/RULES.md must be committed (CI checks drift)
```

### 2.3 Recall test + bench fixtures

- Add a unit recall test (e.g. `packages/core/src/__tests__/openai-recall.test.ts`)
  with **fake-but-real-shaped** keys per vendor format; assert each is detected as
  `critical`. Use clearly-synthetic values.
- Add a true-positive bench fixture for each new format under
  `bench/fixtures/secrets/` + label in `bench/labels.json`, and (important) a
  false-positive guard fixture under `bench/fixtures/clean/` for a benign `sk-`-ish
  identifier so precision stays 100%.
- If you generate fixtures via `bench/generate-fixtures.cjs`, **fragment any literal
  secret markers mid-token** so the generator source isn't itself flagged (this bit
  us with the PEM fixture; see `v1.0.5` history).

### 2.4 Acceptance

- `node bench/run.cjs --assert` still reports **precision 100% / recall 100%**.
- `docs/RULES.md` drift check passes.
- Add a changeset (minor): "fix(core): broaden OpenAI key detection (svcacct/admin/legacy) with recall tests".

---

## Phase 3 — Pre-release verification (full gate)

Run locally and confirm all green:

```bash
pnpm install
pnpm build
pnpm check:pack            # no maps / __tests__ / test helpers
node scripts/gen-rules-doc.cjs && git diff --exit-code docs/RULES.md
pnpm lint
pnpm test                  # all packages
node bench/run.cjs --assert
```

Optional soak: `pnpm release:next` → install `@vaultcompass/vault-guard@next` in a
scratch dir and smoke the proxy + a streaming call before promoting.

---

## Phase 4 — Cut 1.1.0 (single release on the new train)

```bash
pnpm version-packages      # changesets bumps all 4 to 1.1.0 + writes CHANGELOG
# review the generated CHANGELOG + version diffs
git add -A && git commit -m "chore(release): v1.1.0"   # hook scans staged (must pass)
git tag -a v1.1.0 -m "v1.1.0: streaming token telemetry + OpenAI recall + release train"
git push origin main && git push origin v1.1.0         # release.yml publishes @latest
```

Then verify exactly as we did for 1.0.6:
- `release.yml` run green through `check:pack` → publish → smoke test.
- `npm view @vaultcompass/vault-guard version` → `1.1.0` (all 4).
- Pull the tarball from the registry and confirm no maps/test files.

### 1.1.0 acceptance criteria

- [ ] Streaming requests record **non-zero** input/output tokens (`proxy-stream`).
- [ ] Cost is populated for streaming rows (auto via `calculateCost`).
- [ ] Existing non-streaming + overflow + non-JSON proxy tests still pass.
- [ ] OpenAI recall test passes for all targeted formats; bench P/R = 100%.
- [ ] Released as **one** `1.1.0` via changesets (no intermediate patches).
- [ ] `check:pack` enforced and green on the release run.

---

## Explicitly OUT OF SCOPE (separate, larger plans)

These are the competitive-parity / moat features from the audit. **Do not start
them in this PR** — they are multi-day features each and need their own plan:

- **Git history scanning** (`--since-commit`, `git log -p`). Note: current README
  *deliberately* positions us as "not a history miner; compose with gitleaks." This
  is a strategy decision (own the position vs. build the feature) — escalate to the
  owner before building.
- **Active AI-key verification** (`--verify` pinging vendor `/models`).
- **MCP deny-gate** + copy-paste `.cursorrules` snippet.
- **`.claude/` `.cursor/` `.continue/` artifact detection** rule.
- **`init` autowire** + GitHub Action Marketplace listing.
- **TS6 upgrade** (deferred; `@types/node` resolution issues under pnpm).
