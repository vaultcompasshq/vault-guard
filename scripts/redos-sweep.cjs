#!/usr/bin/env node
/**
 * ReDoS timing sweep over the built-in pattern table.
 *
 * WHY THIS EXISTS
 * ---------------
 * The unit suite is graded against fixtures we wrote, so it cannot catch a
 * catastrophic backtracking shape nobody thought to write a fixture for. Six of
 * the built-in rules were quadratic in 1.5.0 and every one of them passed the
 * whole unit suite. This harness measures instead: it runs each rule against
 * adversarial inputs at two sizes and compares growth. Roughly 2x per doubling
 * is linear; roughly 4x is quadratic, i.e. a real ReDoS.
 *
 * WHAT A PASS MEANS, AND WHAT IT DOES NOT
 * ---------------------------------------
 * A pass means: measured linear on the adversarial inputs THIS HARNESS
 * CONSTRUCTS. It is not a proof of linearity, and it is not a guarantee for
 * inputs we did not think to build. Regex cost depends on the shape of the
 * input, and a shape nobody constructed is a shape nobody measured. Treat a
 * clean sweep as "no known-bad shape is present", never as "this table cannot
 * be attacked". Real execution-time bounds need a different engine (re2).
 *
 * The self-test below is what makes a clean result mean anything at all: it
 * replays the six historically-quadratic forms and REQUIRES the harness to flag
 * all six. An early version of this sweep extracted only a leading literal,
 * stopped at the paren in `postgres(?:ql)?`, and therefore never built a
 * many-start input for three of the four DSN rules -- it reported them clean
 * while they were quadratic. Without the self-test that bug was invisible.
 *
 * NOT A CI GATE. Timing in CI is noisy (shared runners, cold caches, other
 * jobs), and a flaky security gate gets disabled, which is worse than no gate.
 * Run it as a manual pre-release check and when editing any pattern.
 *
 * Adversarial inputs are GENERATED here (filler runs and repeated scheme
 * literals), never credential-shaped literals, so nothing secret-looking is
 * committed.
 *
 * Usage:
 *   node scripts/redos-sweep.cjs                 # sweep, compare to baseline
 *   node scripts/redos-sweep.cjs --self-test     # prove the harness detects quadratics
 *   node scripts/redos-sweep.cjs --update-baseline
 *   node scripts/redos-sweep.cjs --json
 */
'use strict';

const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.resolve(__dirname, '..');
const BASELINE_FILE = path.join(__dirname, 'redos-sweep-baseline.json');
const CORE_DIST = path.join(REPO_ROOT, 'packages', 'core', 'dist', 'index.js');

const args = process.argv.slice(2);
const SELF_TEST = args.includes('--self-test');
const UPDATE = args.includes('--update-baseline');
const AS_JSON = args.includes('--json');

/** Growth ratio at or above this is treated as super-linear (quadratic). */
const QUADRATIC_RATIO = 3;
/** Ignore runs too fast to time reliably. */
const NOISE_FLOOR_MS = 5;
/** Above this at the SMALL size, derive the ratio from a half-size pair instead. */
const ALREADY_SLOW_MS = 400;
/**
 * A rule must ALSO be slow in absolute terms before we call it super-linear.
 *
 * Ratio alone is too noisy to stand on its own: a rule costing 3ms at 100k and
 * 14ms at 200k reports a 4.6x ratio from scheduler jitter and JIT warmup, and
 * an early baseline run recorded exactly that false positive for `mysql-url`.
 * A quadratic that matters is slow in wall-clock terms, not just in ratio: the
 * six real ones measured 2,180ms to 16,593ms at 200k, while every bounded rule
 * sits under ~35ms. This floor sits well clear of both.
 */
const MIN_ABSOLUTE_MS_TO_FLAG = 100;

const SIZE_SMALL = 100_000;
const SIZE_LARGE = 200_000;

// ---------------------------------------------------------------------------

function runOnce(regex, input) {
  const re = new RegExp(regex.source, regex.flags);
  re.lastIndex = 0;
  const t0 = process.hrtime.bigint();
  let m;
  let c = 0;
  while ((m = re.exec(input)) !== null) {
    c++;
    if (re.lastIndex === m.index) re.lastIndex++;
    if (c > 3) break;
  }
  return Number(process.hrtime.bigint() - t0) / 1e6;
}

/**
 * Best-of-N timing. Takes the MINIMUM, which is the standard choice for
 * microbenchmarks: scheduler preemption and GC can only ever make a run slower,
 * so the fastest observed run is the closest estimate of true cost. Cheap runs
 * are repeated; an already-slow run is measured once because repeating it is
 * what makes this harness unaffordable.
 */
function timeOnce(regex, input) {
  const first = runOnce(regex, input);
  if (first > ALREADY_SLOW_MS) return first;
  return Math.min(first, runOnce(regex, input), runOnce(regex, input));
}

/**
 * Concrete leading-literal prefixes for a regex source.
 *
 * Returns a LIST, because a scheme is often written with an optional group
 * (`postgres(?:ql)?:\/\/`, `mongodb(?:\+srv)?:`, `rediss?:`). Expanding those
 * both ways is what lets the sweep build a many-start input for those rules;
 * see the note about the blind spot in the header.
 */
function concretePrefixes(src) {
  let variants = [''];
  const LIT = /[A-Za-z0-9_:\-/@;=."']/;
  for (let i = 0; i < src.length && variants.length <= 8; ) {
    const ch = src[i];
    if (ch === '\\') {
      const nxt = src[i + 1];
      if (nxt && /[./+$^|]/.test(nxt)) {
        variants = variants.map(v => v + nxt);
        i += 2;
        continue;
      }
      break;
    }
    if (ch === '(' && src.startsWith('(?:', i)) {
      const close = src.indexOf(')', i);
      if (close === -1) break;
      const body = src.slice(i + 3, close);
      if (!/^[A-Za-z0-9_+\\|.-]*$/.test(body)) break;
      const optional = src[close + 1] === '?';
      const alts = body.split('|').map(a => a.replace(/\\/g, ''));
      const next = [];
      for (const v of variants) {
        if (optional) next.push(v);
        for (const a of alts) next.push(v + a);
      }
      variants = next.slice(0, 8);
      i = close + (optional ? 2 : 1);
      continue;
    }
    if (LIT.test(ch) && src[i + 1] === '?') {
      variants = variants.flatMap(v => [v, v + ch]).slice(0, 8);
      i += 2;
      continue;
    }
    if (LIT.test(ch)) {
      variants = variants.map(v => v + ch);
      i++;
      continue;
    }
    break;
  }
  return [...new Set(variants.filter(v => v.length > 0))];
}

/** Filler alphabets that sit inside the common character classes. */
const FILLERS = ['a', '0', 'A', 'a:', 'a.', 'a-', 'a_', 'aA0'];

function candidates(src, n) {
  const list = [];
  // Pure runs: drive trailing-quantifier and many-start shapes.
  for (const f of FILLERS) list.push(f.repeat(Math.max(1, Math.floor(n / f.length))));
  for (const pre of concretePrefixes(src)) {
    // One start, long tail.
    for (const f of ['a', '0', 'A', 'a:']) {
      list.push(pre + f.repeat(Math.max(1, Math.floor((n - pre.length) / f.length))));
    }
    // MANY starts: repeat the literal prefix with filler between.
    for (const f of ['', 'a', 'a:', 'a.']) {
      const unit = pre + f;
      list.push(unit.repeat(Math.max(1, Math.floor(n / unit.length))));
    }
  }
  return list;
}

/**
 * Measure one rule; returns its worst observed growth ratio.
 *
 * Short-circuits on the first clearly super-linear shape. Finding one bad shape
 * is the whole answer for that rule, and continuing is what made an early
 * version take minutes: a quadratic rule costs seconds PER candidate input, and
 * there are a dozen-plus candidates. Cost matters here because a harness slow
 * enough to skip is a harness nobody runs.
 */
function measureRule(entry) {
  const regex = new RegExp(entry.regexSource, entry.regexFlags);
  const small = candidates(entry.regexSource, SIZE_SMALL);
  const large = candidates(entry.regexSource, SIZE_LARGE);
  let worstRatio = 0;
  let worstMs = 0;
  for (let i = 0; i < small.length; i++) {
    // Time the SMALL input first: if a rule is already pathological here, the
    // large run costs ~4x more and we do not need it to reach a verdict.
    const tSmall = timeOnce(regex, small[i]);
    if (tSmall < NOISE_FLOOR_MS / 2) continue;

    let ratio;
    let msLarge;
    if (tSmall > ALREADY_SLOW_MS) {
      // Derive the ratio from a half-size pair instead, to stay affordable.
      const half = candidates(entry.regexSource, SIZE_SMALL / 2)[i];
      const tHalf = timeOnce(regex, half);
      ratio = tHalf > 0.01 ? tSmall / tHalf : 0;
      msLarge = tSmall * 4; // projected; not measured
    } else {
      msLarge = timeOnce(regex, large[i]);
      if (msLarge < NOISE_FLOOR_MS) continue;
      ratio = tSmall > 0.01 ? msLarge / tSmall : 0;
    }

    // Both conditions must hold: super-linear GROWTH and a cost that actually
    // matters. See MIN_ABSOLUTE_MS_TO_FLAG for why ratio alone is not enough.
    const isBad = ratio >= QUADRATIC_RATIO && msLarge >= MIN_ABSOLUTE_MS_TO_FLAG;
    if (isBad && msLarge > worstMs) {
      worstRatio = ratio;
      worstMs = msLarge;
    } else if (!isBad && msLarge > worstMs && worstRatio < QUADRATIC_RATIO) {
      // Track the most expensive benign shape so the report has a number.
      worstRatio = Math.max(worstRatio, ratio);
      worstMs = msLarge;
    }
    // One confirmed bad shape is the answer for this rule.
    if (isBad) break;
  }
  const verdict =
    worstRatio >= QUADRATIC_RATIO && worstMs >= MIN_ABSOLUTE_MS_TO_FLAG ? 'super-linear' : 'linear';
  return {
    id: entry.id,
    ratio: Number(worstRatio.toFixed(2)),
    ms_at_200k: Number(worstMs.toFixed(1)),
    verdict,
  };
}

function loadEntries() {
  if (!fs.existsSync(CORE_DIST)) {
    console.error('[redos-sweep] packages/core/dist not found. Run `pnpm build` first.');
    process.exit(1);
  }
  const { getBuiltinPatternDocEntries } = require(CORE_DIST);
  return getBuiltinPatternDocEntries();
}

// ---------------------------------------------------------------------------
// Self-test: the six forms that WERE quadratic before 1.6.0.
// The harness must flag every one of them, or a clean sweep proves nothing.
// ---------------------------------------------------------------------------

const HISTORICAL_QUADRATIC = [
  { id: 'gcp-oauth@1.5', regexSource: '[0-9]+-[a-zA-Z0-9_]{32}\\.apps\\.googleusercontent\\.com', regexFlags: 'g' },
  { id: 'jwt-token@1.5', regexSource: 'eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+', regexFlags: 'g' },
  { id: 'postgresql-url@1.5', regexSource: 'postgres(?:ql)?:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)?\\/\\S+', regexFlags: 'g' },
  { id: 'mysql-url@1.5', regexSource: 'mysql:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)?\\/\\S+', regexFlags: 'g' },
  { id: 'mongodb-url@1.5', regexSource: 'mongodb(?:\\+srv)?:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)?', regexFlags: 'g' },
  { id: 'redis-url@1.5', regexSource: 'rediss?:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)', regexFlags: 'g' },
];

function runSelfTest() {
  console.log('[redos-sweep] self-test: replaying the six pre-1.6.0 quadratic forms.');
  console.log('              All six MUST be flagged, or a clean sweep means nothing.\n');
  const missed = [];
  for (const entry of HISTORICAL_QUADRATIC) {
    const r = measureRule(entry);
    const ok = r.verdict === 'super-linear';
    console.log(
      `  ${(ok ? 'DETECTED' : 'MISSED  ').padEnd(9)} ${r.id.padEnd(22)} ratio=${r.ratio}x  200k=${r.ms_at_200k}ms`,
    );
    if (!ok) missed.push(r.id);
  }
  if (missed.length > 0) {
    console.error(`\n[redos-sweep] SELF-TEST FAILED: missed ${missed.join(', ')}.`);
    console.error('              The harness cannot detect quadratic growth, so its');
    console.error('              "clean" verdict on the real table is meaningless.');
    process.exit(1);
  }
  console.log('\n[redos-sweep] SELF-TEST PASSED: all six detected.');
}

// ---------------------------------------------------------------------------

function main() {
  if (SELF_TEST) {
    runSelfTest();
    return;
  }

  const entries = loadEntries();
  const results = entries.map(measureRule);

  if (AS_JSON) {
    process.stdout.write(`${JSON.stringify({ results }, null, 2)}\n`);
  } else {
    console.log(`\n[redos-sweep] ${results.length} built-in patterns, ${SIZE_SMALL} vs ${SIZE_LARGE} chars\n`);
    for (const r of results) {
      const tag = r.verdict === 'super-linear' ? 'SUPER-LINEAR' : 'ok';
      const detail = r.ms_at_200k > 0 ? `ratio=${r.ratio}x  200k=${r.ms_at_200k}ms` : '(below noise floor)';
      console.log(`  ${tag.padEnd(13)} ${r.id.padEnd(22)} ${detail}`);
    }
  }

  if (UPDATE) {
    const baseline = {
      _comment:
        'Recorded output of scripts/redos-sweep.cjs. A pass means measured linear on the ' +
        'adversarial inputs this harness constructs, NOT a proof of linearity. Timing is ' +
        'machine-dependent: diff the `verdict` field, treat `ratio` as indicative only.',
      generatedAt: new Date().toISOString(),
      quadraticRatioThreshold: QUADRATIC_RATIO,
      sizes: { small: SIZE_SMALL, large: SIZE_LARGE },
      rules: Object.fromEntries(results.map(r => [r.id, { verdict: r.verdict, ratio: r.ratio }])),
    };
    fs.writeFileSync(BASELINE_FILE, `${JSON.stringify(baseline, null, 2)}\n`, 'utf-8');
    console.log(`\n[redos-sweep] baseline written to ${path.relative(REPO_ROOT, BASELINE_FILE)}`);
    return;
  }

  const flagged = results.filter(r => r.verdict === 'super-linear');

  // Diff against the recorded baseline. Only a VERDICT change is an error:
  // absolute timings move with the machine, so comparing ms would be noise.
  let drift = [];
  if (fs.existsSync(BASELINE_FILE)) {
    const baseline = JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf-8'));
    for (const r of results) {
      const b = baseline.rules[r.id];
      if (!b) {
        drift.push(`${r.id}: new rule, not in baseline (verdict ${r.verdict})`);
      } else if (b.verdict !== r.verdict) {
        drift.push(`${r.id}: verdict ${b.verdict} -> ${r.verdict}`);
      }
    }
    for (const id of Object.keys(baseline.rules)) {
      if (!results.some(r => r.id === id)) drift.push(`${id}: in baseline but no longer in the table`);
    }
  } else {
    drift.push('no baseline recorded; run with --update-baseline');
  }

  console.log('');
  if (flagged.length > 0) {
    console.error(`[redos-sweep] ${flagged.length} rule(s) measured SUPER-LINEAR:`);
    for (const f of flagged) console.error(`  - ${f.id}: ${f.ratio}x growth, ${f.ms_at_200k}ms at 200k`);
  } else {
    console.log('[redos-sweep] no rule measured super-linear.');
    console.log('              This means: measured linear on the inputs this harness');
    console.log('              constructs. It is NOT a proof of linearity.');
  }
  if (drift.length > 0) {
    console.error('\n[redos-sweep] baseline drift:');
    for (const d of drift) console.error(`  - ${d}`);
  }

  if (flagged.length > 0 || drift.length > 0) process.exit(1);
}

main();
