#!/usr/bin/env node
/**
 * Vault Guard precision / recall benchmark.
 *
 * Scans each labeled fixture with `vault-guard scan --format json` and
 * computes TP, FP, FN, TN, Precision, Recall, and F1.
 *
 * Optionally runs gitleaks (if installed) for a side-by-side comparison.
 *
 * Usage:
 *   node bench/run.cjs [--gitleaks] [--verbose]
 *   node bench/run.cjs --assert [--min-precision 1.0] [--min-recall 0.95]
 */
'use strict';

const { execSync, spawnSync } = require('child_process');
const fs   = require('fs');
const path = require('path');

const REPO_ROOT    = path.resolve(__dirname, '..');
const BENCH_DIR    = __dirname;
const LABELS_FILE  = path.join(BENCH_DIR, 'labels.json');
const BUILT_CLI    = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'cli-entry.js');

const args    = process.argv.slice(2);
const VERBOSE = args.includes('--verbose');
const DO_GL   = args.includes('--gitleaks');
const ASSERT  = args.includes('--assert');

function readFlagValue(flag, fallback) {
  const i = args.indexOf(flag);
  if (i === -1) return fallback;
  const raw = args[i + 1];
  if (raw === undefined || raw.startsWith('--')) {
    throw new Error(`Missing value for ${flag}`);
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 1) {
    throw new Error(`${flag} must be a number between 0 and 1 (got ${raw})`);
  }
  return n;
}

const MIN_PRECISION = readFlagValue('--min-precision', 1.0);
const MIN_RECALL    = readFlagValue('--min-recall', 0.95);

// Generate synthetic secret fixtures at runtime (stored as fragments in
// generate-fixtures.cjs so no contiguous secret pattern lives in git history).
require('./generate-fixtures.cjs');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function resolveVaultGuard() {
  // Prefer the local build so we always benchmark what's in this repo.
  if (fs.existsSync(BUILT_CLI)) return `node "${BUILT_CLI}"`;
  // Fall back to globally installed binary.
  try { execSync('vault-guard --version', { stdio: 'pipe' }); return 'vault-guard'; } catch { /* empty */ }
  throw new Error(
    'vault-guard binary not found. Run `pnpm build` first, or `npm i -g @vaultcompass/vault-guard`.',
  );
}

function scanFile(cmd, filePath) {
  const result = spawnSync(cmd, ['scan', filePath, '--format', 'json'], {
    shell:    true,
    encoding: 'utf-8',
    timeout:  30_000,
  });
  if (result.error) throw result.error;
  try {
    const parsed = JSON.parse(result.stdout);
    return Array.isArray(parsed.results) ? parsed.results : [];
  } catch {
    return [];
  }
}

function gitleaksScanFile(filePath) {
  const result = spawnSync(
    'gitleaks',
    ['detect', '--source', filePath, '--report-format', 'json', '--no-git'],
    { shell: true, encoding: 'utf-8', timeout: 30_000 },
  );
  if (result.error || result.status === null) return null;
  try {
    const parsed = JSON.parse(result.stdout || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return result.status === 0 ? [] : null;
  }
}

function pct(n, d) {
  if (d === 0) return '—';
  return ((n / d) * 100).toFixed(1) + '%';
}

function f1(p, r) {
  if (p === 0 && r === 0) return 0;
  return (2 * p * r) / (p + r);
}

function grade(precision, recall, f1Score) {
  if (f1Score >= 0.90 && precision >= 0.90) return 'A';
  if (f1Score >= 0.80 && precision >= 0.80) return 'B';
  if (f1Score >= 0.70 && precision >= 0.70) return 'C';
  if (f1Score >= 0.55) return 'D';
  return 'F';
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const labels = JSON.parse(fs.readFileSync(LABELS_FILE, 'utf-8'));
const vgCmd  = resolveVaultGuard();

const tools = [{ name: 'vault-guard', scan: f => scanFile(vgCmd, f) }];
if (DO_GL) {
  const glOk = spawnSync('gitleaks', ['version'], { shell: true, encoding: 'utf-8' }).status === 0;
  if (glOk) tools.push({ name: 'gitleaks', scan: gitleaksScanFile });
  else console.warn('[bench] gitleaks not found — skipping comparison.\n');
}

console.log(`\n${'='.repeat(64)}`);
console.log('  Vault Guard Benchmark');
const corpusSize = Object.keys(labels).filter(k => !k.startsWith('_')).length;
console.log(`  Corpus: ${corpusSize} labeled fixtures`);
console.log(`  Binary: ${vgCmd}`);
if (ASSERT) {
  console.log(`  Assert: precision >= ${(MIN_PRECISION * 100).toFixed(1)}%, recall >= ${(MIN_RECALL * 100).toFixed(1)}%`);
}
console.log('='.repeat(64) + '\n');

/** @type {{ name: string, precision: number, recall: number, f1Score: number } | null} */
let vaultGuardMetrics = null;

for (const tool of tools) {
  let TP = 0, FP = 0, FN = 0, TN = 0;
  const rows = [];

  for (const [relPath, label] of Object.entries(labels)) {
    if (relPath.startsWith('_')) continue;
    const filePath = path.join(BENCH_DIR, relPath);
    if (!fs.existsSync(filePath)) {
      rows.push({ relPath, expected: label.shouldDetect, got: false, findings: 0, status: 'MISSING' });
      continue;
    }

    const findings = tool.scan(filePath);
    const detected = Array.isArray(findings) && findings.length > 0;

    let status;
    if (label.shouldDetect && detected)  { TP++; status = 'TP ✓'; }
    else if (!label.shouldDetect && !detected) { TN++; status = 'TN ✓'; }
    else if (label.shouldDetect && !detected)  { FN++; status = 'FN ✗'; }
    else                                       { FP++; status = 'FP ✗'; }

    rows.push({ relPath, expected: label.shouldDetect, got: detected, findings: Array.isArray(findings) ? findings.length : 0, status, note: label.note });
  }

  if (VERBOSE) {
    const colW = Math.max(...rows.map(r => r.relPath.length)) + 2;
    for (const r of rows) {
      console.log(`  ${r.status.padEnd(6)} ${r.relPath.padEnd(colW)} findings=${String(r.findings).padStart(2)}  ${r.note ?? ''}`);
    }
    console.log();
  }

  const total     = TP + FP + FN + TN;
  const precision = TP + FP > 0 ? TP / (TP + FP) : 1;
  const recall    = TP + FN > 0 ? TP / (TP + FN) : 1;
  const f1Score   = f1(precision, recall);
  const toolGrade = grade(precision, recall, f1Score);

  console.log(`  Tool: ${tool.name}`);
  console.log(`  ${'─'.repeat(40)}`);
  console.log(`  Corpus size : ${total} files`);
  console.log(`  TP          : ${TP}`);
  console.log(`  FP          : ${FP}`);
  console.log(`  FN          : ${FN}`);
  console.log(`  TN          : ${TN}`);
  console.log(`  Precision   : ${pct(TP, TP + FP)}  (TP / (TP+FP))`);
  console.log(`  Recall      : ${pct(TP, TP + FN)}  (TP / (TP+FN))`);
  console.log(`  F1          : ${f1Score > 0 ? (f1Score * 100).toFixed(1) + '%' : '—'}`);
  console.log(`  Grade       : ${toolGrade}`);
  console.log();

  if (tool.name === 'vault-guard') {
    vaultGuardMetrics = { name: tool.name, precision, recall, f1Score };
  }
}

if (ASSERT) {
  if (!vaultGuardMetrics) {
    console.error('[bench] --assert requires vault-guard metrics but none were collected.');
    process.exit(1);
  }
  const failures = [];
  if (vaultGuardMetrics.precision < MIN_PRECISION) {
    failures.push(
      `precision ${(vaultGuardMetrics.precision * 100).toFixed(1)}% < floor ${(MIN_PRECISION * 100).toFixed(1)}%`,
    );
  }
  if (vaultGuardMetrics.recall < MIN_RECALL) {
    failures.push(
      `recall ${(vaultGuardMetrics.recall * 100).toFixed(1)}% < floor ${(MIN_RECALL * 100).toFixed(1)}%`,
    );
  }
  if (failures.length > 0) {
    console.error('[bench] ASSERT FAILED:');
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }
  console.log('[bench] ASSERT PASSED: vault-guard metrics meet configured floors.');
}
