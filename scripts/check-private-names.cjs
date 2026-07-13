#!/usr/bin/env node
/*
 * Public-repo hygiene guard: fail CI if tracked files contain private venture
 * codenames, internal workspace paths, or dogfood corpus references.
 *
 * See CONTRIBUTING.md § Public repository hygiene.
 */
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

// Instructional mentions in CONTRIBUTING and the checker itself are allowed.
const ALLOWLIST = new Set(['CONTRIBUTING.md', 'scripts/check-private-names.cjs']);

const PATTERNS = [
  { label: 'venture codename', re: /\b(kidcompass|sheetful|capitalcanvas|prismfolio|brightlet|nixblock|staysafe|medicalbillsuite|cosigned|translator-headphones)\b/i },
  { label: 'internal workspace path', re: /saldanham\/Desktop\/Projects\//i },
  { label: 'dogfood corpus path', re: /\bvg-oss-broad\b/i },
];

const files = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'buffer' })
  .toString('utf8')
  .split('\0')
  .filter(Boolean);

let failed = false;

for (const rel of files) {
  if (ALLOWLIST.has(rel)) continue;
  if (rel.startsWith('node_modules/')) continue;

  const abs = path.join(ROOT, rel);
  let text;
  try {
    text = require('node:fs').readFileSync(abs, 'utf8');
  } catch {
    continue;
  }

  for (const { label, re } of PATTERNS) {
    const match = text.match(re);
    if (match) {
      const line = text.slice(0, match.index).split('\n').length;
      console.error(`✗ ${rel}:${line}: ${label} (${match[0]})`);
      failed = true;
    }
  }
}

if (failed) {
  console.error('\ncheck-private-names: remove private portfolio references from tracked files.');
  console.error('See CONTRIBUTING.md § Public repository hygiene.');
  process.exit(1);
}

console.log('check-private-names: no private portfolio references in tracked files.');
