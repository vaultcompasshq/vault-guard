#!/usr/bin/env node
/*
 * Pre-publish tarball guard.
 *
 * A security tool must not ship source maps, test code, or test helpers in its
 * published npm package: they bloat the tarball, leak internal structure, and
 * (in the case of test helpers misnamed away from `*.test.ts`) slip past the
 * tsconfig `exclude`. This script runs `npm pack --dry-run` for every
 * publishable workspace package and fails CI if any forbidden artifact would
 * be published.
 *
 * Run after `pnpm build`. Wired into CI and the release workflow before publish.
 */
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const PACKAGES = ['core', 'cli', 'telemetry', 'mcp'];

// Anything matching these must never appear in a published tarball.
const FORBIDDEN = [
  { label: 'source map', test: f => /\.map$/.test(f) },
  { label: 'test directory', test: f => /(^|\/)__tests__(\/|$)/.test(f) },
  { label: 'test helper', test: f => /test-helpers?\b/.test(f) },
  { label: 'test file', test: f => /\.(test|spec)\.[cm]?[jt]s$/.test(f) },
];

let failed = false;

for (const name of PACKAGES) {
  const dir = path.join(__dirname, '..', 'packages', name);
  let parsed;
  try {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    parsed = JSON.parse(out);
  } catch (e) {
    console.error(`check-pack: failed to pack ${name}: ${e.message}`);
    failed = true;
    continue;
  }

  const files = (parsed[0]?.files ?? []).map(f => f.path);
  const offenders = [];
  for (const file of files) {
    const hit = FORBIDDEN.find(rule => rule.test(file));
    if (hit) offenders.push(`${file}  (${hit.label})`);
  }

  if (offenders.length > 0) {
    failed = true;
    console.error(`\n\u2717 ${parsed[0]?.name ?? name}: ${offenders.length} forbidden artifact(s) in tarball:`);
    for (const o of offenders) console.error(`    ${o}`);
  } else {
    console.log(`\u2713 ${parsed[0]?.name ?? name}: clean (${files.length} files)`);
  }
}

if (failed) {
  console.error('\ncheck-pack: forbidden artifacts found. Fix tsconfig (sourceMap/declarationMap, exclude __tests__) before publishing.');
  process.exit(1);
}
console.log('\ncheck-pack: all publishable packages are clean.');
