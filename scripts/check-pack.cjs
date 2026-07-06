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
const fs = require('node:fs');
const os = require('node:os');
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
let packFailed = false;
const npmCache = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-npm-pack-'));

for (const name of PACKAGES) {
  const dir = path.join(__dirname, '..', 'packages', name);
  let parsed;
  try {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      cwd: dir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        ...process.env,
        npm_config_cache: npmCache,
        npm_config_update_notifier: 'false',
      },
    });
    parsed = JSON.parse(out);
  } catch (e) {
    console.error(`check-pack: failed to pack ${name}: ${e.message}`);
    const stdout = typeof e.stdout === 'string' ? e.stdout : e.stdout?.toString('utf8');
    const stderr = typeof e.stderr === 'string' ? e.stderr : e.stderr?.toString('utf8');
    if (stdout?.trim()) console.error(stdout.trim());
    if (stderr?.trim()) console.error(stderr.trim());
    failed = true;
    packFailed = true;
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
  try {
    fs.rmSync(npmCache, { recursive: true, force: true });
  } catch {
    /* best-effort cleanup */
  }
  if (packFailed) {
    console.error('\ncheck-pack: npm pack failed. See the npm output above.');
  } else {
    console.error('\ncheck-pack: forbidden artifacts found. Fix tsconfig (sourceMap/declarationMap, exclude __tests__) before publishing.');
  }
  process.exit(1);
}
try {
  fs.rmSync(npmCache, { recursive: true, force: true });
} catch {
  /* best-effort cleanup */
}
console.log('\ncheck-pack: all publishable packages are clean.');
