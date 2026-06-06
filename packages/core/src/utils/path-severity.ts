import path from 'path';
import type { SecretMatch } from '../types';

/**
 * Pattern IDs whose severity is downgraded to `low` in obvious test / fixture
 * paths. Two groups:
 *
 *   - Low-precision generic patterns (`password-in-code`, …) — common in test
 *     scaffolding and rarely real leaks there.
 *   - Connection strings and key/token shapes (`postgresql-url`,
 *     `ssh-private-key`, `jwt-token`, …) — test suites are full of throwaway
 *     DSNs, fixture PEMs, and sample tokens. Downgrading (not suppressing)
 *     keeps them visible at `low` without drowning real criticals.
 *
 * Hard vendor-anchored API-key patterns (anthropic, aws-access, stripe,
 * github-token, …) are intentionally **absent**: a real provider key is a real
 * key even in a test file, and those patterns have near-zero false positives.
 */
const TEST_PATH_DOWNGRADE_IDS = new Set([
  // generic / assignment
  'password-in-code',
  'api-key-generic',
  'secret-generic',
  'bearer-token',
  // connection strings
  'postgresql-url',
  'mysql-url',
  'mongodb-url',
  'redis-url',
  // key / token shapes
  'ssh-private-key',
  'jwt-token',
]);

/**
 * Segments that indicate a file lives in a test / fixture tree.
 * Matched against every directory component in the file path.
 */
const TEST_DIR_SEGMENTS = new Set([
  '__tests__',
  '__mocks__',
  'tests',
  'test',
  'fixtures',
  'testdata',
  'spec',
  'e2e',
  'examples',
  'example',
  'samples',
  'sample',
]);

/**
 * Directory names ending in `test` that are **not** test roots (e.g. `contest/`).
 */
const NON_TEST_TEST_SUFFIX_DIRS = new Set(['contest', 'latest', 'shortest']);

/**
 * File name suffixes / extensions that mark test or fixture files.
 * Checked against `path.basename(filePath)`.
 */
const TEST_FILE_PATTERNS = [
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /\.test\.api\.[jt]sx?$/,
  /\.fixture\.[jt]sx?$/,
  /_test\.go$/,
  /^test_[^/]+\.py$/i,
  /^[^/]+_test\.py$/i,
];

/** Env template basenames — never production secrets. */
const FIXTURE_ENV_BASENAME = /^\.env\.(example|sample|template|local\.example)$/;

function splitPathParts(filePath: string): string[] {
  return filePath.split(path.sep).flatMap(p => p.split('/'));
}

/**
 * True when a path segment names a test/fixture directory, including common
 * `*test` suffixes (`caddytest/`, `integrationtest/`) but not `contest/`.
 */
function isTestDirectorySegment(seg: string): boolean {
  if (TEST_DIR_SEGMENTS.has(seg)) return true;
  return (
    seg.endsWith('test') &&
    seg.length >= 7 &&
    !NON_TEST_TEST_SUFFIX_DIRS.has(seg)
  );
}

/**
 * Celery / Perl-style test root: `t/unit/…`, `t/integration/…`.
 */
function isCeleryStyleTestRoot(parts: string[]): boolean {
  for (let i = 0; i < parts.length - 1; i++) {
    const next = parts[i + 1];
    if (parts[i] === 't' && (next === 'unit' || next === 'integration')) {
      return true;
    }
  }
  return false;
}

/**
 * Return `true` when `filePath` looks like a test or fixture file.
 */
export function isTestFilePath(filePath: string): boolean {
  const parts = splitPathParts(filePath);
  if (parts.some(isTestDirectorySegment)) return true;
  if (isCeleryStyleTestRoot(parts)) return true;

  const basename = path.basename(filePath);
  if (FIXTURE_ENV_BASENAME.test(basename)) return true;

  return TEST_FILE_PATTERNS.some(re => re.test(basename));
}

/**
 * Downgrade low-precision generic pattern findings to `'low'` severity when
 * they appear inside a test / fixture file.
 *
 * Rationale: password assignments, bearer tokens, and generic api-key patterns
 * are common in test scaffolding (`const password = 'Admin1234!'`) and are
 * rarely real leaked credentials in that context. Vendor-anchored patterns
 * (aws-access, anthropic, stripe, …) are unaffected — a real key in a test
 * file is still worth a `critical` alert.
 */
export function applyPathAwareSeverity(
  matches: SecretMatch[],
  filePath: string,
): SecretMatch[] {
  if (matches.length === 0) return matches;
  if (!isTestFilePath(filePath)) return matches;

  return matches.map(m => {
    if (!TEST_PATH_DOWNGRADE_IDS.has(m.type)) return m;
    if (m.severity === 'low') return m;
    return { ...m, severity: 'low' as const };
  });
}
