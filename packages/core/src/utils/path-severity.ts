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
]);

/**
 * File name suffixes / extensions that mark test or fixture files.
 * Checked against `path.basename(filePath)`.
 */
const TEST_FILE_PATTERNS = [
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /\.test\.api\.[jt]sx?$/,
  /\.fixture\.[jt]sx?$/,
];

/**
 * Return `true` when `filePath` looks like a test or fixture file.
 */
export function isTestFilePath(filePath: string): boolean {
  const parts = filePath.split(path.sep).flatMap(p => p.split('/'));
  if (parts.some(seg => TEST_DIR_SEGMENTS.has(seg))) return true;
  const basename = path.basename(filePath);
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
