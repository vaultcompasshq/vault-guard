import path from 'path';
import type { SecretMatch } from '../types';
import { isDocumentationPath } from './doc-context';
import { contextPathFor, splitPathParts } from './path-parts';
import { LOCALE_PATH_DOWNGRADE_IDS, LOW_PRECISION_PATH_DOWNGRADE_IDS } from './path-downgrade-ids';

/**
 * Pattern IDs whose severity is downgraded to `low` in obvious test / fixture
 * paths. Two groups:
 *
 *   - Low-precision generic patterns (`password-in-code`, …) -- common in test
 *     scaffolding and rarely real leaks there.
 *   - Connection strings and key/token shapes (`postgresql-url`,
 *     `ssh-private-key`, `jwt-token`, …) -- test suites are full of throwaway
 *     DSNs, fixture PEMs, and sample tokens. Downgrading (not suppressing)
 *     keeps them visible at `low` without drowning real criticals.
 *
 * Hard vendor-anchored API-key patterns (anthropic, aws-access, stripe,
 * github-token, …) are intentionally **absent** from test-path downgrades: a real
 * provider key is a real key even in a test file, and those patterns have
 * near-zero false positives. The same holds in documentation and markdown: a
 * live key pasted into CLAUDE.md or a docs page is still a live key, so docs
 * paths get no vendor downgrade either.
 */
const TEST_PATH_DOWNGRADE_IDS = LOW_PRECISION_PATH_DOWNGRADE_IDS;

/**
 * Downgrade-eligible rules that documentation paths do NOT downgrade. The PEM
 * rule only fires when key material follows the header (a bare header is
 * suppressed upstream), so a hit in a docs or markdown file is a real private
 * key, not a label. Test / fixture paths still downgrade it.
 */
const DOCS_EXEMPT_IDS = new Set(['ssh-private-key']);

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
  'fixture',
  'testdata',
  'test-data',
  'test_data',
  'testfixtures',
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
  // Rust. Cargo has no separate directory for unit tests, so a crate's tests
  // live beside its source: `src/auth/auth_tests.rs` next to `src/auth/auth.rs`.
  // Both the singular and plural suffix are in common use.
  /_tests?\.rs$/,
];

/** Env template basenames -- never production secrets. */
const FIXTURE_ENV_BASENAME = /^\.env(\.[a-z0-9_-]+)*\.(example|sample|template)$/i;

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

/** Directory segments holding UI translation catalogues. */
const LOCALE_DIR_SEGMENTS = new Set([
  'locales',
  'locale',
  'translations',
  'translation',
  'i18n',
  'lang',
  'langs',
]);

/**
 * True when a file sits under a translation-catalogue directory.
 *
 * Catalogues are natural-language strings keyed by identifiers, so a key such
 * as `tfa_secret` or `api_key_label` puts a translated *label* where the
 * generic assignment patterns expect a value -- `tfa_secret: Zwei-Faktor-
 * Authentifizierung` reads as a 29-character high-entropy secret.
 *
 * Only a locale DIRECTORY on the path counts (design 2026-10-12, section 5).
 * A two-letter file name alone (`db.ts`, `ci.yml`, `sa.json`) used to count,
 * which downgraded DSNs, private keys and JWTs in those files to `low`.
 */
export function isLocalePath(filePath: string): boolean {
  return splitPathParts(filePath).some(p => LOCALE_DIR_SEGMENTS.has(p.toLowerCase()));
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
 * (aws-access, anthropic, stripe, …) are unaffected -- a real key in a test
 * file is still worth a `critical` alert.
 */
function isLowPrecisionContextPath(filePath: string): boolean {
  return isTestFilePath(filePath) || isDocumentationPath(filePath) || isLocalePath(filePath);
}

/**
 * `pathRoot` is the directory the scan is rooted at. Context is judged on
 * `filePath` relative to it (see {@link contextPathFor}), so directories above
 * the scanned tree never count as test or documentation context.
 */
export function applyPathAwareSeverity(
  matches: SecretMatch[],
  filePath: string,
  pathRoot?: string,
): SecretMatch[] {
  if (matches.length === 0) return matches;
  const ctxPath = contextPathFor(filePath, pathRoot);
  if (!isLowPrecisionContextPath(ctxPath)) return matches;
  // A match is downgraded when ANY context the path is in allows its rule:
  // a test path the low-precision set (throwaway PEMs and DSNs live there),
  // a documentation path that set without the PEM rule (a full-body key
  // pasted into CLAUDE.md is a leak), a locale path only the four generic
  // rules. The union replaces a docs-only special case that read "not a
  // locale path" as permission to downgrade the PEM rule.
  const test = isTestFilePath(ctxPath);
  const docs = isDocumentationPath(ctxPath);
  const locale = isLocalePath(ctxPath);
  const allowed = (id: string): boolean =>
    (test && TEST_PATH_DOWNGRADE_IDS.has(id)) ||
    (docs && TEST_PATH_DOWNGRADE_IDS.has(id) && !DOCS_EXEMPT_IDS.has(id)) ||
    (locale && LOCALE_PATH_DOWNGRADE_IDS.has(id));

  return matches.map(m => {
    if (allowed(m.type) && m.severity !== 'low') {
      return { ...m, severity: 'low' as const };
    }
    return m;
  });
}
