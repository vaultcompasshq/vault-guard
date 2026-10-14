/**
 * Pattern IDs downgraded to `low` in test/fixture/documentation paths (not suppressed).
 */
export const LOW_PRECISION_PATH_DOWNGRADE_IDS = new Set([
  'password-in-code',
  'api-key-generic',
  'secret-generic',
  'bearer-token',
  'postgresql-url',
  'mysql-url',
  'mongodb-url',
  'redis-url',
  'ssh-private-key',
  'jwt-token',
]);

/**
 * The rules a LOCALE path may downgrade (design 2026-10-12, section 5). A
 * positive list of what may drop, not the low-precision list minus
 * exceptions, so a rule added to that list later is not downgraded on locale
 * paths without a decision. Connection strings, private keys and JWTs keep
 * their severity: a two-letter `db.ts` or a `messages/` tree is exactly where
 * a DSN lives.
 */
export const LOCALE_PATH_DOWNGRADE_IDS = new Set([
  'password-in-code',
  'api-key-generic',
  'secret-generic',
  'bearer-token',
]);

// Vendor-anchored rules (anthropic, openai, stripe, aws-access, github-token,
// slack, ...) are deliberately NOT in this list and there is no separate
// documentation-only list for them: a live provider key pasted into a README,
// CLAUDE.md or a docs page is still a live key. Docs and test paths downgrade
// only the low-precision generic patterns above.
