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

// Vendor-anchored rules (anthropic, openai, stripe, aws-access, github-token,
// slack, ...) are deliberately NOT in this list and there is no separate
// documentation-only list for them: a live provider key pasted into a README,
// CLAUDE.md or a docs page is still a live key. Docs and test paths downgrade
// only the low-precision generic patterns above.
