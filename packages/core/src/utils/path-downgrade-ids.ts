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
 * Vendor-anchored patterns downgraded to `low` in documentation paths only.
 */
export const DOCS_VENDOR_DOWNGRADE_IDS = new Set([
  'anthropic',
  'openai',
  'openai-project',
  'stripe',
  'stripe-test',
  'aws-access',
  'gcp-api-key',
  'gcp-oauth',
  'resend-api',
  'github-token',
  'sendgrid-api',
  'slack-webhook',
  'slack-token',
]);
