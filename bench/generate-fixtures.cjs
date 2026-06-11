#!/usr/bin/env node
/**
 * Generates the bench/fixtures/secrets/ directory at runtime.
 *
 * WHY THIS EXISTS
 * ---------------
 * Committing files that contain contiguous secret-shaped strings (even
 * synthetic ones) is blocked by GitHub Advanced Security push protection and
 * would also be flagged by vault-guard's own pre-commit hook.  Storing the
 * values as split fragments here prevents both triggers while still producing
 * realistic fixture files that exercise vault-guard's detection patterns.
 *
 * HOW IT WORKS
 * ------------
 * Each entry below has a `parts` array.  At generation time the parts are
 * joined to produce the full value.  No individual part matches a secret
 * pattern; the complete value does.  Generated files land in
 * bench/fixtures/secrets/ which is gitignored.
 *
 * Run automatically by bench/run.cjs before scanning.
 * Can also be run directly:  node bench/generate-fixtures.cjs
 */
'use strict';

const fs   = require('fs');
const path = require('path');

const OUT_DIR = path.join(__dirname, 'fixtures', 'secrets');
fs.mkdirSync(OUT_DIR, { recursive: true });

function write(filename, lines) {
  fs.writeFileSync(path.join(OUT_DIR, filename), lines.join('\n') + '\n', 'utf-8');
}

/** Write under fixtures/secrets/ preserving nested paths (e.g. caddytest/key.pem). */
function writeNested(relPath, content) {
  const full = path.join(OUT_DIR, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content, 'utf-8');
}

// ---------------------------------------------------------------------------
// Fixture definitions — parts joined at generation time
// ---------------------------------------------------------------------------

const fixtures = [
  {
    file: 'anthropic.ts',
    comment: 'True positive: Anthropic API key',
    lines: (j) => [
      `// ${j.comment}`,
      `const apiKey = ${JSON.stringify(
        ['sk-ant-', 'api03-', 'Zg7kP2mQxN4Rv', 'T8wYhLs6Fj', 'EbDcA9uKpViW3nOe', 'X1yMt5lHqJr0CsIzBdGfU-AAA'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai.ts',
    comment: 'True positive: OpenAI project key (sk-proj-…T3BlbkFJ…)',
    lines: (j) => [
      `// ${j.comment}`,
      // Split at the sk-proj- prefix boundary so no single string literal matches the
      // full pattern (sk-proj- alone is not a secret; the watermark+suffix fragment does
      // not start with the required prefix). The joined value is a real-shaped key.
      `const OPENAI_KEY = ${JSON.stringify(
        ['sk-proj-', 'aB3cD4eF5gH6iJ7kLmNoPqRsTuVw' + 'T3BlbkFJ' + 'xYz0123456789abcdefghijklmno'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai-svcacct.ts',
    comment: 'True positive: OpenAI service-account key (sk-svcacct-…T3BlbkFJ…)',
    lines: (j) => [
      `// ${j.comment}`,
      `const OPENAI_SVCACCT = ${JSON.stringify(
        ['sk-svcacct-', 'aB3cD4eF5gH6iJ7kLmNoPqRsTuVw' + 'T3BlbkFJ' + 'xYz0123456789abcdefghijklmno'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai-admin.ts',
    comment: 'True positive: OpenAI admin key (sk-admin-…T3BlbkFJ…)',
    lines: (j) => [
      `// ${j.comment}`,
      `const OPENAI_ADMIN = ${JSON.stringify(
        ['sk-admin-', 'aB3cD4eF5gH6iJ7kLmNoPqRsTuVw' + 'T3BlbkFJ' + 'xYz0123456789abcdefghijklmno'].join(''),
      )};`,
    ],
  },
  {
    file: 'openai-legacy.ts',
    comment: 'True positive: OpenAI legacy user key (sk-<20>T3BlbkFJ<20>)',
    lines: (j) => [
      `// ${j.comment}`,
      // Legacy format: sk- + exactly 20 alphanum + T3BlbkFJ + 20 alphanum (48 chars total after sk-)
      `const OPENAI_LEGACY = ${JSON.stringify(
        ['sk-', 'aB3cD4eF5gH6iJ7kLmNo' + 'T3BlbkFJ' + 'PqRsTuVwXyZ012345678'].join(''),
      )};`,
    ],
  },
  {
    file: 'aws.ts',
    comment: 'True positive: AWS access key',
    lines: (j) => [
      `// ${j.comment}`,
      `const AWS_ACCESS_KEY_ID = ${JSON.stringify(['AKIA', 'Z3KYR7N4QWXB2FGH'].join(''))};`,
    ],
  },
  {
    file: 'github.ts',
    comment: 'True positive: GitHub classic PAT',
    lines: (j) => [
      `// ${j.comment}`,
      `const GITHUB_TOKEN = ${JSON.stringify(['ghp_', 'AbCdEfGhIjKlMnOpQrStUv', 'WxYz0123456789AB'].join(''))};`,
      `const GITHUB_FINE  = ${JSON.stringify(['github_pat_11AB', 'CDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcde'].join(''))};`,
    ],
  },
  {
    file: 'stripe.ts',
    comment: 'True positive: Stripe live secret key',
    lines: (j) => [
      `// ${j.comment}`,
      `const STRIPE_LIVE = ${JSON.stringify(['sk_live_', 'AbCdEfGhIjKlMnOp', 'QrStUvWxYzAbCdEfGhIj', 'KlMnOpQrStUvWx'].join(''))};`,
    ],
  },
  {
    file: 'stripe-test-key.ts',
    comment: 'True positive: Stripe test key (real credential, sandbox scope)',
    lines: (j) => [
      `// ${j.comment}`,
      `const STRIPE_TEST = ${JSON.stringify(['sk_test_', 'AbCdEfGhIjKlMnOp', 'QrStUvWxYzAbCdEfGhIj', 'KlMnOpQrStUvWx'].join(''))};`,
    ],
  },
  {
    file: 'resend.ts',
    comment: 'True positive: Resend API key (standalone token, high entropy)',
    lines: (j) => [
      `// ${j.comment}`,
      `const RESEND_API_KEY = ${JSON.stringify(['re_', 'A1b2C3d4E5f6', 'G7h8J9k0L1m2', 'N3o4P5q6R7s8'].join(''))};`,
    ],
  },
  {
    file: 'slack.ts',
    comment: 'True positive: Slack incoming webhook URL',
    lines: (j) => [
      `// ${j.comment}`,
      `const SLACK_WEBHOOK = ${JSON.stringify(
        ['https://hooks.slack.com/services/', 'T01ABCDEF01/', 'B02GHIJKL02/', 'xyz123abc456def789ghi012'].join(''),
      )};`,
    ],
  },
  {
    file: 'database.ts',
    comment: 'True positive: database URL with real-looking credentials on a remote host',
    lines: (j) => [
      `// ${j.comment}`,
      `const DB_URL = ${JSON.stringify(
        ['postgresql://', 'admin:S3cur3P@ssw0rdXYZ@', 'prod-db.acme-corp.com:5432/app'].join(''),
      )};`,
    ],
  },
  {
    file: 'remote-dsn.ts',
    comment: 'True positive: remote PostgreSQL DSN — real host + real password (NOT local)',
    lines: (j) => [
      `// ${j.comment}`,
      `const PROD_DB = ${JSON.stringify(
        ['postgresql://', 'svc_app:Xj8kP2mQ9zRv@', 'db.prod.acme-corp.com:5432/main'].join(''),
      )};`,
    ],
  },
];

/**
 * Nested text fixtures (not limited to top-level .ts files).
 *
 * The PEM header/footer are stored as joined fragments for the SAME reason as
 * the secrets above: the marker `-----BEGIN <TYPE> PRIVATE KEY-----` matches
 * vault-guard's own `ssh-private-key` pattern, so a contiguous copy in this
 * committed file would be flagged by the pre-commit hook. The fragments are
 * split mid-word so no single string literal matches the detector, while the
 * joined result is a valid PEM marker.
 */
const nestedFixtures = [
  {
    relPath: 'caddytest/key.pem',
    comment: 'True positive: RSA private key in caddytest/ (path downgrades severity to low)',
    content: () =>
      [
        ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join('') + '\n',
        'MIIEpAIBAAKCAQEAx32kL3AXuPTjn0Wd0+wN653+urjWMRkWxU5W2NCCNLUDly3o\n',
        ['-----END RSA PRIV', 'ATE KEY-----'].join('') + '\n',
      ].join(''),
  },
];

// ---------------------------------------------------------------------------

let written = 0;
for (const f of fixtures) {
  write(f.file, f.lines(f));
  written++;
}
for (const f of nestedFixtures) {
  writeNested(f.relPath, f.content(f));
  written++;
}

if (process.env.BENCH_VERBOSE || process.argv.includes('--verbose')) {
  console.log(`[generate-fixtures] wrote ${written} fixture files to bench/fixtures/secrets/`);
}
