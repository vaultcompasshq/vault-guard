/**
 * Recognise obviously non-secret placeholder / example / test values so that
 * broad patterns stop firing on documentation samples and unit-test fixtures —
 * empirically the dominant real-world false-positive source (e.g. AWS's own
 * documented `AKIAIOSFODNN7EXAMPLE` key, or `const password = 'testPass1234'`).
 *
 * Two tiers, by precision cost:
 *
 *   - `standard` (safe for every pattern, including vendor-anchored keys):
 *     unambiguous markers that effectively never occur inside a real generated
 *     credential — `EXAMPLE`, `changeme`, `your_token_here`, all-`x` padding, …
 *
 *   - `aggressive` (opt-in, used only by the low-precision generic / password
 *     assignment patterns): additionally treats common test-fixture words
 *     (`test`, `sample`, `password`, …) as placeholders. Scoped to those
 *     patterns so vendor-anchored keys keep full recall.
 *
 * Matching is substring-based on the lower-cased value. Markers are chosen to
 * be long/specific enough that a real high-entropy secret will not contain them
 * by chance.
 */

/** Unambiguous placeholder markers — applied to all patterns. */
const STANDARD_MARKERS: readonly string[] = [
  'example',
  'changeme',
  'change-me',
  'change_me',
  'placeholder',
  'redacted',
  'notreal',
  'not-a-real',
  'dummy',
  'yourtoken',
  'yourkey',
  'yourapikey',
  'your_token',
  'your-token',
  'your_key',
  'your-key',
  'your_api_key',
  'your-api-key',
  'insertyour',
  'insert_your',
  'replace_me',
  'replaceme',
  'loremipsum',
  // Pure character repetition (e.g. `xxxxxxxx`, `00000000`) is handled by the
  // low-variety check below rather than literal markers, so it does not clash
  // with real keys that merely contain a short repeated run.
];

/** Common test / fixture markers — applied only to generic assignment patterns. */
const AGGRESSIVE_MARKERS: readonly string[] = [
  'test',
  'sample',
  'demo',
  'fake',
  'mock',
  'foobar',
  'password',
  'passw0rd',
  'secret',
  'sensitive',
  'hunter2',
  'qwerty',
  'letmein',
];

/**
 * A value made of one or two distinct characters (e.g. `xxxxxxxx`, `00000000`)
 * is padding, never a real secret.
 */
function isLowVariety(value: string): boolean {
  return value.length >= 8 && new Set(value).size <= 2;
}

/** Hosts that are never a remotely-exploitable credential leak. */
const LOCAL_HOSTS: ReadonlySet<string> = new Set([
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  '[::1]',
  'host.docker.internal',
]);

/** Reserved / non-routable TLD suffixes (RFC 6761 + docker/dev conventions). */
const LOCAL_TLD_SUFFIXES: readonly string[] = [
  '.local',
  '.localhost',
  '.test',
  '.example',
  '.invalid',
];

/**
 * Password tokens that are obviously defaults / placeholders rather than a
 * real secret. Matched case-insensitively against the password component of a
 * connection string. Deliberately scoped to the *password* — usernames like
 * `admin` / `root` / `postgres` are extremely common in genuine leaks, so we
 * never suppress based on the username alone.
 */
const PLACEHOLDER_PASSWORDS: ReadonlySet<string> = new Set([
  'password', 'passwd', 'pass', 'pwd', 'secret',
  'changeme', 'example', 'test', 'user', 'username',
  'root', 'admin', 'postgres', 'mysql', 'mongo', 'mongodb', 'redis',
  'db', 'database', 'prisma', 'identifier', 'key', 'token', 'name',
  'randompassword', 'yourpassword', 'mypassword',
]);

/**
 * Return `true` when a database/Redis connection string is **not** a real
 * credential leak — i.e. it targets a local/dev/docker/example host, or uses
 * obvious placeholder/default credentials.
 *
 * The exploitable secret in a DSN is the password against a *reachable* host.
 * We suppress when either:
 *   1. the host is local, a bare docker-compose service name, or a reserved
 *      TLD (`localhost`, `mysql`, `db.local`, …) — not remotely reachable; or
 *   2. the password is a placeholder/default (`pass`, `PASSWORD`, `root:root`,
 *      `${DB_PASS}`, `<your-password>`, …).
 *
 * A real remote host with a real password (e.g.
 * `postgres://app:8Fk2$mQ9z@db.prod.example-corp.com/main`) is **not**
 * suppressed.
 */
/**
 * Recognise the canonical jwt.io / RFC 7519 sample token that is pasted into
 * countless READMEs, OpenAPI specs, and tutorials. Its decoded payload carries
 * the well-known sample claims (`sub: "1234567890"`, `name: "John Doe"`,
 * `iat: 1516239022`). These are never real credentials.
 */
export function isSampleJwt(token: string): boolean {
  const parts = token.split('.');
  if (parts.length < 2 || !parts[1]) return false;
  let payload: string;
  try {
    payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
  } catch {
    return false;
  }
  return (
    /"sub"\s*:\s*"1234567890"/.test(payload) ||
    /"name"\s*:\s*"John Doe"/.test(payload) ||
    /\b1516239022\b/.test(payload)
  );
}

export function isNonSecretConnectionString(url: string): boolean {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^:@/\s]+):([^@/\s]+)@([^:/?\s]+)/i.exec(url);
  if (!m) return false;

  const user = m[1];
  const pass = m[2];
  const host = m[3].toLowerCase();

  // 1. Non-routable / local / docker-service / reserved-TLD host.
  if (LOCAL_HOSTS.has(host)) return true;
  if (LOCAL_TLD_SUFFIXES.some(suffix => host.endsWith(suffix))) return true;
  // Bare single-token host with no dot (and not a raw IPv4) is a docker-compose
  // service name (`mysql`, `db`, `postgres`) — local to a compose network.
  if (!host.includes('.') && !host.includes(':') && !/^\d+$/.test(host)) return true;

  // 2. Placeholder / default password.
  const p = pass.toLowerCase();
  if (PLACEHOLDER_PASSWORDS.has(p)) return true;
  if (user.toLowerCase() === p) return true;            // root:root, prisma:prisma
  if (/^[A-Z][A-Z0-9_]*$/.test(pass)) return true;      // USER:PASSWORD, DBPASS
  if (pass.startsWith('$') || pass.startsWith('<') || pass.startsWith('{')) return true; // ${DB_PASS}, <pw>
  if (isPlaceholderSecret(pass, { aggressive: true })) return true;

  return false;
}

/**
 * @returns `true` when `value` looks like a placeholder / example / test
 * credential and should be suppressed.
 */
export function isPlaceholderSecret(
  value: string,
  opts: { aggressive?: boolean } = {},
): boolean {
  if (!value) return false;
  const v = value.toLowerCase();

  for (const marker of STANDARD_MARKERS) {
    if (v.includes(marker)) return true;
  }

  if (isLowVariety(value)) return true;

  if (opts.aggressive) {
    for (const marker of AGGRESSIVE_MARKERS) {
      if (v.includes(marker)) return true;
    }
  }

  return false;
}
