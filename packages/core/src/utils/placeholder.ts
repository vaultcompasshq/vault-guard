/**
 * Recognise obviously non-secret placeholder / example / test values so that
 * broad patterns stop firing on documentation samples and unit-test fixtures  -- 
 * empirically the dominant real-world false-positive source (e.g. AWS's own
 * documented `AKIAIOSFODNN7EXAMPLE` key, or `const password = 'testPass1234'`).
 *
 * Two tiers, by precision cost:
 *
 *   - `standard` (safe for every pattern, including vendor-anchored keys):
 *     unambiguous markers that effectively never occur inside a real generated
 *     credential -- `EXAMPLE`, `changeme`, `your_token_here`, all-`x` padding, …
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

/** Unambiguous placeholder markers -- applied to all patterns. */
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
  'replace-with',
  'replace_with',
  'loremipsum',
  // Pure character repetition (e.g. `xxxxxxxx`, `00000000`) is handled by the
  // low-variety check below rather than literal markers, so it does not clash
  // with real keys that merely contain a short repeated run.
];

/** Common test / fixture markers -- applied only to generic assignment patterns. */
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
  'your_', // your_google_places_key, your_api_key_here
  'your-', // your-anthropic-api-key -- hyphen form is just as common in docs
];

/** Known vendor key prefixes whose remainder is often redacted with X/* in docs. */
const REDACTED_PREFIXES: readonly RegExp[] = [
  /^sk_live_/i,
  /^sk_test_/i,
  /^sk-ant-api\d+-/i,
  /^sk-proj-/i,
  /^sk-/i,
  /^pk_live_/i,
  /^pk_test_/i,
  /^re_/i,
  /^whsec_/i,
  /^phc_/i,
  /^AIza/i,
  /^ghp_/i,
  /^gho_/i,
  /^npm_/i,
  /^xox[baprs]-/i,
];

export function isRedactedTemplateValue(value: string): boolean {
  if (!value) return false;
  if (/^replace-with-/i.test(value)) return true;
  if (value.length >= 8 && /^[Xx*]+$/.test(value)) return true;
  for (const prefix of REDACTED_PREFIXES) {
    const m = prefix.exec(value);
    if (!m) continue;
    const rest = value.slice(m[0].length);
    if (rest.length >= 8 && /^[Xx*_.-]+$/.test(rest)) return true;
  }
  return false;
}

/**
 * A `dckr_pat_` value with too short a suffix to be one Docker issued.
 *
 * Real Docker personal access tokens carry a long random suffix (27 characters
 * at the time of writing). API reference docs show a keyboard-mash value such as
 * `dckr_pat_124509ugsdjga93` under a `secret` key, which the generic assignment
 * rule reports. Used for the generic rules ONLY: a vendor-anchored rule is never
 * weakened by it. The threshold is 20, below the issued length, so a real token
 * is never judged by it.
 */
export function isShortDockerPatExample(value: string): boolean {
  return /^dckr_pat_[A-Za-z0-9_-]{1,19}$/.test(value);
}

/**
 * A stored password *hash* is the safe-at-rest form of a credential, not a
 * credential. Seed data, fixtures, and migration files are full of them, and
 * flagging them as `password-in-code` is noise: rotating them is meaningless
 * and they cannot be used to authenticate.
 *
 * Covers modular crypt format (bcrypt `$2a/2b/2y$`, sha-crypt `$1/5/6$`,
 * yescrypt `$y$`, `$argon2i/d/id$`, `$pbkdf2-*$`) and the Django/Passlib
 * `algo$iterations$salt$hash` convention.
 */
export function isPasswordHash(value: string): boolean {
  if (/^\$(?:2[abxy]?|1|5|6|7|y|gy|argon2(?:i|d|id)?|scrypt|pbkdf2(?:-[a-z0-9]+)?|sha1|md5|apr1|bcrypt)\$/i.test(value)) {
    return true;
  }
  // Django: pbkdf2_sha256$390000$<salt>$<hash>, argon2$..., bcrypt_sha256$...
  return /^(?:pbkdf2_[a-z0-9]+|argon2[a-z]*|bcrypt(?:_sha256)?|scrypt|sha1|md5|crypt|unsalted_[a-z0-9]+)\$\d*\$?/i.test(value);
}

/**
 * True when a PEM `-----BEGIN … PRIVATE KEY-----` header is not followed by
 * any key material.
 *
 * UI code and documentation carry the header on its own as a label or an
 * input placeholder (`const privateKeyBeginsWith = '-----BEGIN RSA PRIVATE
 * KEY-----'`). A header with no body leaks nothing. A body is base64 and
 * nothing else, however the author folded it: one long line, the usual 64 or
 * 76 columns, or any narrower fold (`openssl` reads a key refolded at 16 or 32
 * columns just the same). So a body is either a single base64 token of 40 or
 * more characters, or a run of single-token base64 lines of one width (the last
 * may be shorter) whose joined text is long and mixed enough not to be prose.
 * Indentation, CRLF, comment leaders and the JSON `\n` escape are peeled off
 * first.
 */
export function isPemHeaderWithoutBody(content: string, headerEndOffset: number): boolean {
  // Judge the text between this header and the END marker that closes it (or
  // the next BEGIN, or the cap when neither exists). A fixed 400-character
  // window missed any key whose armor headers ran long.
  let region = content.slice(headerEndOffset, headerEndOffset + PEM_REGION_CAP);
  const stop = /-----(END|BEGIN) /.exec(region);
  // A matching END footer makes the whole span between the two armor lines the
  // body, at whatever widths the author folded it (see the end of this function).
  const hasFooter = stop !== null && stop[1] === 'END';
  if (stop !== null) region = region.slice(0, stop.index);

  // Newlines can hide as XML character references.
  region = region.replace(/&#(?:x0*[aAdD]|0*1[03]);/g, '\n');
  // Or as markup and escapes: `<br>`, `<br/>` and the JSON `\u000a` / `\u000d`.
  region = region.replace(/<br\s*\/?>|\\u000[aAdD]/gi, '\n');

  // Split on real newlines and on the escaped `\n` used when a key is embedded
  // in JSON, YAML or a string literal.
  const lines = region.split(/\r?\n|\\r\\n|\\n|\\r/);

  // Single-token base64 lines in a row: a candidate narrow-folded body.
  let run: string[] = [];
  const runIsBody = (): boolean => {
    if (run.length < 2) return false;
    // The fold width is the longest line but the last. Peeling a token's
    // trailing `+` (list syntax, in `cleanPemToken`) can shorten a base64 line
    // by a character or two, so a line within two of the width is the same width.
    let width = 0;
    for (let i = 0; i < run.length - 1; i++) width = Math.max(width, run[i].length);
    if (width < 14) return false;
    for (let i = 0; i < run.length - 1; i++) if (run[i].length < width - 2) return false;
    if (run[run.length - 1].length > width) return false;
    const joined = run.join('');
    return joined.length >= 40 && /[a-z]/.test(joined) && /[A-Z]/.test(joined) && /[0-9+/]/.test(joined);
  };

  // Between a header and its footer: every non-blank line one base64 token.
  const between: string[] = [];
  let betweenOk = true;

  // A truncated example: an ellipsis line (`...`, the Unicode ellipsis, `[...]`,
  // `<snip>`) between the armor lines, with only a little base64 around it. It
  // would otherwise read as a blank line. The cap is 48 base64 characters, counted
  // BEFORE `cleanPemToken` peels a trailing `+` (list syntax, but also a base64
  // character: about one line in 64 ends in one). The smallest real body is 64
  // (Ed25519 PKCS8), so 48 leaves 16 characters of margin for that peeling and
  // for line ends the author trimmed, and a documentation example (a few lines,
  // truncated) stays under it. A full-length body with a stray ellipsis line is
  // not declined, so the line cannot be used to hide a whole key.
  if (hasFooter && lines.some(isEllipsisLine)) {
    let base64Chars = 0;
    for (const line of lines) {
      if (isEllipsisLine(line)) continue;
      for (const raw of line.split(/\s+/)) {
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleanPemToken(raw))) continue;
        base64Chars += raw.replace(/^[^A-Za-z0-9+/]+|[^A-Za-z0-9+/=]+$/g, '').length;
      }
    }
    if (base64Chars < ELLIPSIS_BODY_CAP) return true;
  }

  // The last line with anything on it: only there may a padding-only line stand.
  let lastLineWithTokens = -1;
  lines.forEach((l, i) => {
    if (l.split(/\s+/).some(r => cleanPemToken(r) !== '')) lastLineWithTokens = i;
  });

  let lineNo = -1;
  for (const line of lines) {
    lineNo++;
    const tokens: string[] = [];
    for (const raw of line.split(/\s+/)) {
      const token = cleanPemToken(raw);
      if (token !== '') tokens.push(token);
    }
    if (tokens.length === 0) continue;
    // A `=` or `==` on a line of its own is base64 padding folded onto a new line,
    // and that is a body line only as the LAST one; it adds nothing to the length.
    if (tokens.length === 1 && /^={1,2}$/.test(tokens[0])) {
      if (lineNo !== lastLineWithTokens) betweenOk = false;
    } else if (tokens.length === 1 && /^[A-Za-z0-9+/]+={0,2}$/.test(tokens[0])) between.push(tokens[0]);
    // An RFC 1421 header of a legacy encrypted key (`Proc-Type: 4,ENCRYPTED`, `DEK-Info: ...`).
    else if (!/^\s*[A-Za-z][A-Za-z0-9-]*:\s/.test(line)) betweenOk = false;

    // A body line is base64 and nothing else, after comment markers and string
    // syntax are peeled off. Requiring EVERY token on the line to be base64 is
    // what separates it from surrounding code and prose: `ssh-rsa AAAA...
    // user@host` and `const x = someLongIdentifier;` each carry a token that is
    // not.
    if (!tokens.every(t => /^[A-Za-z0-9+/]+={0,2}$/.test(t))) {
      if (runIsBody()) return false;
      run = [];
      continue;
    }

    // Length and character mix separate a body from English: at least 40
    // characters, mixed case, and a digit or + or /. A 64-character random
    // base64 line lacks all of digit, + and / with probability about
    // (52/64)^64, roughly one in a million; English words never carry a digit.
    // A body flattened onto one line with spaces yields one such token per
    // original line, so the tokens that qualify must make up nearly all of the
    // line: a long token inside a sentence of short words does not.
    let bodyChars = 0;
    let allChars = 0;
    for (const t of tokens) {
      allChars += t.length;
      if (t.length >= 40 && /[a-z]/.test(t) && /[A-Z]/.test(t) && /[0-9+/]/.test(t)) {
        bodyChars += t.length;
      }
    }
    if (bodyChars > 0 && bodyChars / allChars >= 0.85) return false;

    if (tokens.length === 1) {
      run.push(tokens[0]);
    } else {
      if (runIsBody()) return false;
      run = [];
    }
  }

  if (runIsBody()) return false;

  // With a footer the body is whatever lies between the armor lines: parsers
  // (OpenSSL 3 among them) accept lines of any width, so an author who folds a
  // key unevenly must not make it read as a label. Every non-blank line has to
  // be one base64 token (a sentence is several), and the joined text has to be
  // long enough to be key material and mixed the way base64 is, which English
  // words are not (no digit, no `+` or `/`).
  if (hasFooter && betweenOk) {
    const joined = between.join('');
    if (joined.length >= 64 && /[a-z]/.test(joined) && /[A-Z]/.test(joined) && /[0-9+/]/.test(joined)) return false;
  }
  return true;
}

/** Base64 characters around an ellipsis line below which the span is a truncated example. */
const ELLIPSIS_BODY_CAP = 48;

/** A line that only marks something left out: `...`, the Unicode ellipsis, `[...]`, `<snip>`. */
function isEllipsisLine(line: string): boolean {
  const t = line.replace(/^[\s#>;*/"'`,[(<-]+|[\s"'`,;\])>]+$/g, '');
  return /^(?:\.{3,}|\u2026+|snip)$/i.test(t);
}

/** How far past a PEM header the body check looks when no END marker bounds it. */
const PEM_REGION_CAP = 8192;

/**
 * Peel what surrounds a base64 body line in the places keys get pasted: comment
 * leaders (`#`, `//`, `*`, `>`, `--`, `;`), a Python string prefix (`b"`, `r'`),
 * quotes and brackets, and the trailing comma, plus or semicolon of a literal.
 * A leading or trailing `+` or `/` can be a base64 character, but losing one
 * from a 64-character line cannot change a verdict that needs 40.
 */
function cleanPemToken(raw: string): string {
  let t = raw;
  for (let i = 0; i < 4; i++) {
    const before = t;
    t = t
      .replace(/^(?:[#>;%|*]+|\/{2,}|-{2,})/, '')
      .replace(/^[bBrRuUfF]{1,2}(?=["'`])/, '')
      .replace(/^["'`[({\\]+/, '');
    if (t === before) break;
  }
  t = t.replace(/[\s"'`\])},;+\\.&|]+$/, '');
  // A token that is only an operator or list marker (a YAML `-`, a line
  // continuation `_`) carries no content and must not fail the line.
  return /^[-.&|+_]+$/.test(t) ? '' : t;
}

/**
 * ALL_CAPS identifiers (e.g. `PLAID_TOKEN_ENCRYPTION_KEY`) are env-var names,
 * not secret values -- common in GitHub Actions `secret:NAME` checks.
 */
export function isEnvVarNameToken(value: string): boolean {
  return /^[A-Z][A-Z0-9_]{7,}$/.test(value);
}

/**
 * True when an **unquoted** captured value is a reference to a code
 * identifier rather than a literal credential -- e.g.
 *
 *     headers: { 'x-api-key': scheduledIngestApiKey }
 *     api_key = defaultServiceCredential
 *
 * The generic assignment patterns capture whatever follows `:`/`=`, and in
 * real code that is very often a variable, not a secret. An existing check
 * covers the function-call case (`= makeKey(...)`); this covers the far more
 * common bare-reference case.
 *
 * Discriminator: generated credentials are random, so they mix digits into the
 * alphabet and do not decompose into word-shaped segments. We require the
 * value to split (on `_` and camelCase boundaries) into **two or more**
 * segments that are each purely alphabetic and at least two characters long.
 *
 *   `scheduledIngestApiKey` → scheduled | Ingest | Api | Key  → identifier
 *   `default_service_token` → default | service | token       → identifier
 *   `x7Kf9mQ2pL8vB3nR5wT1`  → contains digits                 → NOT identifier
 *   `qwertyuiopasdfghjklz`  → one segment                     → NOT identifier
 *
 * Callers must only apply this to unquoted values on low-precision generic
 * patterns; a quoted string literal is a literal, and vendor-anchored rules
 * must never be weakened by it.
 */
export function isCodeIdentifierReference(value: string): boolean {
  if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(value)) return false;
  if (/\d/.test(value)) return false;

  const segments = value
    .replace(/\$/g, '_')
    .split('_')
    .filter(s => s.length > 0)
    .flatMap(part => part.split(/(?=[A-Z])/));

  if (segments.length < 2) return false;
  if (!segments.every(s => s.length >= 2 && /^[A-Za-z]+$/.test(s))) return false;

  // Guard against alpha-only random keys with alternating capitals
  // (`PmZkQvXtLdRwNbGhYuJcEaSf` splits into twelve 2-char "segments"). Real
  // identifiers are made of words, so beyond a handful of segments the mean
  // segment length stays word-like. Values of three segments or fewer are
  // exempt: `myApiKey` is a legitimate identifier with short parts.
  if (segments.length > 3) {
    const mean = segments.reduce((n, s) => n + s.length, 0) / segments.length;
    if (mean < 3) return false;
  }

  return true;
}

/**
 * A value made of one or two distinct characters (e.g. `xxxxxxxx`, `00000000`)
 * is padding, never a real secret.
 */
function isLowVariety(value: string): boolean {
  return value.length >= 8 && new Set(value).size <= 2;
}

/**
 * Fraction of a value that must sit inside sequential runs before it is called
 * a placeholder.
 *
 * Chosen at 0.75 to sit clearly between the two cases that bound it. A value
 * that is half run and half random scores 0.50 and must survive, because a real
 * credential can contain an incidental run. A genuine alphabet-run placeholder
 * under a real vendor prefix scores at worst about 0.80: `AKIA` + `ABCDEF…P` is
 * 16 run characters in a 20-character value, because the fixed prefix is part
 * of the matched value and is not itself a run. 0.75 clears the first with a
 * 25-point margin and admits the second with a 5-point one.
 */
export const SEQUENTIAL_RUN_COVERAGE_THRESHOLD = 0.75;

/** Shortest run of consecutive code points that counts as sequential. */
const SEQUENTIAL_RUN_MIN_LENGTH = 3;

/**
 * Below this length, coverage is not evidence of anything: a four-character
 * value is trivially "all run". Every pattern that reaches this check matches
 * far longer values than this.
 */
const SEQUENTIAL_RUN_MIN_VALUE_LENGTH = 12;

/**
 * True when `value` is mostly made of runs of consecutive code points:
 * `abcdefghijklmnopqrstuvwxyz0123456789`, `ABCDEFGHIJKLMNOP`, `zyxwvu…`, or the
 * same short run repeated.
 *
 * WHY THIS EXISTS SEPARATELY FROM THE ENTROPY GATE
 * ------------------------------------------------
 * Shannon entropy counts how often each character occurs and throws the order
 * away. A strict alphabet run uses every character exactly once, which is the
 * flattest possible frequency distribution, so it scores at or near the maximum
 * for its length, higher than most real credentials. The entropy gate is
 * therefore structurally blind to the single most common way a developer types
 * a fake key by hand, and no threshold tuning can fix that: order is the signal,
 * and entropy does not look at order.
 *
 * Unlike the entropy gate this check runs for vendor-anchored rules too, which
 * is where it matters most, since those rules have no entropy gate at all. It is
 * safe there for the same reason it is useful: a real provider key is generated
 * from a random source and cannot come out as the alphabet.
 */
export function isSequentialRunPlaceholder(value: string): boolean {
  if (value.length < SEQUENTIAL_RUN_MIN_VALUE_LENGTH) return false;

  const covered: boolean[] = new Array(value.length).fill(false);

  let i = 0;
  while (i < value.length - 1) {
    const step = value.charCodeAt(i + 1) - value.charCodeAt(i);
    if (step !== 1 && step !== -1) {
      i++;
      continue;
    }

    let end = i + 1;
    while (end + 1 < value.length && value.charCodeAt(end + 1) - value.charCodeAt(end) === step) {
      end++;
    }

    if (end - i + 1 >= SEQUENTIAL_RUN_MIN_LENGTH) {
      for (let k = i; k <= end; k++) covered[k] = true;
    }
    i = end;
  }

  let inRuns = 0;
  for (const c of covered) if (c) inRuns++;

  return inRuns / value.length >= SEQUENTIAL_RUN_COVERAGE_THRESHOLD;
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
 * connection string. Deliberately scoped to the *password* -- usernames like
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
 * credential leak -- i.e. it targets a local/dev/docker/example host, or uses
 * obvious placeholder/default credentials.
 *
 * The exploitable secret in a DSN is the password against a *reachable* host.
 * We suppress when either:
 *   1. the host is local, a bare docker-compose service name, or a reserved
 *      TLD (`localhost`, `mysql`, `db.local`, …) -- not remotely reachable; or
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
    /\b1516239022\b/.test(payload) ||
    // Supabase ships fixed anon / service_role keys for local development.
    // They are printed by `supabase start`, published in Supabase's own docs,
    // and signed with a well-known secret, so they appear verbatim in a large
    // share of Supabase projects. Same category as the jwt.io sample.
    /"iss"\s*:\s*"supabase-demo"/.test(payload)
  );
}

export function isNonSecretConnectionString(url: string): boolean {
  const d = connectionStringDeclines(url);
  return d.host || d.password;
}

/**
 * Why {@link isNonSecretConnectionString} declines a connection string, kept
 * apart: the HOST is text the repository chose (`db`, `localhost`, `x.local`),
 * while a placeholder PASSWORD is the credential itself.
 */
export function connectionStringDeclines(url: string): { host: boolean; password: boolean } {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^:@/\s]*):([^@/\s]+)@([^:/?\s]+)/i.exec(url);
  if (!m) return { host: false, password: false };

  const user = m[1];
  const pass = m[2];
  const host = m[3].toLowerCase();

  // 1. Non-routable / local / docker-service / reserved-TLD host.
  const hostDeclines =
    LOCAL_HOSTS.has(host) ||
    LOCAL_TLD_SUFFIXES.some(suffix => host.endsWith(suffix)) ||
    // Bare single-token host with no dot (and not a raw IPv4) is a docker-compose
    // service name (`mysql`, `db`, `postgres`) -- local to a compose network.
    (!host.includes('.') && !host.includes(':') && !/^\d+$/.test(host));

  // 2. Placeholder / default password.
  return { host: hostDeclines, password: passwordLooksPlaceholder(user, pass) };
}

/** Whether a connection string's password is a placeholder or a default (`root:root`, `USER:PASSWORD`, `${DB_PASS}`). */
export function passwordLooksPlaceholder(user: string, pass: string): boolean {
  const p = pass.toLowerCase();
  return (
    PLACEHOLDER_PASSWORDS.has(p) ||
    user.toLowerCase() === p || // root:root, prisma:prisma
    /^[A-Z][A-Z0-9_]*$/.test(pass) || // USER:PASSWORD, DBPASS
    pass.startsWith('$') ||
    pass.startsWith('<') ||
    pass.startsWith('{') || // ${DB_PASS}, <pw>
    /^\*+$/.test(pass) || // masked by Celery and Kombu: redis://:**@host
    /^%[A-Za-z_][A-Za-z0-9_]*%$/.test(pass) || // %REDIS_PW% (Windows environment variable)
    /^["'`][+.&][\w.$[\]()]+[+.&]["'`]$/.test(pass) || // '+pw+' (a string concatenation, no spaces)
    isPlaceholderSecret(pass, { aggressive: true })
  );
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

/** The passwords a `--no-repo-controls` run accepts as placeholders, whole and case-insensitive. */
const EXACT_PLACEHOLDER_WORDS = new Set([
  'password',
  'passwd',
  'pass',
  'pw',
  'secret',
  'changeme',
  'change_me',
  'example',
  'test',
  'dummy',
  'placeholder',
  'redacted',
  'your_password',
  'yourpassword',
  'mypassword',
]);

/**
 * Whether the inside of a template form reads as a NAME (`DB_PASSWORD`,
 * `db.password`, `your-password`, `password 1`) and not as a secret wrapped in
 * brackets: at most 64 characters; a letter or underscore first; then letters,
 * digits, `_`, `.`, `-` or single spaces; and, with the separators removed, one
 * case of letters only (so no camelCase, no mixed-case random text) plus at
 * most three digits in all (so no digit run of four or more).
 */
export function isNameShaped(inside: string): boolean {
  if (inside.length === 0 || inside.length > 64) return false;
  if (!/^[A-Za-z_][A-Za-z0-9_.\- ]*$/.test(inside) || / {2}/.test(inside)) return false;
  const core = inside.replace(/[_.\- ]/g, '');
  const digits = core.replace(/[^0-9]/g, '').length;
  const letters = core.replace(/[0-9]/g, '');
  const oneCase = letters === letters.toLowerCase() || letters === letters.toUpperCase();
  return digits <= 3 && oneCase;
}

/** The inside of a `${X}`, `$X`, `<X>`, `{X}`, `{{X}}` or `$(X)` template, or undefined. */
function templateInside(pass: string): string | undefined {
  return (
    /^\$\{([^{}]*)\}$/.exec(pass)?.[1] ??
    /^\$([A-Za-z_][A-Za-z0-9_]*)$/.exec(pass)?.[1] ??
    /^<([^<>]*)>$/.exec(pass)?.[1] ??
    /^\{\{ ?([^{}]*?) ?\}\}$/.exec(pass)?.[1] ??
    /^\{([^{}]*)\}$/.exec(pass)?.[1] ??
    /^\$\(([^()]*)\)$/.exec(pass)?.[1]
  );
}

/** A password that is exactly a placeholder word, a run of x or *, or entirely a name-shaped template. */
export function isExactPlaceholderPassword(pass: string): boolean {
  if (EXACT_PLACEHOLDER_WORDS.has(pass.toLowerCase())) return true;
  if (/^x{3,}$/i.test(pass) || /^\*+$/.test(pass)) return true;
  const inside = templateInside(pass);
  return inside !== undefined && isNameShaped(inside);
}

/**
 * Whether a whole URL token (from the scheme to the next whitespace or quote) is
 * a counted placeholder in a run that does not trust the repository's text. All
 * of: the token has no `%` (an encoded character the driver decodes), no `?` and
 * no `#` (a query or fragment a driver reads a password from) and exactly one
 * `@` (so the end of the userinfo is not a guess); and the password, taken
 * whole, is exactly a placeholder word or template. No substring marker, no
 * "user equals password", no host rule: all of those are text the repository
 * chooses. For the Azure rule: the one `AccountKey=` value is exactly a
 * placeholder form. Anything else is kept.
 */
export function isExactPlaceholderUrl(type: string, token: string): boolean {
  if (type === 'azure-storage') {
    const keys = [...token.matchAll(/AccountKey=([^;\s"']*)/g)].map(m => m[1]);
    return keys.length === 1 && isExactPlaceholderPassword(keys[0]);
  }
  if (/[%?#]/.test(token)) return false;
  if (token.split('@').length !== 2) return false;
  const m = /^[a-z][a-z0-9+.-]*:\/\/[^:@/]*:([^@]*)@/i.exec(token);
  return m !== null && isExactPlaceholderPassword(m[1]);
}
