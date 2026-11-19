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
 * True when a PEM `-----BEGIN ... PRIVATE KEY-----` header is not followed by
 * any key material.
 *
 * UI code and documentation carry the header on its own as a label or an
 * input placeholder (`const privateKeyBeginsWith = '-----BEGIN RSA PRIVATE
 * KEY-----'`), or around dummy bodies. A header with no body leaks nothing.
 *
 * A key 1.13.4 reported is still reported (`declinedBy1134` is its function,
 * unchanged: any line of the region that is a base64 token of 40 or more
 * characters, mixed case with a digit, `+` or `/`, is a body). In addition, a
 * key it missed is reported when the second path finds one. A header is
 * declined only when both paths decline it, so recall is a superset of 1.13.4's
 * by construction, and only the second path can add a false positive.
 *
 * The second path reads what `openssl` reads: a body is base64 and nothing
 * else, however it is folded (8, 16 or 32 columns, or unevenly). Indentation,
 * CRLF, comment leaders, quotes and the JSON `\n` escape are peeled off first.
 * A run of single-token base64 lines is a body when:
 *  - it is 64 or more characters in all (an Ed25519 PKCS8 key is the smallest),
 *    mixed-case with a digit, `+` or `/`, not a run of the alphabet (steps of
 *    1 or 2 over the first 128 characters), and the lines after the first read
 *    as key material (see {@link looksLikeKeyMaterial}). The first line is left
 *    out because documentation puts a realistic `MIIE...` prefix there and
 *    filler after it;
 *  - no placeholder marker (`example`, `redacted`, `fake`, `sample` ...) in the
 *    first or last 128 characters of the body, the first line and the middle of
 *    a token included, and the body does not base64-decode to mostly printable
 *    ASCII (85% of its first 144 bytes: an encoded sentence; random bytes are 37%
 *    and the highest of about 9,000 real keys (Ed25519, X25519, EC, RSA) was 67%);
 *  - a `=` or `==` counts only as the last line and adds no length, and a last
 *    line of only `+` or `/` characters is the end of the body, not syntax;
 *  - with an END footer the run is the span between the armor lines at any
 *    widths. Only the RFC 1421 header lines of a legacy encrypted key
 *    (`Proc-Type:`, `DEK-Info:`, `Comment:`, case-sensitive, after a literal's
 *    quote or comment punctuation) may be non-base64; any other such line
 *    vetoes it;
 *  - without a footer the run starts on the line directly after the header
 *    (only blank and RFC 1421 lines between), so the header must end its line.
 *    Lines of syntax only (the `\n" +` of a string concatenation) are skipped;
 *    an empty line or a non-base64 line ends it; its lines are of one width of
 *    at least 14 columns (the last may be shorter; a line two short is the same
 *    width);
 *  - a line that says something is left out splits the run into pieces, with a
 *    footer or without: `...`, `. . .`, the ellipsis character, `[...]`,
 *    `<snip>`, `etc.`, `(truncated)`, a lone word (`omitted`, `TRUNCATED`,
 *    `snipped`, `[elided]`, `cut` ...), or a base64 token that ends in dots.
 *    Each piece is judged alone and must be 128 characters (twice the smallest
 *    body). The cost: a real key of 64 to 127 characters with a stray omission
 *    line in it is not found by this path (1.13.4's rule still reports it when
 *    one line has 40 or more characters).
 */
export function isPemHeaderWithoutBody(content: string, headerEndOffset: number): boolean {
  // The header is declined only when BOTH paths decline it, so a key 1.13.4 reported
  // is reported whichever runs first. The order is a cost choice: 1.13.4 finds a
  // standard 64-column body on its first line, so it goes first; a body whose first
  // line is shorter than 40 columns is certain to need the second path, which can
  // then end the work (and skip the 1.13.4 scan) when it finds the body.
  if (NARROW_FIRST_LINE.test(content.slice(headerEndOffset, headerEndOffset + 80))) {
    return declinedByNewPath(content, headerEndOffset) && declinedBy1134(content, headerEndOffset);
  }
  return declinedBy1134(content, headerEndOffset) && declinedByNewPath(content, headerEndOffset);
}

/** A first line after the header that is base64 of 14 to 39 characters: a narrow fold. */
const NARROW_FIRST_LINE = /^\s*[A-Za-z0-9+/]{14,39}\s/;

/**
 * The 1.13.4 decision, verbatim from origin/main (only its name differs; its
 * helper `cleanPemToken` differs by one linear expression, proved equal by a
 * property test). True when no line of the region is a base64 token of 40 or
 * more characters. The exported function declines only when this AND the second
 * path decline, so the result is the same whichever runs first (when the first
 * line after the header is a narrow fold the second path runs first, to save
 * the 1.13.4 scan when it finds the body): a key 1.13.4 reported is reported by
 * construction.
 */
/** @internal exported for the superset property test only; not part of the package API. */
export function declinedBy1134(content: string, headerEndOffset: number): boolean {
  // Judge the text between this header and the END marker that closes it (or
  // the next BEGIN, or the cap when neither exists). A fixed 400-character
  // window missed any key whose armor headers ran long.
  let region = content.slice(headerEndOffset, headerEndOffset + PEM_REGION_CAP);
  const stop = region.search(/-----(?:END|BEGIN) /);
  if (stop >= 0) region = region.slice(0, stop);

  // Newlines can hide as XML character references.
  region = region.replace(/&#(?:x0*[aAdD]|0*1[03]);/g, '\n');
  // Or as markup and escapes: `<br>`, `<br/>` and the JSON `\u000a` / `\u000d`.
  region = region.replace(/<br\s*\/?>|\\u000[aAdD]/gi, '\n');

  // Split on real newlines and on the escaped `\n` used when a key is embedded
  // in JSON, YAML or a string literal.
  const lines = region.split(/\r?\n|\\r\\n|\\n|\\r/);

  for (const line of lines) {
    const tokens: string[] = [];
    for (const raw of line.split(/\s+/)) {
      const token = cleanPemToken(raw);
      if (token !== '') tokens.push(token);
    }
    if (tokens.length === 0) continue;

    // A PEM body wraps base64 at 64 characters, so a body line is base64 and
    // nothing else, after comment markers and string syntax are peeled off.
    // Requiring EVERY token on the line to be base64 is what separates it from
    // surrounding code and prose: `ssh-rsa AAAA... user@host` and
    // `const x = someLongIdentifier;` each carry a token that is not.
    if (!tokens.every(t => /^[A-Za-z0-9+/]+={0,2}$/.test(t))) continue;

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
  }

  return true;
}

/** Escaped or markup newlines inside a region: when none is present the two replaces below are skipped. */
const PEM_NEWLINE_HIDING = /&#|<br|\\u000/i;
const ALL_SPACE = /^\s*$/;

/** How many characters after the header must hold something other than whitespace for the second path to read on. */
const PEM_GATE = 400;

function declinedByNewPath(content: string, headerEndOffset: number): boolean {
  // Gate: nothing but whitespace for the next 400 characters cannot start a body, and
  // is not read further (a header followed by a long run of spaces).
  if (ALL_SPACE.test(content.slice(headerEndOffset, headerEndOffset + PEM_GATE))) return true;
  // Judge the text between this header and the END marker that closes it (or
  // the next BEGIN, or the cap when neither exists). A fixed 400-character
  // window missed any key whose armor headers ran long.
  let region = content.slice(headerEndOffset, headerEndOffset + PEM_REGION_CAP);
  const stop = /-----(END|BEGIN) /.exec(region);
  const hasFooter = stop !== null && stop[1] === 'END';
  if (stop !== null) region = region.slice(0, stop.index);

  if (PEM_NEWLINE_HIDING.test(region)) {
    // Newlines can hide as XML character references.
    region = region.replace(/&#(?:x0*[aAdD]|0*1[03]);/g, '\n');
    // Or as markup and escapes: `<br>`, `<br/>` and the JSON `\u000a` / `\u000d`.
    region = region.replace(/<br\s*\/?>|\\u000[aAdD]/gi, '\n');
  }

  // Split on real newlines and on the escaped `\n` used when a key is embedded
  // in JSON, YAML or a string literal.
  const lines = region.split(/\r?\n|\\r\\n|\\n|\\r/);

  // Lines are classified on demand, so a header that is a label (code or prose
  // follows it) costs a line or two, not the whole region.
  const cache: Array<PemLine | undefined> = [];
  let lastIdx = lines.length - 1;
  while (lastIdx >= 1 && ALL_SPACE.test(lines[lastIdx])) lastIdx--;
  const info = (i: number): PemLine => {
    let l = cache[i];
    if (l === undefined) {
      l = classifyPemLine(lines[i]);
      // A last line of only `+` and `/` characters is the end of a body that a fold left
      // alone on a line (an Ed25519 body is 64 characters; at 21 or 9 columns one remains),
      // not list syntax: keep it as base64.
      if (i === lastIdx && i >= 1 && (l.kind === 'blank' || l.kind === 'b64') && info(i - 1).kind === 'b64') {
        const plus = LONE_PLUS.exec(lines[i]);
        if (plus !== null) l = { tokens: [plus[1]], kind: 'b64' };
      }
      cache[i] = l;
    }
    return l;
  };

  const isB64 = (i: PemLine): boolean => i.kind === 'b64';

  if (!hasFooter) {
    // The header must end its line, apart from the punctuation the peeling
    // understands (a closing quote, a comma, a concatenation operator).
    if (info(0).tokens.length > 0) return true;
    let i = 1;
    while (i < lines.length) {
      const k = info(i).kind;
      if (k !== 'blank' && k !== 'empty' && k !== 'rfc') break;
      i++;
    }
    // The run that starts on the first line with content. A line of only syntax (the
    // `\n" +` of a string concatenation) is skipped; an empty line, or any line that
    // is not base64, ends it, so two blocks are never joined across a gap. An
    // omission line splits it into pieces.
    let piece: PemLine[] = [];
    const pieces: PemLine[][] = [piece];
    for (; i < lines.length; i++) {
      const l = info(i);
      if (l.kind === 'b64' || l.kind === 'multi' || l.kind === 'pad') piece.push(l);
      else if (l.kind === 'ellipsis') {
        if (l.tokens.length === 1) piece.push({ tokens: l.tokens, kind: 'b64' });
        pieces.push((piece = []));
      } else if (l.kind !== 'blank') break;
    }
    const need = pieces.length > 1 ? 2 * PEM_BODY_MIN : PEM_BODY_MIN;
    return !pieces.some(pc => {
      const ls = trailingPadding(pc);
      return ls.length >= 2 && ls.every(isB64) && isUniformBody(ls.map(l => l.tokens[0]), need);
    });
  }

  // With a footer: the whole span between the armor lines, read until the first
  // veto. A line that is neither base64 nor an RFC 1421 header, a several-token
  // line, or content after a padding line, vetoes the span as a body.
  let piece: string[] = [];
  const pieces: string[][] = [piece];
  let padSeen = false;
  for (let i = 0; i < lines.length; i++) {
    const l = info(i);
    if (l.kind === 'other' || l.kind === 'multi') return true;
    if (padSeen && l.tokens.length > 0) return true;
    if (l.kind === 'pad') padSeen = true;
    else if (l.kind === 'ellipsis') {
      // Split at ellipsis lines (blank lines are tolerated inside a piece).
      if (l.tokens.length === 1) piece.push(l.tokens[0]);
      pieces.push((piece = []));
    } else if (l.kind === 'b64') piece.push(l.tokens[0]);
  }
  // An ellipsis in the span means a cut: a piece before or after it is a body only
  // if it is itself twice the smallest key body (a truncated example trails off
  // after a few lines; a real key with a stray ellipsis line has most of its
  // length on each side).
  const need = pieces.length > 1 ? 2 * PEM_BODY_MIN : PEM_BODY_MIN;
  return !pieces.some(p => p.length >= 2 && isBodySpan(p, need));
}

/** A line of a PEM region, classified. */
interface PemLine {
  /** The tokens left once comment leaders, quotes and string syntax are peeled. */
  tokens: string[];
  kind: 'blank' | 'empty' | 'ellipsis' | 'pad' | 'b64' | 'multi' | 'rfc' | 'other';
}

const PEM_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** The only RFC 1421 header lines a legacy key carries, with the quote and concatenation punctuation of a literal in front. */
const RFC1421_LINE = /^[\s"'`#>;*/+,([{\\]*(?:Proc-Type|DEK-Info|Comment):/;

/** A last line that is only `+` and `/` characters (with the quotes and commas of a literal). */
const LONE_PLUS = /^[\s"'`,;]*([+/]+)[\s"'`,;]*$/;

const CLOSERS = new Set([' ', '\t', '\r', '\n', '\f', '\v', '"', "'", '`', ']', ')', '}', ',', ';']);

/** `s` without the trailing characters in `set`, found by a scan from the end (a regex `[...]+$` is quadratic on a long run that is not at the end). */
function trimEndSet(s: string, set: ReadonlySet<string>): string {
  let e = s.length;
  while (e > 0 && set.has(s[e - 1])) e--;
  return e === s.length ? s : s.slice(0, e);
}

function trimStartSet(s: string, set: ReadonlySet<string>): string {
  let b = 0;
  while (b < s.length && set.has(s[b])) b++;
  return b === 0 ? s : s.slice(b);
}

const PEM_PURE_BASE64 = /^[A-Za-z0-9+/]{10,}={0,2}$/;

function classifyPemLine(line: string): PemLine {
  // The common case, a line of nothing but base64: no peeling to do.
  if (line.length >= 10 && PEM_PURE_BASE64.test(line)) return { tokens: [line], kind: 'b64' };
  if (ALL_SPACE.test(line)) return { tokens: [], kind: 'empty' };
  // Every test below ignores surrounding whitespace; trimming once (natively) keeps a long
  // run of spaces from being walked a character at a time by each of them.
  line = line.trim();
  if (isEllipsisLine(line)) return { tokens: [], kind: 'ellipsis' };
  const tokens: string[] = [];
  for (const raw of line.split(/\s+/)) {
    let t = cleanPemToken(raw);
    // A trailing `+` is peeled as list syntax but is also a base64 character, and
    // one in six Ed25519 bodies has one at a fold boundary: keep it when the token
    // is a base64 token (not a lone operator) so the body keeps its length.
    const closed = trimEndSet(raw, CLOSERS);
    let k = closed.length;
    while (k > 0 && closed[k - 1] === '+') k--;
    const plusRun = closed.slice(k);
    if (t !== '' && plusRun !== '' && PEM_BASE64.test(`${t}${plusRun}`)) t += plusRun;
    // Likewise a base64 line that begins with `//` (a comment leader peeled off).
    const slashes = /^\/{2,}/.exec(raw);
    if (t !== '' && slashes !== null && PEM_BASE64.test(`${slashes[0]}${t}`)) t = `${slashes[0]}${t}`;
    if (t !== '') {
      tokens.push(t);
      // The first token that is not base64 settles the line as prose or code; the
      // rest of it need not be peeled.
      if (!PEM_BASE64.test(t)) break;
    }
  }
  if (RFC1421_LINE.test(line)) return { tokens, kind: 'rfc' };
  if (tokens.length === 0) return { tokens, kind: line.trim() === '' ? 'empty' : 'blank' };
  if (tokens.length === 1 && /^={1,2}$/.test(tokens[0])) return { tokens, kind: 'pad' };
  // A single base64 token that trails off (`MIIEpAIB...`): the dots are peeled, but
  // the line says the rest is left out, so it ends a piece.
  if (tokens.length === 1 && PEM_BASE64.test(tokens[0]) && endsWithEllipsis(line)) return { tokens, kind: 'ellipsis' };
  if (tokens.every(t => PEM_BASE64.test(t))) return { tokens, kind: tokens.length === 1 ? 'b64' : 'multi' };
  return { tokens, kind: 'other' };
}

/** The lines of a block with a padding-only line at the very end dropped. */
function trailingPadding(block: PemLine[]): PemLine[] {
  const last = block[block.length - 1];
  return last !== undefined && last.kind === 'pad' ? block.slice(0, -1) : block;
}

/** The size of the smallest real key body: an Ed25519 PKCS8 key is 64 base64 characters. */
const PEM_BODY_MIN = 64;

/** Lines of one fold width: the longest but the last is the width (at least 14), the last is no longer. */
function isUniformBody(tokens: string[], min = PEM_BODY_MIN): boolean {
  if (tokens.length < 2) return false;
  // Peeling a trailing `+` (list syntax, in `cleanPemToken`) can shorten a base64
  // line by a character or two, so a line within two of the width is the same width.
  let width = 0;
  for (let i = 0; i < tokens.length - 1; i++) width = Math.max(width, tokens[i].length);
  if (width < 14) return false;
  for (let i = 0; i < tokens.length - 1; i++) if (tokens[i].length < width - 2) return false;
  if (tokens[tokens.length - 1].length > width) return false;
  return isBodySpan(tokens, min);
}

/** Single-token base64 lines that together are a key body: long enough, mixed, and the lines after the first look like key material. */
function isBodySpan(tokens: string[], min = PEM_BODY_MIN): boolean {
  const joined = tokens.join('');
  if (joined.length < min) return false;
  if (!/[a-z]/.test(joined) || !/[A-Z]/.test(joined) || !/[0-9+/]/.test(joined)) return false;
  const head = joined.length > PEM_SAMPLE ? joined.slice(0, PEM_SAMPLE) : joined;
  // A marker anywhere in the head or tail, the first line and the middle of a token
  // included (`...FAKEKEY...`), and a body that decodes to text, are documentation.
  const ends = joined.length > 2 * PEM_SAMPLE ? head + joined.slice(-PEM_SAMPLE) : joined;
  if (isPlaceholderSecret(ends) || PEM_FAKE_MARKERS.test(ends) || decodesToText(joined)) return false;
  if (isSequentialRunPlaceholder(head) || isStrideRunPlaceholder(head)) return false;
  // An unencrypted OpenSSH key opens with the base64 of `openssh-key-v1` and carries
  // its public key and zero padding inside, so its 6-grams repeat more than a DER
  // key's (0.72 to 0.75 measured): a lower bar, and the constant preamble alone is
  // not a key.
  if (!joined.startsWith(OPENSSH_MAGIC)) return looksLikeKeyMaterial(tokens.slice(1), 0.85);
  const constant = joined.startsWith(OPENSSH_PREAMBLE) ? OPENSSH_PREAMBLE.length : OPENSSH_MAGIC.length;
  if (joined.length - constant < PEM_BODY_MIN) return false;
  return looksLikeKeyMaterial(tokens.slice(1), 0.6);
}

/** The base64 of `openssh-key-v1`, and of the 33 bytes every unencrypted OpenSSH key opens with (magic, cipher none, kdf none, empty options). */
const OPENSSH_MAGIC = 'b3BlbnNzaC1rZXktdjE';
const OPENSSH_PREAMBLE = 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAA';

/** Like the sequential-run test, for an alphabet typed with every second character (`acegik...`, `ACEGIK...`). */
function isStrideRunPlaceholder(value: string): boolean {
  if (value.length < 12) return false;
  let covered = 0;
  for (const step of [2, -2]) {
    let i = 0;
    while (i < value.length - 1) {
      if (value.charCodeAt(i + 1) - value.charCodeAt(i) !== step) {
        i++;
        continue;
      }
      let end = i + 1;
      while (end + 1 < value.length && value.charCodeAt(end + 1) - value.charCodeAt(end) === step) end++;
      if (end - i + 1 >= 4) covered += end - i + 1;
      i = end;
    }
  }
  return covered / value.length >= SEQUENTIAL_RUN_COVERAGE_THRESHOLD;
}

const B64_INDEX = ((): Uint8Array => {
  const t = new Uint8Array(128);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (let i = 0; i < 64; i++) t[chars.charCodeAt(i)] = i;
  return t;
})();

/** Distinct 6-grams over all 6-grams of a string: 1 for random text, small for a repeated phrase. */
function sixGramVariety(s: string): number {
  if (s.length < 7) return 1;
  const seen = new Set<number>();
  let key = 0;
  const top = 64 ** 5;
  for (let i = 0; i < s.length; i++) {
    // A rolling base-64 key of the last six characters.
    if (i >= 6) key -= B64_INDEX[s.charCodeAt(i - 6) & 127] * top;
    key = key * 64 + B64_INDEX[s.charCodeAt(i) & 127];
    if (i >= 5) seen.add(key);
  }
  return seen.size / (s.length - 5);
}

/** Lowercase, uppercase, and a digit, `+` or `/` all present: one pass instead of three regex tests. */
function isMixedCase(l: string): boolean {
  let lower = false;
  let upper = false;
  let other = false;
  for (let i = 0; i < l.length; i++) {
    const c = l.charCodeAt(i);
    if (c >= 97 && c <= 122) lower = true;
    else if (c >= 65 && c <= 90) upper = true;
    else other = true;
  }
  return lower && upper && other;
}

/** Markers short enough to be tested only in a body that reached the second path (`fake` is also aggressive-tier in `isPlaceholderSecret`). */
const PEM_FAKE_MARKERS = /fake|sample/i;

/**
 * True when most of the start of a base64 body decodes to printable ASCII: a body
 * that is the base64 of an English sentence or a config line is not a key. Random
 * bytes are printable about 37% of the time; a key's ASN.1 framing is not text.
 */
function decodesToText(b64: string): boolean {
  const n = Math.min(b64.length, 192) & ~3;
  if (n < 32) return false;
  let printable = 0;
  let total = 0;
  for (let i = 0; i < n; i += 4) {
    const a = B64_INDEX[b64.charCodeAt(i) & 127];
    const b = B64_INDEX[b64.charCodeAt(i + 1) & 127];
    const c = B64_INDEX[b64.charCodeAt(i + 2) & 127];
    const d = B64_INDEX[b64.charCodeAt(i + 3) & 127];
    const bytes = [(a << 2) | (b >> 4), ((b & 15) << 4) | (c >> 2), ((c & 3) << 6) | d];
    for (const x of bytes) {
      total++;
      if ((x >= 0x20 && x <= 0x7e) || x === 0x09 || x === 0x0a || x === 0x0d) printable++;
    }
  }
  return printable / total >= 0.85;
}

/** How many characters of a body the shape tests (alphabet, repeated phrase, words) read. */
const PEM_SAMPLE = 128;

/** Shortest rest of a body for which the word share is evidence. */
const WORD_TEST_MIN = 48;

/** The share of a string that sits in English-looking words (`Several`, `material`): near 1 for camelCase prose, small for base64. */
function wordCoverage(s: string): number {
  let covered = 0;
  for (const m of s.matchAll(/[A-Z][a-z]{3,}|[a-z]{5,}/g)) covered += m[0].length;
  return covered / s.length;
}

/**
 * Whether the lines after a body's first line read as key material rather than
 * filler or prose. Documentation shows a realistic first line (`MIIEvQIBADAN...`)
 * and then `xxxx...`, `AAAA...`, `REDACTEDREDACTED...`, a repeated phrase,
 * camelCase words, or the alphabet. The test, with the numbers that set it
 * (Ed25519, X25519, EC P-256 and RSA 2048 PKCS8 bodies folded at widths 8 to 39
 * and, for the 25519 keys, unevenly between 20 and 39, with a footer: 280,800
 * measured, none declined; without a footer widths under 14 are declined by
 * design). The shape tests below read the first 128 characters of the rest:
 *  - no placeholder marker (the first and last 128 characters of the rest), not one or two
 *    characters repeated, and not a sequential run or an every-second-character
 *    run (the alphabet);
 *  - at least `varietyBar` of the 6-grams of its first 128 characters are
 *    distinct (a repeated phrase scores its period over the length). The bar is
 *    0.85, and DER keys score 0.988 or more; for an unencrypted OpenSSH key (it
 *    starts with the base64 of `openssh-key-v1`, whose padding and embedded public
 *    key repeat, measured 0.72 to 0.75) it is 0.6, and the constant preamble
 *    does not count towards its 64 characters;
 *  - fewer than 0.7 of its first 128 characters sit in English-looking words when
 *    the rest is 48 or more characters, fewer than 0.85 when it is shorter.
 *    Random base64 averages 0.1 to 0.2 and the worst measured with 48 or more
 *    was 0.583; under 48 (an Ed25519 body folded at 17 or more columns) a few
 *    letters decide the share, so the bar is stricter, not absent. The dummies
 *    score 0.79 to 1.0;
 *  - when it has 16 or more lines of 16 or more characters, more than half of
 *    the first 24 of them are mixed (lower, upper and a digit, `+` or `/`).
 * None of this is a proof: a key can fail it by chance, which only matters for a
 * key 1.13.4 also missed, since 1.13.4's rule is applied first.
 */
function looksLikeKeyMaterial(rest: string[], varietyBar: number): boolean {
  const joined = rest.join('');
  if (joined.length === 0) return false;
  // Markers are looked for in the head and the tail of a long body.
  if (isPlaceholderSecret(joined.length > 2 * PEM_SAMPLE ? joined.slice(0, PEM_SAMPLE) + joined.slice(-PEM_SAMPLE) : joined)) return false;
  // The shape tests look at the first PEM_SAMPLE characters: filler and prose show
  // within them, and a body of a thousand characters is not hashed in full.
  const sample = joined.length > PEM_SAMPLE ? joined.slice(0, PEM_SAMPLE) : joined;
  if (isSequentialRunPlaceholder(sample) || isStrideRunPlaceholder(sample)) return false;
  if (sixGramVariety(sample) < varietyBar) return false;
  // Under 48 characters (an Ed25519 or X25519 body folded at 17 or more columns) a
  // handful of letters decides the word share, so only a strict bar applies.
  if (wordCoverage(sample) >= (joined.length >= WORD_TEST_MIN ? 0.7 : 0.85)) return false;
  let judged = 0;
  let mixed = 0;
  for (let i = 0; i < rest.length && judged < 24; i++) {
    const l = rest[i];
    if (l.length < 16) continue;
    judged++;
    if (isMixedCase(l)) mixed++;
  }
  if (judged >= 16 && mixed * 2 <= judged) return false;
  return true;
}

const ELLIPSIS_LEAD = new Set([' ', '\t', '\r', '\n', '\f', '\v', '#', '>', ';', '*', '/', '"', "'", '`', ',', '[', '(', '<', '-']);
const ELLIPSIS_TRAIL = new Set([' ', '\t', '\r', '\n', '\f', '\v', '"', "'", '`', ',', ';', ']', ')', '>']);
const ELLIPSIS_ONLY = /^(?:\.{2,}|(?:\.\s?){3,}|\u2026+|(?:cut|Cut|CUT|etc|Etc|ETC)\.?|(?:\.{2,}|\u2026)\s*\(?[Tt]runcated\)?)$/;
/** A lone English word that says something was left out, in any case (three-letter words are matched in three casings only: `cut` is also a base64 line). */
const ELLIPSIS_WORDS = /^(?:omitted|truncated|elided|snipped|snip|trimmed|removed|skipped|abridged)\.?$/i;

/** A line that only marks something left out: `...`, `. . .`, the Unicode ellipsis, `[...]`, `<snip>`, `etc`, `.. (truncated)`. */
function isEllipsisLine(line: string): boolean {
  const t = trimEndSet(trimStartSet(line, ELLIPSIS_LEAD), ELLIPSIS_TRAIL);
  return ELLIPSIS_ONLY.test(t) || ELLIPSIS_WORDS.test(t);
}

/** A line that ends in an ellipsis after its content: `MIIEpAIBAAKC...`. */
function endsWithEllipsis(line: string): boolean {
  const t = trimEndSet(line, ELLIPSIS_TRAIL);
  return t.endsWith('...') || t.endsWith('\u2026') || t.endsWith('. . .');
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
const CLEAN_TRAIL = new Set(['"', "'", '`', ']', ')', '}', ',', ';', '+', '\\', '.', '&', '|']);
const WHITESPACE = /\s/;

/** `cleanPemToken` as on origin/main, except that the trailing strip scans from the end (the regex it replaces, `[\s"'`\])},;+\\.&|]+$`, is quadratic on a long run). Exported for its equivalence test only. */
export function cleanPemToken(raw: string): string {
  let t = raw;
  for (let i = 0; i < 4; i++) {
    const before = t;
    t = t
      .replace(/^(?:[#>;%|*]+|\/{2,}|-{2,})/, '')
      .replace(/^[bBrRuUfF]{1,2}(?=["'`])/, '')
      .replace(/^["'`[({\\]+/, '');
    if (t === before) break;
  }
  let e = t.length;
  while (e > 0 && (CLEAN_TRAIL.has(t[e - 1]) || WHITESPACE.test(t[e - 1]))) e--;
  t = e === t.length ? t : t.slice(0, e);
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
  if (value.length < 8) return false;
  // At most two distinct code points (as `new Set(value).size <= 2` counted them: an
  // emoji is one), found without building a Set of the whole value.
  let first: string | undefined;
  let second: string | undefined;
  for (const c of value) {
    if (first === undefined) first = c;
    else if (c === first || c === second) continue;
    else if (second === undefined) second = c;
    else return false;
  }
  return true;
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

  // Runs are found left to right and can share only an end point, so the covered
  // count is the run lengths less the shared points (no array of flags).
  let inRuns = 0;
  let lastCovered = -1;
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
      inRuns += end - Math.max(i, lastCovered + 1) + 1;
      lastCovered = end;
    }
    i = end;
  }

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

/** The port each scheme's server listens on by default: an empty-user URL whose "password" is exactly this is a typo of `host:port`. */
const WELL_KNOWN_PORTS: Readonly<Record<string, readonly string[]>> = {
  redis: ['6379', '6380'],
  rediss: ['6379', '6380'],
  postgres: ['5432'],
  postgresql: ['5432'],
  mysql: ['3306'],
  mongodb: ['27017'],
  'mongodb+srv': ['27017'],
};

export function isNonSecretConnectionString(url: string): boolean {
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^:@/\s]*):([^@/\s]+)@([^:/?\s]+)/i.exec(url);
  if (!m) return false;

  const scheme = m[1].toLowerCase();
  const user = m[2];
  const pass = m[3];
  const host = m[4].toLowerCase();

  // 1. Non-routable / local / docker-service / reserved-TLD host.
  if (LOCAL_HOSTS.has(host)) return true;
  if (LOCAL_TLD_SUFFIXES.some(suffix => host.endsWith(suffix))) return true;
  // Bare single-token host with no dot (and not a raw IPv4) is a docker-compose
  // service name (`mysql`, `db`, `postgres`) -- local to a compose network.
  if (!host.includes('.') && !host.includes(':') && !/^\d+$/.test(host)) return true;

  // 2. Placeholder / default password.
  const p = pass.toLowerCase();
  if (PLACEHOLDER_PASSWORDS.has(p)) return true;
  if (user.toLowerCase() === p) return true;            // root:root, prisma:prisma
  if (/^[A-Z][A-Z0-9_]*$/.test(pass)) return true;      // USER:PASSWORD, DBPASS
  if (pass.startsWith('$') || pass.startsWith('<') || pass.startsWith('{')) return true; // ${DB_PASS}, <pw>
  // The forms below were not declined in 1.13.4. They are placeholders in the
  // `redis://:pw@host` shape (an empty user), where a masked or templated password
  // is the norm; with a user the 1.13.4 verdict stands (`app:none@host` is reported).
  if (user === '') {
    if (/^\*+$/.test(pass)) return true;                  // masked by Celery and Kombu: redis://:**@host
    if (/^%[A-Za-z_][A-Za-z0-9_]*%$/.test(pass)) return true; // %REDIS_PW% (Windows environment variable)
    if (/^(?:%2[aA])+$/.test(pass)) return true;          // the mask `***`, percent-encoded
    if (/^x{3,}$/i.test(pass) || /^\.+$/.test(pass)) return true; // xxxx and ....
    if (/^%\([A-Za-z_][A-Za-z0-9_]*\)s$/.test(pass)) return true; // Python %(name)s
    if (/^%[sdvqS]$/.test(pass)) return true;             // printf verbs: %s, %v (Go)
    if (/^(?:null|undefined|none|nil)$/i.test(pass)) return true; // nothing set
    if (/^[-?]$/.test(pass)) return true;                 // a lone dash or question mark
    if (/^[\u2022\u25CF\u00B7\u2B24\u25CB]+$/u.test(pass)) return true; // bullet masks
    if (/^#\{.*\}$/.test(pass)) return true;             // Ruby interpolation #{ENV['X']}
    // `redis://:6379@host` is `host:port` mistyped, not a password, when the number
    // is the scheme's default port. Any other number is a password (a numeric
    // Redis password is possible).
    if ((WELL_KNOWN_PORTS[scheme] ?? []).includes(pass)) return true;
  }
  // A string concatenation (`'+os.environ['PW']+'`). With a user, only one whose inside
  // is an expression or a name is declined; `'&Tr0ub4dor&'` is a password in quotes.
  const concat = /^["'`]\s*[+.&]\s*([\w.$[\]()'"`]+)\s*[+.&]\s*["'`]$/.exec(pass);
  if (concat !== null) {
    const inside = concat[1];
    if (user === '') return true;
    if (/os\.environ|process\.env|[[(]/.test(inside) || /^[A-Z][A-Z0-9_]*$/.test(inside) || /^[a-z][a-z0-9_]*$/.test(inside)) return true;
  }
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
