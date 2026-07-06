import fs from 'fs';
import { SecretMatch } from '../types';
import { VaultGuardConfig } from '../config';
import { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from '../utils/entropy';
import { isPlaceholderSecret, isNonSecretConnectionString, isSampleJwt, isRedactedTemplateValue, isEnvVarNameToken } from '../utils/placeholder';
import { applyPathAwareSeverity } from '../utils/path-severity';
import { shouldSuppressDocContextMatch, isInsidePythonTripleQuoted } from '../utils/doc-context';
import {
  validateRegexLength,
  validateRegexSafety,
} from '../utils/regex-safety';

// ---------------------------------------------------------------------------
// Pattern registry
// ---------------------------------------------------------------------------

interface PatternEntry {
  regex: RegExp;
  severity: SecretMatch['severity'];
  /**
   * Minimum Shannon entropy (bits/char) required for the raw matched value.
   * If set and the match falls below the threshold the match is dropped —
   * this is the primary defence against false positives on broad patterns.
   */
  minEntropy?: number;
  /**
   * Apply the *aggressive* placeholder filter (test-fixture words such as
   * `test`, `password`, `sample`). Only set on low-precision generic /
   * assignment patterns — vendor-anchored keys always use the standard filter
   * so recall on real credentials is unaffected.
   */
  aggressivePlaceholder?: boolean;
  /**
   * Treat the match as a database/Redis connection string and suppress it when
   * the host is local/docker/reserved-TLD or the password is a placeholder /
   * default (see {@link isNonSecretConnectionString}). Prevents the dominant
   * real-world false positive: localhost & example DSNs in docker-compose,
   * `.env.example`, and test fixtures.
   */
  connectionString?: boolean;
}

/**
 * Vendor-specific patterns anchored to known prefixes / structures.
 *
 * Deliberately NOT included (too broad / not actual secrets):
 *   - cohere            (`[a-zA-Z0-9]{40}`)   — matches git SHAs, MD5s, …
 *   - aws-secret        (`[a-zA-Z0-9/+]{40}`) — matches any base-64-ish string
 *   - circleci-token    (`[a-zA-Z0-9_-]{40}`) — identical problem
 *   - jenkins-token     (`[a-zA-Z0-9]{32}`)   — matches MD5 hashes
 *   - kubernetes-token  (JWT)                 — merged into jwt-token
 *   - elasticsearch-url (`https://u:p@h:n`)   — matches any auth URL
 *   - ssh-rsa-public    / ssh-ed25519-public  — public keys are NOT secrets
 *   - google-analytics  / google-analytics-4  — publishable measurement IDs
 *   - twilio-account    (AC…)                 — public Account SID, not secret
 *
 * AWS secret access key is retained as a context-anchored pattern only.
 */
const BUILTIN_PATTERNS: ReadonlyMap<string, PatternEntry> = new Map([
  // --- AI / ML providers ---
  ['anthropic',         { regex: /sk-ant-[a-zA-Z0-9_-]{20,}/g,                                                         severity: 'critical' }],
  // OpenAI key formats. All current keys embed the T3BlbkFJ watermark (base64 "OpenAI").
  // Specific prefixes are ordered first so they get their own rule title (blast radius differs).
  // The legacy sk- catch-all uses the watermark + token-boundary so it does not shadow the
  // prefixed rules and avoids matching short benign identifiers.
  //
  // DELIBERATE: we do NOT match the pre-2023 bare `sk-<48 alphanumerics>` format (no watermark).
  // That pattern fires on any base64/hex blob following `sk-` and floods false positives; the
  // watermark is the only reliable discriminator, matching the gitleaks/trufflehog consensus.
  // Do not re-add a bare `sk-[A-Za-z0-9]{N,}` rule without an entropy gate and a bench FP guard.
  ['openai-project',    { regex: /sk-proj-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}/g,                       severity: 'critical' }],
  ['openai-svcacct',    { regex: /sk-svcacct-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}/g,                    severity: 'critical' }],
  ['openai-admin',      { regex: /sk-admin-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}/g,                      severity: 'critical' }],
  // Legacy user key (sk-<20>T3BlbkFJ<20+>). Token-boundary anchored so benign sk- prefixes
  // in identifiers (e.g. sk-None-short) don't fire without the watermark present.
  ['openai',            { regex: /(?<![A-Za-z0-9_-])sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20,}/g,                    severity: 'critical' }],
  ['huggingface',    { regex: /hf_[a-zA-Z0-9]{34,}/g,                                           severity: 'critical' }],
  ['replicate',      { regex: /r8_[a-zA-Z0-9]{32}/g,                                            severity: 'critical' }],

  // --- Payment processors ---
  ['stripe',         { regex: /sk_live_[a-zA-Z0-9]{24,}/g,                                      severity: 'critical' }],
  ['stripe-test',    { regex: /sk_test_[a-zA-Z0-9]{24,}/g,                                      severity: 'high' }],
  ['paypal',         { regex: /access_token\$production\$[a-zA-Z0-9]{20,}/g,                    severity: 'critical' }],

  // --- Cloud providers ---
  ['aws-access',          { regex: /AKIA[0-9A-Z]{16}/g,                                          severity: 'critical' }],
  // Context-anchored AWS secret: only flags values that appear on the same
  // line as the canonical env-var / config-key name.
  ['aws-secret-context',  { regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([a-zA-Z0-9/+]{40})/gi, severity: 'critical' }],
  ['gcp-service-account', { regex: /"type":\s*"service_account"/g,                               severity: 'critical' }],
  ['gcp-api-key',         { regex: /AIza[a-zA-Z0-9_-]{35}/g,                                    severity: 'critical' }],
  ['gcp-oauth',           { regex: /[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g,    severity: 'critical' }],
  ['azure-storage',       { regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}/g, severity: 'critical' }],

  // --- Database connection strings ---
  ['postgresql-url', { regex: /postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?\/\S+/g,  severity: 'critical', connectionString: true }],
  ['mysql-url',      { regex: /mysql:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?\/\S+/g,             severity: 'critical', connectionString: true }],
  ['mongodb-url',    { regex: /mongodb(?:\+srv)?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?/g,      severity: 'critical', connectionString: true }],
  ['redis-url',      { regex: /rediss?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)/g,                 severity: 'critical', connectionString: true }],

  // --- Source control tokens ---
  ['github-token',   { regex: /gh[pousor]_[a-zA-Z0-9]{36}/g,                                    severity: 'critical' }],
  ['github-pat',     { regex: /github_pat_[a-zA-Z0-9_]{82}/g,                                   severity: 'critical' }],
  ['gitlab-token',   { regex: /glpat-[a-zA-Z0-9_-]{20}/g,                                       severity: 'critical' }],
  ['bitbucket-token',{ regex: /BBDC-[a-zA-Z0-9_-]{40}/g,                                        severity: 'critical' }],

  // --- Communication platforms ---
  ['slack-webhook',  { regex: /hooks\.slack\.com\/services\/[A-Z0-9]{9,}\/[A-Z0-9]{9,}\/[a-zA-Z0-9]{20,}/g, severity: 'critical' }],
  ['slack-token',    { regex: /xox[baprs]-[a-zA-Z0-9-]{10,}/g,                                  severity: 'critical' }],
  ['discord-webhook',{ regex: /discord\.com\/api\/webhooks\/[0-9]{17,20}\/[a-zA-Z0-9_-]{60,}/g, severity: 'critical' }],

  // --- Email / messaging services ---
  ['sendgrid-api',   { regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,                     severity: 'critical' }],
  // `re_` is a short prefix that also occurs mid-identifier (e.g. a long Go
  // test name yields a `re_<camelCase>` substring). Anchor to a token boundary
  // so only standalone `re_<key>` tokens match, and entropy-gate to drop
  // low-entropy identifiers while keeping random Resend keys.
  ['resend-api',     { regex: /(?<![A-Za-z0-9_])re_[a-zA-Z0-9]{32,}/g,                            severity: 'critical', minEntropy: 3.5 }],
  ['mailgun-api',    { regex: /key-[a-zA-Z0-9]{32}/g,                                            severity: 'critical', minEntropy: 3.5 }],

  // --- Package managers ---
  ['npm-token',      { regex: /npm_[a-zA-Z0-9]{36}/g,                                            severity: 'critical' }],

  // --- Monitoring ---
  ['newrelic-api',   { regex: /NRAK-[a-zA-Z0-9]{26}/g,                                          severity: 'critical' }],

  // --- E-commerce ---
  ['shopify-admin',  { regex: /shp(?:ss|at|ca)_[a-zA-Z0-9]{32}/g,                               severity: 'critical' }],

  // --- Keys and auth tokens ---
  ['ssh-private-key',{ regex: /-----BEGIN [A-Z ]+ PRIVATE KEY-----/g,                            severity: 'critical' }],
  ['jwt-token',      { regex: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,            severity: 'high' }],

  // Generic patterns — entropy-gated AND placeholder-filtered (aggressive) to
  // suppress false positives on documentation samples and unit-test fixtures.
  ['bearer-token',   { regex: /Bearer [a-zA-Z0-9_-]{20,}/g,                                     severity: 'high',   minEntropy: 3.5, aggressivePlaceholder: true }],
  ['api-key-generic',{ regex: /api[_-]?key["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,         severity: 'high',   minEntropy: 3.5, aggressivePlaceholder: true }],
  ['secret-generic', { regex: /secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,               severity: 'high',   minEntropy: 3.5, aggressivePlaceholder: true }],
  // Negative lookbehind prevents matching when `password` is a suffix of a
  // compound identifier (e.g. `email-reset-password`, `changePassword`).
  // Only standalone assignments trigger — `password =`, `password:`, etc.
  ['password-in-code',{ regex: /(?<![a-zA-Z0-9_-])password["']?\s*[:=]\s*["']([a-zA-Z0-9_\-!@#$%^&*]{12,})/gi, severity: 'high', minEntropy: 3.2, aggressivePlaceholder: true }],
]);

/**
 * Low-precision generic assignment patterns (`<key> = <value>`) whose captured
 * value may be an unquoted code identifier rather than a literal secret. Only
 * these are subject to the function-call suppression heuristic; vendor- and
 * context-anchored detectors are deliberately excluded.
 */
const GENERIC_ASSIGNMENT_IDS = new Set(['secret-generic', 'api-key-generic', 'password-in-code']);

/**
 * Read-only metadata for built-in patterns (docs / codegen). Exposes
 * `RegExp#source` and flags only — not live `RegExp` instances.
 */
export interface BuiltinPatternDocEntry {
  id: string;
  severity: SecretMatch['severity'];
  minEntropy?: number;
  regexSource: string;
  regexFlags: string;
}

/** Stable insertion order of {@link BUILTIN_PATTERNS}. */
export function getBuiltinPatternDocEntries(): BuiltinPatternDocEntry[] {
  return [...BUILTIN_PATTERNS.entries()].map(([id, entry]) => ({
    id,
    severity: entry.severity,
    ...(entry.minEntropy !== undefined ? { minEntropy: entry.minEntropy } : {}),
    regexSource: entry.regex.source,
    regexFlags: entry.regex.flags,
  }));
}

// ---------------------------------------------------------------------------
// Severity ranking (higher = worse)
// ---------------------------------------------------------------------------
const SEVERITY_RANK: Record<SecretMatch['severity'], number> = {
  critical: 4,
  high:     3,
  medium:   2,
  low:      1,
};

// ---------------------------------------------------------------------------
// SecretScanner
// ---------------------------------------------------------------------------

export class SecretScanner {
  private readonly patterns: Map<string, PatternEntry>;
  private readonly entropyThreshold: number;

  constructor(config?: VaultGuardConfig) {
    this.entropyThreshold = config?.entropy_threshold ?? DEFAULT_ENTROPY_THRESHOLD;

    // Start from a mutable copy of the built-ins.
    this.patterns = new Map(
      [...BUILTIN_PATTERNS].map(([k, v]) => [k, { ...v, regex: new RegExp(v.regex.source, v.regex.flags) }])
    );

    // Apply severity overrides / "off" switches.
    if (config?.severity_overrides) {
      for (const [id, override] of Object.entries(config.severity_overrides)) {
        if (override === 'off') {
          this.patterns.delete(id);
        } else {
          const entry = this.patterns.get(id);
          if (entry) {
            this.patterns.set(id, { ...entry, severity: override });
          }
        }
      }
    }

    // Compile and append extra patterns from config.
    //
    // Security policy: every user-supplied regex passes through
    // `validateRegexSafety` (heuristic ReDoS check). Patterns that fail are
    // **not** silently skipped — that is exactly the behaviour the audit
    // flagged (Audit §14: silent error swallows). They are reported via
    // `extraPatternRejections` for the caller (CLI / MCP) to surface to the
    // user, then dropped.
    //
    // `extra_patterns_unsafe: true` opts out of the heuristic, but the length
    // cap still runs as a memory-use backstop.
    if (config?.extra_patterns) {
      const unsafe = config.extra_patterns_unsafe === true;

      for (const ep of config.extra_patterns) {
        const lengthCheck = validateRegexLength(ep.regex);
        if (!lengthCheck.ok) {
          this.extraPatternRejections.push({
            id: ep.id,
            reason: lengthCheck.reason ?? 'too_long',
            detail: lengthCheck.detail ?? 'pattern exceeds length cap',
          });
          continue;
        }

        if (!unsafe) {
          const safety = validateRegexSafety(ep.regex);
          if (!safety.ok) {
            this.extraPatternRejections.push({
              id: ep.id,
              reason: safety.reason ?? 'invalid_syntax',
              detail: safety.detail ?? 'pattern failed ReDoS safety check',
            });
            continue;
          }
        }

        try {
          this.patterns.set(ep.id, {
            regex: new RegExp(ep.regex, 'g'),
            severity: ep.severity,
            ...(ep.min_entropy !== undefined ? { minEntropy: ep.min_entropy } : {}),
          });
        } catch (e) {
          this.extraPatternRejections.push({
            id: ep.id,
            reason: 'invalid_syntax',
            detail: e instanceof Error ? e.message : String(e),
          });
        }
      }
    }
  }

  /**
   * Rejected `extra_patterns` from the most recent constructor call.
   *
   * Callers should surface these to the user (stderr today, structured
   * `diagnostics[]` channel post Phase 2.2). A non-empty list means the
   * user's `.vault-guard.json` declared rules that are not active.
   */
  readonly extraPatternRejections: Array<{
    id: string;
    reason: string;
    detail: string;
  }> = [];

  /** Number of built-in + extra patterns active after config (severity "off" removes rules). */
  getActivePatternCount(): number {
    return this.patterns.size;
  }

  /**
   * Scan a file and return deduplicated, ignore-directive-filtered matches.
   */
  scan(filePath: string): SecretMatch[] {
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, 'utf-8');
    // Path-aware severity is applied here (not in scanContent) because it needs
    // the file path. scanContent callers that know the path (scanTextFile*)
    // apply it themselves, so this does not double-apply.
    return applyPathAwareSeverity(this.scanContent(content, { filePath }), filePath);
  }

  /**
   * Scan arbitrary UTF-8 text (editor buffer, pasted snippet, MCP payload).
   * Line numbers and byte offsets are relative to this string.
   *
   * Pass `opts.filePath` when the content comes from a file on disk so
   * documentation-site suppressions (Algolia search keys, etc.) can apply.
   *
   * Each call uses fresh `RegExp` instances so overlapping `scanContent` work
   * (e.g. after an `await` in a concurrent worker pool) cannot corrupt
   * `lastIndex` on shared patterns.
   */
  scanContent(content: string, opts?: { filePath?: string }): SecretMatch[] {
    const lineIndex = this.buildLineIndex(content);
    const ignoredLines = this.parseIgnoreDirectives(content, lineIndex);

    const raw: SecretMatch[] = [];

    // Fresh `RegExp` per invocation so concurrent or interleaved `scanContent`
    // calls (e.g. across `await` in a worker pool) never share `lastIndex`.
    const patternsForRun = new Map<string, PatternEntry>();
    for (const [k, v] of this.patterns) {
      patternsForRun.set(k, {
        ...v,
        regex: new RegExp(v.regex.source, v.regex.flags),
      });
    }

    for (const [type, entry] of patternsForRun) {
      const { regex, severity, minEntropy, aggressivePlaceholder, connectionString } = entry;
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const rawValue = match[1] ?? match[0];
        const fullMatch = match[0];

        const threshold = minEntropy ?? (minEntropy === 0 ? 0 : undefined);
        if (threshold !== undefined && shannonEntropy(rawValue) < threshold) {
          continue;
        }

        // Suppress documentation samples / test fixtures (e.g. AWS's
        // `AKIAIOSFODNN7EXAMPLE`, `password: 'testPass1234'`). The aggressive
        // tier only applies to the low-precision generic patterns.
        if (isPlaceholderSecret(rawValue, { aggressive: aggressivePlaceholder === true })) {
          continue;
        }

        if (isRedactedTemplateValue(rawValue)) {
          continue;
        }

        if (GENERIC_ASSIGNMENT_IDS.has(type) && isEnvVarNameToken(rawValue)) {
          continue;
        }

        if (
          GENERIC_ASSIGNMENT_IDS.has(type) &&
          opts?.filePath?.endsWith('.py') &&
          isInsidePythonTripleQuoted(content, match.index)
        ) {
          continue;
        }

        // Suppress local/dev/example/placeholder connection strings — the
        // dominant FP source on real repos (docker-compose, `.env.example`,
        // test fixtures all carry `postgres://user:pass@localhost/db`).
        if (connectionString === true && isNonSecretConnectionString(fullMatch)) {
          continue;
        }

        // Suppress the ubiquitous jwt.io sample token (John Doe / sub 1234567890)
        // that appears in API docs and tutorials everywhere.
        if (type === 'jwt-token' && isSampleJwt(fullMatch)) {
          continue;
        }

        // Suppress unquoted assignments whose "value" is actually a function
        // call — e.g. `csrf_secret = _add_new_csrf_cookie(request)`. The value
        // capture group stops at `(`, so a `(` immediately following the match
        // means we captured a callee identifier, not a literal secret. Scoped to
        // the low-precision generic assignment patterns only — vendor-anchored
        // and context-anchored detectors (incl. critical `aws-secret-context`)
        // are never weakened by this heuristic.
        if (
          GENERIC_ASSIGNMENT_IDS.has(type) &&
          content[match.index + fullMatch.length] === '('
        ) {
          continue;
        }

        const line = this.lineFromIndex(lineIndex, match.index);
        const lineContent = this.lineContentAt(content, lineIndex, line);

        if (
          opts?.filePath &&
          shouldSuppressDocContextMatch(type, opts.filePath, rawValue, fullMatch, lineContent)
        ) {
          continue;
        }

        if (ignoredLines.has(line)) continue;

        raw.push({
          type,
          value: this.maskValue(fullMatch),
          line,
          column: match.index - (lineIndex[line - 1] ?? 0),
          offset: match.index,
          matchLength: fullMatch.length,
          severity,
        });
      }
    }

    return this.deduplicateMatches(raw);
  }

  /**
   * Merge matches produced from chunked reads (e.g. line-by-line streaming)
   * using the same overlap / severity rules as a full-file scan.
   */
  mergeChunkedMatches(matches: SecretMatch[]): SecretMatch[] {
    return this.deduplicateMatches(matches);
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  /**
   * Build an index of line-start byte offsets for O(log n) line lookup.
   * Index position 0 = start of line 1.
   */
  private buildLineIndex(content: string): number[] {
    const idx = [0];
    for (let i = 0; i < content.length; i++) {
      if (content[i] === '\n') idx.push(i + 1);
    }
    return idx;
  }

  /** Binary-search the line index to return a 1-based line number. */
  private lineFromIndex(lineIndex: number[], byteOffset: number): number {
    let lo = 0;
    let hi = lineIndex.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (lineIndex[mid] <= byteOffset) lo = mid + 1;
      else hi = mid - 1;
    }
    return lo; // 1-based
  }

  /** Return the full text of a 1-based line number (without trailing newline). */
  private lineContentAt(content: string, lineIndex: number[], lineNum: number): string {
    const start = lineIndex[lineNum - 1] ?? 0;
    const end = lineNum < lineIndex.length ? lineIndex[lineNum] - 1 : content.length;
    return content.slice(start, end);
  }

  /**
   * Parse inline ignore directives from file content.
   *
   * Supported forms (case-insensitive):
   *   `// vault-guard: ignore-line`        — ignores that line
   *   `// vault-guard: ignore-next-line`   — ignores the following line
   *   `# vault-guard: ignore-line`         — same, for shell/Python/YAML
   *   `# vault-guard: ignore-next-line`
   *
   * Returns a Set of 1-based line numbers to ignore.
   */
  private parseIgnoreDirectives(content: string, lineIndex: number[]): Set<number> {
    const ignored = new Set<number>();
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const lineNum = i + 1; // 1-based
      const lower = lines[i].toLowerCase();

      if (lower.includes('vault-guard: ignore-line') || lower.includes('vault-guard:ignore-line')) {
        ignored.add(lineNum);
      }
      if (lower.includes('vault-guard: ignore-next-line') || lower.includes('vault-guard:ignore-next-line')) {
        ignored.add(lineNum + 1);
      }
    }

    // lineIndex is available for future column-level ignore; unused here.
    void lineIndex;

    return ignored;
  }

  /**
   * Deduplicate matches by overlapping byte ranges.
   *
   * When two matches cover the same (or overlapping) bytes in the file the
   * more-specific (higher-severity or shorter) match is kept.  This prevents
   * the same secret from being reported multiple times when several patterns
   * overlap.
   */
  private deduplicateMatches(matches: SecretMatch[]): SecretMatch[] {
    if (matches.length <= 1) return matches;

    // Sort by start offset so we can do a linear sweep.
    const sorted = [...matches].sort((a, b) => a.offset - b.offset || a.line - b.line);
    const kept: SecretMatch[] = [];

    for (const candidate of sorted) {
      const cStart = candidate.offset;
      const cEnd = cStart + candidate.matchLength;

      let dominated = false;

      for (let i = kept.length - 1; i >= 0; i--) {
        const existing = kept[i];
        const eStart = existing.offset;
        const eEnd = eStart + existing.matchLength;

        // No possible overlap once we've passed the candidate start by more
        // than the max pattern length (optimisation — safe upper bound: 512).
        if (eEnd < cStart - 512) break;

        const overlaps = cStart < eEnd && eStart < cEnd;
        if (!overlaps) continue;

        const existingRank = SEVERITY_RANK[existing.severity];
        const candidateRank = SEVERITY_RANK[candidate.severity];

        if (candidateRank > existingRank) {
          // Candidate is more severe — replace existing.
          kept.splice(i, 1);
        } else {
          // Existing is at least as severe — drop candidate.
          dominated = true;
          break;
        }
      }

      if (!dominated) kept.push(candidate);
    }

    return kept;
  }

  /**
   * Redact a matched secret to a low-information identifier.
   *
   * Format: `<prefix>…(<length>c)` — e.g. `sk-a…(37c)`.
   *
   * Why not show more characters?
   *   - 4-char prefix is enough to identify vendor (sk-a, sk_l, ghp_, AKIA, …)
   *     without leaking meaningful entropy of the underlying secret.
   *   - The exact location is already in `line` / `column`, so users don't
   *     need a longer fragment to find the match in source.
   *   - Output of this tool is routinely pasted into PRs, Slack, terminals,
   *     SARIF uploads, and GitHub Code Scanning — the surface area for
   *     leakage is large, so we keep the redaction conservative.
   *
   * For values shorter than 6 chars (rare; broad patterns enforce ≥20)
   * we redact entirely to `*…(<length>c)`.
   */
  private maskValue(value: string): string {
    const PREFIX = 4;
    const lengthTag = `(${value.length}c)`;
    if (value.length < 6) {
      return `*…${lengthTag}`;
    }
    return `${value.substring(0, PREFIX)}…${lengthTag}`;
  }
}
