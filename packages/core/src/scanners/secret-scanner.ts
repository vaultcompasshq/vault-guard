import fs from 'fs';
import { SecretMatch } from '../types';
import { VaultGuardConfig } from '../config';
import { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from '../utils/entropy';

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
  ['anthropic',      { regex: /sk-ant-[a-zA-Z0-9_-]{20,}/g,                                    severity: 'critical' }],
  ['openai',         { regex: /sk-[a-zA-Z0-9]{48}/g,                                            severity: 'critical' }],
  ['openai-project', { regex: /sk-proj-[a-zA-Z0-9_-]{48,}/g,                                   severity: 'critical' }],
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
  ['postgresql-url', { regex: /postgres(?:ql)?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?\/\S+/g,  severity: 'critical' }],
  ['mysql-url',      { regex: /mysql:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?\/\S+/g,             severity: 'critical' }],
  ['mongodb-url',    { regex: /mongodb(?:\+srv)?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)?/g,      severity: 'critical' }],
  ['redis-url',      { regex: /rediss?:\/\/[^:@\s]+:[^@\s]+@[^:\s/]+(?::\d+)/g,                 severity: 'critical' }],

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
  ['resend-api',     { regex: /re_[a-zA-Z0-9]{32,}/g,                                            severity: 'critical' }],
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

  // Generic patterns — entropy-gated to suppress false positives.
  ['bearer-token',   { regex: /Bearer [a-zA-Z0-9_-]{20,}/g,                                     severity: 'high',   minEntropy: 3.5 }],
  ['api-key-generic',{ regex: /api[_-]?key["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,         severity: 'high',   minEntropy: 3.5 }],
  ['secret-generic', { regex: /secret["']?\s*[:=]\s*["']?([a-zA-Z0-9_-]{20,})/gi,               severity: 'high',   minEntropy: 3.5 }],
  ['password-in-code',{ regex: /password["']?\s*[:=]\s*["']([a-zA-Z0-9_\-!@#$%^&*]{12,})/gi,   severity: 'high',   minEntropy: 3.2 }],
]);

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
    if (config?.extra_patterns) {
      for (const ep of config.extra_patterns) {
        try {
          this.patterns.set(ep.id, {
            regex: new RegExp(ep.regex, 'g'),
            severity: ep.severity,
            ...(ep.min_entropy !== undefined ? { minEntropy: ep.min_entropy } : {}),
          });
        } catch {
          // Skip patterns with invalid regex.
        }
      }
    }
  }

  /**
   * Scan a file and return deduplicated, ignore-directive-filtered matches.
   */
  scan(filePath: string): SecretMatch[] {
    if (!fs.existsSync(filePath)) return [];
    const content = fs.readFileSync(filePath, 'utf-8');
    return this.scanContent(content);
  }

  /**
   * Scan arbitrary UTF-8 text (editor buffer, pasted snippet, MCP payload).
   * Line numbers and byte offsets are relative to this string.
   */
  scanContent(content: string): SecretMatch[] {
    const lineIndex = this.buildLineIndex(content);
    const ignoredLines = this.parseIgnoreDirectives(content, lineIndex);

    const raw: SecretMatch[] = [];

    for (const [type, entry] of this.patterns) {
      const { regex, severity, minEntropy } = entry;
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        const rawValue = match[1] ?? match[0];
        const fullMatch = match[0];

        const threshold = minEntropy ?? (minEntropy === 0 ? 0 : undefined);
        if (threshold !== undefined && shannonEntropy(rawValue) < threshold) {
          continue;
        }

        const line = this.lineFromIndex(lineIndex, match.index);

        if (ignoredLines.has(line)) continue;

        raw.push({
          type,
          value: this.maskValue(fullMatch),
          line,
          column: match.index,
          matchLength: fullMatch.length,
          severity,
        });
      }
    }

    return this.deduplicateMatches(raw);
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
    const sorted = [...matches].sort((a, b) => a.column - b.column || a.line - b.line);
    const kept: SecretMatch[] = [];

    for (const candidate of sorted) {
      const cStart = candidate.column;
      const cEnd = cStart + candidate.matchLength;

      let dominated = false;

      for (let i = kept.length - 1; i >= 0; i--) {
        const existing = kept[i];
        const eStart = existing.column;
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

  /** Show the first 12 characters of a secret and replace the rest with '…'. */
  private maskValue(value: string): string {
    const PREFIX = 12;
    if (value.length <= PREFIX) {
      const show = Math.max(3, value.length - 3);
      return value.substring(0, show) + '...';
    }
    return value.substring(0, PREFIX) + '...';
  }
}
