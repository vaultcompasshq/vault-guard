export interface SecretMatch {
  /** Pattern id (e.g. "anthropic", "aws-access"). */
  type: string;
  /** Masked representation of the matched value (safe to log). */
  value: string;
  /** 1-based line number in the file. */
  line: number;
  /** 0-based line-relative UTF-16 column, for CLI/SARIF/editor display. */
  column: number;
  /** 0-based absolute UTF-16 offset in the scanned content, for dedupe/baselines. */
  offset: number;
  /** UTF-16 code-unit length of the original match (used for SARIF region output). */
  matchLength: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /**
   * SHA-256 hex of the raw matched text, present only for a value-bearing rule
   * (one whose match contains the secret rather than a fixed marker). It keys
   * the baseline's content fingerprint. The raw value itself never leaves the
   * scanner; only this digest does.
   */
  valueDigest?: string;
  /**
   * Which copy of the file the match came from: `index` (the staged blob),
   * `head` (the HEAD tree blob, pull-request mode), `worktree` (the copy on
   * disk of a tracked file), or `file` (an untracked file, a run outside git,
   * a single named file). Absent on matches from a bare `scanContent` call.
   */
  source?: MatchSource;
  /** For a conflicted path: 2 for the ours stage blob, 3 for theirs. */
  stage?: 2 | 3;
  /**
   * Set when the match was lowered to `low` because it is a slice of encoded
   * media (design 2026-10-17 data files, section 4.2). `severity` is already
   * the demoted one; `from` is what it was before.
   */
  demotion?: ContentDemotion;
  /**
   * Where the match sits in a data-shaped copy (design 2026-10-17 data files,
   * section 5.2): one column of the regular lines of a delimited copy, or a
   * line of 65536 characters or more. Presentation only: grouping reads it,
   * nothing that decides a severity or the exit does.
   */
  groupSlot?: GroupSlot;
}

/** Why a match was demoted. See {@link SecretMatch.demotion}. */
export type DemotionReason = 'data-uri-binary-payload' | 'base64-binary-run';

/** The record a demoted match carries. Field names are the JSON output's. */
export interface ContentDemotion {
  /** The severity before demotion. */
  from: 'critical' | 'high' | 'medium';
  reason: DemotionReason;
  /** The binary family the decoded head confirmed (`image`, `font`, ...). */
  family: string;
  /** The binary-table row that confirmed it (`.png`, `.woff2`, ...). */
  format: string;
  /** The declared media type, for a `data:` payload only. */
  media_type?: string;
  /** Characters in the base64 run. */
  run_length: number;
}

/** See {@link SecretMatch.groupSlot}. */
export type GroupSlot =
  | { basis: 'column'; delimiter: string; column: number }
  | { basis: 'long-line' };

/** Where a match's bytes were read from. See {@link SecretMatch.source}. */
export type MatchSource = 'index' | 'head' | 'worktree' | 'file';

export interface TokenReport {
  totalTokens: number;
  estimatedCost: number;
  breakdown: Record<string, number>;
}

export interface GuardStatus {
  security: {
    clean: boolean;
    critical: number;
    warning: number;
  };
  tokens: {
    used: number;
    limit: number;
    cost: number;
  };
  savings: {
    percentage: number;
    amount: number;
  };
  aiActive: boolean;
}
