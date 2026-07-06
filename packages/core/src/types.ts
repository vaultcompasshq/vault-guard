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
}

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
