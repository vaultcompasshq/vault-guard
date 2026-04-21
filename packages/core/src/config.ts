import fs from 'fs';
import path from 'path';
import { SecretMatch } from './types';

/**
 * Shape of .vault-guard.json in a repository root.
 *
 * YAML support (.vault-guard.yml) deferred to a follow-up to avoid adding a runtime
 * dependency on the core package.
 */
export interface VaultGuardConfig {
  /** Glob patterns or file paths to skip entirely during scanning. */
  ignore?: {
    paths?: string[];
    patterns?: string[];
  };
  /**
   * Override severity for built-in pattern keys, or set to "off" to disable a
   * pattern entirely.  Keys match the pattern id strings in secret-scanner.ts.
   */
  severity_overrides?: Record<string, SecretMatch['severity'] | 'off'>;
  /**
   * Additional patterns to run alongside the built-in set.  Regex strings are
   * compiled at scanner construction time.
   */
  extra_patterns?: Array<{
    id: string;
    regex: string;
    severity: SecretMatch['severity'];
    description?: string;
    /** Optional minimum Shannon entropy (bits/char) for the matched value. */
    min_entropy?: number;
  }>;
  /**
   * Override the default Shannon entropy threshold (3.5 bits/char) used by
   * generic catch-all patterns.  Lower = more matches but more false positives.
   */
  entropy_threshold?: number;
}

const CONFIG_FILENAMES = ['.vault-guard.json', '.vault-guard.local.json'];

/**
 * Load the nearest Vault Guard config file, walking up from `startDir`.
 * Returns an empty config if no file is found.
 */
export function loadConfig(startDir: string = process.cwd()): VaultGuardConfig {
  let dir = startDir;

  while (true) {
    for (const filename of CONFIG_FILENAMES) {
      const filePath = path.join(dir, filename);
      if (fs.existsSync(filePath)) {
        try {
          const raw = fs.readFileSync(filePath, 'utf-8');
          return JSON.parse(raw) as VaultGuardConfig;
        } catch {
          // Silently ignore malformed config; fall through to defaults.
        }
      }
    }

    const parent = path.dirname(dir);
    if (parent === dir) break; // Reached filesystem root.
    dir = parent;
  }

  return {};
}
