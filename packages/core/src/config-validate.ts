import type { SecretMatch } from './types';
import type { VaultGuardConfig } from './config';

const SEVERITIES: ReadonlySet<string> = new Set(['critical', 'high', 'medium', 'low', 'off']);

/**
 * Structural validation for parsed `.vault-guard.json` (no file I/O).
 * Used by `vault-guard config validate` and for tooling that cannot run the scanner.
 */
export function validateVaultGuardConfig(value: unknown): { ok: true; config: VaultGuardConfig } | { ok: false; errors: string[] } {
  const errors: string[] = [];

  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return { ok: false, errors: ['root must be a JSON object'] };
  }

  const o = value as Record<string, unknown>;

  for (const key of Object.keys(o)) {
    const allowed = new Set([
      'ignore',
      'severity_overrides',
      'extra_patterns',
      'extra_patterns_unsafe',
      'entropy_threshold',
    ]);
    if (!allowed.has(key)) {
      errors.push(`unknown top-level key: ${JSON.stringify(key)}`);
    }
  }

  if (o.ignore !== undefined) {
    if (o.ignore === null || typeof o.ignore !== 'object' || Array.isArray(o.ignore)) {
      errors.push('ignore must be an object');
    } else {
      const ig = o.ignore as Record<string, unknown>;
      for (const k of Object.keys(ig)) {
        if (k !== 'paths' && k !== 'patterns') {
          errors.push(`ignore: unknown key ${JSON.stringify(k)}`);
        }
      }
      if (ig.paths !== undefined && !isStringArray(ig.paths)) {
        errors.push('ignore.paths must be an array of strings');
      }
      if (ig.patterns !== undefined && !isStringArray(ig.patterns)) {
        errors.push('ignore.patterns must be an array of strings');
      }
    }
  }

  if (o.severity_overrides !== undefined) {
    if (o.severity_overrides === null || typeof o.severity_overrides !== 'object' || Array.isArray(o.severity_overrides)) {
      errors.push('severity_overrides must be an object');
    } else {
      for (const [id, sev] of Object.entries(o.severity_overrides as Record<string, unknown>)) {
        if (typeof id !== 'string' || id.length === 0) {
          errors.push('severity_overrides keys must be non-empty strings');
          continue;
        }
        if (typeof sev !== 'string' || !SEVERITIES.has(sev)) {
          errors.push(`severity_overrides[${JSON.stringify(id)}] must be critical|high|medium|low|off`);
        }
      }
    }
  }

  if (o.extra_patterns_unsafe !== undefined && typeof o.extra_patterns_unsafe !== 'boolean') {
    errors.push('extra_patterns_unsafe must be a boolean');
  }

  if (o.entropy_threshold !== undefined) {
    if (typeof o.entropy_threshold !== 'number' || !Number.isFinite(o.entropy_threshold)) {
      errors.push('entropy_threshold must be a finite number');
    }
  }

  if (o.extra_patterns !== undefined) {
    if (!Array.isArray(o.extra_patterns)) {
      errors.push('extra_patterns must be an array');
    } else {
      o.extra_patterns.forEach((entry, i) => {
        if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
          errors.push(`extra_patterns[${i}] must be an object`);
          return;
        }
        const ep = entry as Record<string, unknown>;
        if (typeof ep.id !== 'string' || ep.id.length === 0) {
          errors.push(`extra_patterns[${i}].id must be a non-empty string`);
        }
        if (typeof ep.regex !== 'string' || ep.regex.length === 0) {
          errors.push(`extra_patterns[${i}].regex must be a non-empty string`);
        }
        if (typeof ep.severity !== 'string' || !isSeverity(ep.severity)) {
          errors.push(`extra_patterns[${i}].severity must be critical|high|medium|low`);
        }
        if (ep.description !== undefined && typeof ep.description !== 'string') {
          errors.push(`extra_patterns[${i}].description must be a string`);
        }
        if (ep.min_entropy !== undefined) {
          if (typeof ep.min_entropy !== 'number' || !Number.isFinite(ep.min_entropy)) {
            errors.push(`extra_patterns[${i}].min_entropy must be a finite number`);
          }
        }
      });
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, config: value as VaultGuardConfig };
}

function isStringArray(v: unknown): boolean {
  return Array.isArray(v) && v.every(x => typeof x === 'string');
}

function isSeverity(v: string): v is SecretMatch['severity'] {
  return v === 'critical' || v === 'high' || v === 'medium' || v === 'low';
}
