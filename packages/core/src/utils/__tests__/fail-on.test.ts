import {
  DEFAULT_FAIL_ON,
  meetsFailThreshold,
  countBlockingMatches,
  resolveFailOn,
  isFailOnThreshold,
} from '../fail-on';
import type { FileScanResult } from '../../scan-output';
import type { SecretMatch } from '../../types';

function match(severity: SecretMatch['severity'], type = 'api-key-generic'): SecretMatch {
  return { type, value: 'abcd…(24c)', line: 1, column: 0, offset: 0, matchLength: 24, severity };
}

function results(...severities: SecretMatch['severity'][]): FileScanResult[] {
  return [{ file: 'a.ts', matches: severities.map(s => match(s)) }];
}

describe('fail-on threshold', () => {
  it('defaults to medium so path-downgraded findings do not block', () => {
    expect(DEFAULT_FAIL_ON).toBe('medium');
  });

  it('treats severities at or above the threshold as blocking', () => {
    expect(meetsFailThreshold('critical', 'medium')).toBe(true);
    expect(meetsFailThreshold('high', 'medium')).toBe(true);
    expect(meetsFailThreshold('medium', 'medium')).toBe(true);
    expect(meetsFailThreshold('low', 'medium')).toBe(false);
  });

  it('never blocks when the threshold is "none"', () => {
    for (const s of ['critical', 'high', 'medium', 'low'] as const) {
      expect(meetsFailThreshold(s, 'none')).toBe(false);
    }
  });

  it('blocks on everything at threshold "low" (pre-1.4.0 behaviour)', () => {
    expect(meetsFailThreshold('low', 'low')).toBe(true);
  });

  it('counts only blocking matches, not all matches', () => {
    const r = results('low', 'low', 'high', 'critical');
    expect(countBlockingMatches(r, 'medium')).toBe(2);
    expect(countBlockingMatches(r, 'low')).toBe(4);
    expect(countBlockingMatches(r, 'critical')).toBe(1);
    expect(countBlockingMatches(r, 'none')).toBe(0);
  });

  it('returns zero for an empty result set', () => {
    expect(countBlockingMatches([], 'medium')).toBe(0);
  });

  describe('resolveFailOn precedence', () => {
    it('prefers the CLI flag over config', () => {
      const r = resolveFailOn('critical', 'low');
      expect(r).toEqual({ ok: true, threshold: 'critical' });
    });

    it('falls back to config when no flag is given', () => {
      const r = resolveFailOn(undefined, 'low');
      expect(r).toEqual({ ok: true, threshold: 'low' });
    });

    it('falls back to the default when neither is set', () => {
      const r = resolveFailOn(undefined, undefined);
      expect(r).toEqual({ ok: true, threshold: 'medium' });
    });

    it('reports an invalid flag value rather than silently defaulting', () => {
      expect(resolveFailOn('sometimes', undefined)).toEqual({ ok: false, invalid: 'sometimes' });
    });

    it('reports an invalid config value', () => {
      expect(resolveFailOn(undefined, 'off')).toEqual({ ok: false, invalid: 'off' });
    });
  });

  it('validates threshold strings', () => {
    expect(isFailOnThreshold('none')).toBe(true);
    expect(isFailOnThreshold('critical')).toBe(true);
    expect(isFailOnThreshold('off')).toBe(false);
    expect(isFailOnThreshold(2)).toBe(false);
  });
});
