import { validateVaultGuardConfig } from '../config-validate';

describe('validateVaultGuardConfig', () => {
  it('accepts an empty object', () => {
    const v = validateVaultGuardConfig({});
    expect(v.ok).toBe(true);
  });

  it('rejects unknown top-level keys', () => {
    const v = validateVaultGuardConfig({ foo: 1 });
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.errors.some(e => e.includes('unknown'))).toBe(true);
  });

  it('rejects invalid severity_overrides value', () => {
    const v = validateVaultGuardConfig({ severity_overrides: { openai: 'mega' } });
    expect(v.ok).toBe(false);
  });

  it('accepts a minimal extra_patterns entry', () => {
    const v = validateVaultGuardConfig({
      extra_patterns: [{ id: 'x', regex: 'foo', severity: 'high' }],
    });
    expect(v.ok).toBe(true);
  });
});
