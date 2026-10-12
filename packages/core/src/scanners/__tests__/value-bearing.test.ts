import { createHash } from 'crypto';

import { SecretScanner, getBuiltinPatternDocEntries } from '../secret-scanner';

/**
 * Header-only rules (T17, unit half).
 *
 * A baseline content entry keys on a digest of the matched text. For a rule
 * whose match is a fixed marker rather than the secret, that digest is the same
 * for every key, so a content entry would suppress any replacement key in the
 * file. Which rules are like that is declared on the rule table itself, as a
 * required field, so a new rule cannot be added without deciding.
 */
describe('valueBearing on the rule table', () => {
  it('every built-in rule declares valueBearing as a boolean', () => {
    for (const entry of getBuiltinPatternDocEntries()) {
      expect(typeof entry.valueBearing).toBe('boolean');
    }
  });

  it('exactly ssh-private-key and gcp-service-account are not value-bearing today', () => {
    const headerOnly = getBuiltinPatternDocEntries()
      .filter(e => !e.valueBearing)
      .map(e => e.id)
      .sort();
    expect(headerOnly).toEqual(['gcp-service-account', 'ssh-private-key']);
  });

  it('a user extra pattern is never value-bearing', () => {
    const scanner = new SecretScanner({
      extra_patterns: [{ id: 'acme-token', regex: 'acme_[a-z0-9]{24}', severity: 'high' }],
    });
    expect(scanner.isValueBearing('acme-token')).toBe(false);
    expect(scanner.isValueBearing('github-token')).toBe(true);
    expect(scanner.isValueBearing('ssh-private-key')).toBe(false);
    expect(scanner.isValueBearing('no-such-rule')).toBe(false);
  });

  it('a value-bearing match carries the SHA-256 of the raw match, never the raw value', () => {
    const token = ['ghp_', 'Zq8mW2xRb7nTd4vHs6yLc3pJf8gRu5eNa1vB'].join('');
    const [m] = new SecretScanner().scanContent(`const t = "${token}";\n`);
    expect(m.type).toBe('github-token');
    expect(m.valueDigest).toBe(createHash('sha256').update(token, 'utf8').digest('hex'));
    expect(JSON.stringify(m)).not.toContain(token);
  });

  it('a header-only match carries no value digest', () => {
    const header = ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join('');
    const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn';
    const matches = new SecretScanner().scanContent(`${header}\n${body}\n`);
    const pem = matches.find(m => m.type === 'ssh-private-key');
    expect(pem).toBeDefined();
    expect(pem?.valueDigest).toBeUndefined();
  });
});
