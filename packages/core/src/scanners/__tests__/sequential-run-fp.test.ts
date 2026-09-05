import { SecretScanner } from '../secret-scanner';

/**
 * Alphabet-run placeholders under a real vendor prefix are the shape that
 * produced the criticals on a public Rust monorepo scan: every one was a test
 * fixture spelling out the alphabet after `ghp_` or `AKIA`. The entropy gate
 * cannot see them, and vendor-anchored rules do not consult it at all.
 *
 * Suppressing them is safe for vendor-anchored rules specifically because a
 * real provider key is random and cannot be an alphabet run.
 *
 * Every value below is synthetic and written for this test.
 */
describe('alphabet-run placeholders under vendor prefixes', () => {
  const scanner = new SecretScanner();

  it('suppresses a github-token-shaped alphabet run', () => {
    const src = `const t = "${['ghp_', 'abcdefghijklmnopqrstuvwxyz1234567890'].join('')}";`;
    expect(scanner.scanContent(src).map(m => m.type)).not.toContain('github-token');
  });

  it('still reports a random value under the same prefix', () => {
    const src = `const t = "${['ghp_', 'Kq7mZr2xVb9nTd4wHs6yLc3pJf8gRu5eNa1v'].join('')}";`;
    expect(scanner.scanContent(src).map(m => m.type)).toContain('github-token');
  });

  it('suppresses an aws-access-shaped alphabet run', () => {
    const src = `const k = "${['AKIA', 'ABCDEFGHIJKLMNOP'].join('')}";`;
    expect(scanner.scanContent(src).map(m => m.type)).not.toContain('aws-access');
  });

  it('still reports a random AWS access key id', () => {
    const src = `const k = "${['AKIA', 'Z3KYR7N4QWXB2FGH'].join('')}";`;
    expect(scanner.scanContent(src).map(m => m.type)).toContain('aws-access');
  });

  it('suppresses an alphabet run behind a generic api-key assignment', () => {
    const value = [
      'sk-',
      'proj-',
      'abcdefghijklmnopqrstuvwxyz',
      'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      '0123456789',
    ].join('');
    const src = `let api_key = "${value}";`;
    expect(scanner.scanContent(src)).toHaveLength(0);
  });

  it('does not suppress a value that is only half a run', () => {
    const src = 'let api_key = "abcdefghijklmnopqrKq7mZr2xVb9nTd4wHs";';
    expect(scanner.scanContent(src).map(m => m.type)).toContain('api-key-generic');
  });
});

/**
 * The sequential-run check suppresses outright, and its safety argument is
 * "a real key is random, so it cannot be a run". That argument holds for
 * machine-generated credentials and fails completely for human-chosen ones: a
 * weak password IS a keyboard run, and being a run is what makes it worth
 * reporting rather than evidence that it is fake. Rules whose value a person
 * types are exempt from the check.
 *
 * Every value below is synthetic and written for this test.
 */
describe('rules whose value is human-chosen are exempt from the run check', () => {
  const scanner = new SecretScanner();

  const WEAK_RUN_PASSWORDS = [
    'abcdefgh1234', // 12 chars: one 8-letter run plus one 4-digit run
    'abcd1234wxyz6789', // 16 chars: four 4-character runs
  ];

  it.each(WEAK_RUN_PASSWORDS)('reports the weak password %s at full severity', pw => {
    const found = scanner.scanContent(`const password = "${pw}";`);
    expect(found.map(m => m.type)).toContain('password-in-code');
    expect(found.find(m => m.type === 'password-in-code')?.severity).toBe('high');
  });

  it.each(WEAK_RUN_PASSWORDS)('still suppresses %s shaped as a vendor token', pw => {
    // Same run material, padded to a github-token length under a real prefix.
    const token = ['ghp_', pw.repeat(4).slice(0, 36)].join('');
    expect(scanner.scanContent(`const t = "${token}";`).map(m => m.type)).not.toContain(
      'github-token',
    );
  });

  it('reports a connection string whose password is a long run', () => {
    // The DSN structure around a human-chosen password is not by itself enough
    // to pull run coverage below the threshold: this one lands at 75.4%.
    const dsn = `redis://a:${'abcdefghijklmnopqrstuvwxyz'.repeat(2)}@b.io:1`;
    expect(scanner.scanContent(`const url = "${dsn}";`).map(m => m.type)).toContain('redis-url');
  });
});
