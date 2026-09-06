import { SecretScanner } from '../secret-scanner';

/**
 * ReDoS regression guard for two built-in patterns whose shapes were flagged in
 * a source audit and then MEASURED:
 *
 *   - `gcp-oauth`: `[0-9]+-...` backtracks quadratically on a long unbroken
 *     digit run (measured 50k=1.0s, 100k=4.1s, 200k=16.6s, 400k=71.6s on the
 *     unbounded form — doubling the input quadrupled the time, i.e. a real
 *     catastrophic ReDoS). Bounding the prefix to `[0-9]{1,64}` makes it linear.
 *   - `ssh-private-key`: the space inside `[A-Z0-9 ]+ ` sits in the repeated
 *     class AND is required after it. Measured flat/linear on the unbounded form
 *     (all under 2ms at 400k), so lifting the space out of the class is
 *     hardening, not a fix, but it removes the ambiguous overlap for good.
 *
 * These assertions fail (via elapsed-time bound) if either bound is widened back
 * to the catastrophic shape. The per-test timeout is raised so the unbounded
 * form reports its real elapsed time rather than dying on jest's 5s default.
 */
describe('ReDoS bounds on built-in patterns', () => {
  const scanner = new SecretScanner();

  // Generous relative to the bounded cost (single-digit ms) and far below the
  // unbounded cost (16s at 200k digits), so CI variance cannot flip it.
  const BUDGET_MS = 2000;

  it('gcp-oauth: a 200k unbroken digit run scans in linear time', () => {
    const input = '0'.repeat(200_000);
    const t0 = performance.now();
    scanner.scanContent(input);
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('ssh-private-key: a long BEGIN + caps/space run scans in linear time', () => {
    const input = '-----BEGIN ' + 'A '.repeat(100_000);
    const t0 = performance.now();
    scanner.scanContent(input);
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('still detects a real gcp-oauth client id after bounding', () => {
    const value = `407408718192-${'a'.repeat(32)}.apps.googleusercontent.com`;
    const matches = scanner.scanContent(`const id = "${value}";`);
    expect(matches.map(m => m.type)).toContain('gcp-oauth');
  });

  it('still detects PKCS#8 and RSA private key headers after bounding', () => {
    // A real PEM body wraps base64 at 64 chars/line; a short body is treated as
    // a bare header (UI label) and suppressed, so use a full-length line.
    const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn';
    const pkcs8 = scanner.scanContent(`-----BEGIN PRIVATE KEY-----\n${body}\n`);
    expect(pkcs8.map(m => m.type)).toContain('ssh-private-key');
    const rsa = scanner.scanContent(`-----BEGIN RSA PRIVATE KEY-----\n${body}\n`);
    expect(rsa.map(m => m.type)).toContain('ssh-private-key');
  });
});
