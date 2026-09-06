import { SecretScanner, getBuiltinPatternDocEntries } from '../secret-scanner';

/**
 * ReDoS regression guards for the built-in pattern table.
 *
 * Every bound here was MEASURED before it was changed, against an adversarial
 * input built to maximise backtracking, and re-measured after. Two shapes
 * produce super-linear cost in this table:
 *
 *   1. An unbounded greedy repeat followed by something that can fail, where
 *      the input supplies MANY viable start offsets. Each start rescans, so the
 *      g-flag start loop multiplies the per-start backtracking.
 *      (`gcp-oauth` on a digit run; `jwt-token` on repeated `eyJ`.)
 *   2. Two adjacent variable-length classes where the SECOND class contains the
 *      delimiter that ends the first, so every delimiter is a viable split and
 *      each split rescans to the end. (The four DSN rules: `[^:@\s]+ : [^@\s]+ @`,
 *      where `[^@\s]` contains `:`.)
 *
 * Bounding the repeat caps the per-start work; where a short prefix also
 * created the start offsets, a token-boundary lookbehind removes them.
 *
 * The budget below is generous relative to the bounded cost (tens of ms) and
 * far below the unbounded cost on these inputs, so CI variance cannot flip it.
 *
 * WHAT THESE TIMING TESTS DO AND DO NOT PROVE. Each timing assertion is
 * mutation-verified: reverting the change it guards makes that assertion fail
 * by a wide margin. The one exception is `jwt-token`, which carries TWO
 * defences that are not equally testable. This is recorded explicitly because
 * an earlier version of this comment claimed every bound was timing-guarded,
 * and for the `jwt-token` bound that was false:
 *
 *   - The token-boundary lookbehind is what makes `jwt-token` linear, and it IS
 *     guarded by timing (the 2M-character packed case below).
 *   - The `{1,4096}` segment bound is NOT provable by timing while the
 *     lookbehind is present. The lookbehind admits one candidate start per
 *     non-word separator, and each start's segment run reaches only as far as
 *     the next separator, so the runs are disjoint and total work is O(n) with
 *     or without the bound. Measured on separator-prefixed long runs the bound
 *     is a constant factor only: at a 50 MB input, bounded 11.7ms vs unbounded
 *     59.9ms. No practical input makes it cross a time budget, so the bound is
 *     guarded STRUCTURALLY instead (see the last test in this file). It still
 *     earns its keep as the second layer: with the lookbehind removed it cuts
 *     the packed-input cost from 8,203ms to 650ms at 200k.
 */
describe('ReDoS bounds on built-in patterns', () => {
  const scanner = new SecretScanner();

  const BUDGET_MS = 2000;

  /** Time a full scanContent pass over `input`. */
  const timeScan = (input: string): number => {
    const t0 = performance.now();
    scanner.scanContent(input);
    return performance.now() - t0;
  };

  // --- Shape 1: many viable start offsets ---------------------------------

  it('gcp-oauth: a 200k unbroken digit run scans in linear time', () => {
    // Unbounded `[0-9]+`: 200k measured at 16,563ms. Bounded {1,64}: ~38ms.
    expect(timeScan('0'.repeat(200_000))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('jwt-token: 2M of packed eyJ scans in linear time (guards the lookbehind)', () => {
    // Packed `eyJ` with no separators: every third character is a candidate
    // start, and each rescans forward hunting a `.` that never comes.
    //
    // Sized at 2M deliberately. At 200k, removing the lookbehind cost 650ms,
    // which sits UNDER the 2s budget, so the mutation would not have gone red
    // and this test would have guarded nothing. At 2M the same mutation costs
    // 6,803ms, a 3.4x margin over budget, while the correct pattern scans the
    // whole 2M in 23ms.
    expect(timeScan('eyJ'.repeat(666_666))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('ssh-private-key: a long BEGIN + caps/space run scans in linear time', () => {
    // This shape measured linear already (under 2ms at 400k); the bound is
    // hardening that removes the ambiguous overlap, not a fix.
    expect(timeScan('-----BEGIN ' + 'A '.repeat(100_000))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  // --- Shape 2: adjacent classes, second contains the first's delimiter ----

  // 400k rather than 200k so the UNBOUNDED form is unambiguously over budget:
  // measured unbounded at 200k these sit at 1.4s to 2.3s, which a 2s budget
  // would not reliably catch. At 400k the unbounded cost is roughly 4x that.
  const dsnAdversarial = (scheme: string): string => {
    const unit = `${scheme}a:`;
    return unit.repeat(Math.floor(400_000 / unit.length));
  };

  it('postgresql-url: repeated scheme + colon run scans in linear time', () => {
    // Unbounded: 50k=92ms, 100k=361ms, 200k=1,462ms (quadratic).
    expect(timeScan(dsnAdversarial('postgresql://'))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('mysql-url: repeated scheme + colon run scans in linear time', () => {
    // Unbounded: 50k=144ms, 100k=550ms, 200k=2,217ms (quadratic).
    expect(timeScan(dsnAdversarial('mysql://'))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('mongodb-url: repeated scheme + colon run scans in linear time', () => {
    // Unbounded: 50k=118ms, 100k=460ms, 200k=1,848ms (quadratic).
    expect(timeScan(dsnAdversarial('mongodb://'))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  it('redis-url: repeated scheme + colon run scans in linear time', () => {
    // Unbounded: 50k=139ms, 100k=572ms, 200k=2,289ms (quadratic).
    expect(timeScan(dsnAdversarial('redis://'))).toBeLessThan(BUDGET_MS);
  }, 30_000);

  // --- Detection must be unchanged by every bound above --------------------
  //
  // Values are assembled from fragments at runtime so no contiguous
  // credential-shaped string is committed (the convention used by
  // bench/generate-fixtures.cjs).

  it('still detects a real gcp-oauth client id after bounding', () => {
    const value = `407408718192-${'a'.repeat(32)}.apps.googleusercontent.com`;
    expect(scanner.scanContent(`const id = "${value}";`).map(m => m.type)).toContain('gcp-oauth');
  });

  it('still detects a real three-segment JWT after bounding', () => {
    const token = [
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
      '.',
      'eyJzdWIiOiJ2Zy1yZWRvcyIsImlhdCI6MTcwMDAwMDAwMH0',
      '.',
      'Kq7mZr2xVb9nTd4wHs6yLc3pJf8gRu5eNa1v',
    ].join('');
    expect(scanner.scanContent(`const t = "${token}";`).map(m => m.type)).toContain('jwt-token');
  });

  it('still detects a JWT with a long (1k+ char) payload segment', () => {
    // The bound is generous on purpose: a real token with fat claims must not
    // fall out of detection. This payload is ~1200 base64url chars.
    const token = [
      'eyJhbGciOiJIUzI1NiJ9',
      '.',
      `eyJ${'QWxpY2VCb2JDaGFybGll'.repeat(60)}`,
      '.',
      'Kq7mZr2xVb9nTd4wHs6yLc3p',
    ].join('');
    expect(scanner.scanContent(`const t = "${token}";`).map(m => m.type)).toContain('jwt-token');
  });

  it('still detects each real-shaped DSN after bounding', () => {
    const cases: Array<[string, string]> = [
      [
        'postgresql-url',
        ['postgresql://', 'svc_app:', 'Xj8kP2mQ9zRv@', 'db.prod.acme-corp.com:5432/main'].join(''),
      ],
      [
        'mysql-url',
        ['mysql://', 'svc_app:', 'Xj8kP2mQ9zRv@', 'db.prod.acme-corp.com:3306/main'].join(''),
      ],
      [
        'mongodb-url',
        ['mongodb://', 'svc_app:', 'Xj8kP2mQ9zRv@', 'db.prod.acme-corp.com:27017'].join(''),
      ],
      [
        'redis-url',
        ['redis://', 'svc_app:', 'Xj8kP2mQ9zRv@', 'cache.prod.acme-corp.com:6379'].join(''),
      ],
    ];
    for (const [rule, dsn] of cases) {
      expect(scanner.scanContent(`const url = "${dsn}";`).map(m => m.type)).toContain(rule);
    }
  });

  // --- Structural guard for the jwt-token bound ---------------------------
  //
  // Timing cannot guard this one (see the header comment): with the lookbehind
  // in place the bound is a constant factor, not an asymptotic one. So assert
  // the bound is literally present. This goes red the moment a segment repeat
  // is widened back to `+`, which is exactly the mutation timing misses.
  it('jwt-token keeps BOTH defences: bounded segments and the token boundary', () => {
    const jwt = getBuiltinPatternDocEntries().find(e => e.id === 'jwt-token');
    expect(jwt).toBeDefined();
    const src = jwt!.regexSource;

    // Second layer: every base64url segment repeat is bounded, so if the
    // lookbehind is ever removed the damage stays capped.
    expect(src).not.toMatch(/\[a-zA-Z0-9_-\]\+/);
    expect(src.match(/\[a-zA-Z0-9_-\]\{1,\d+\}/g) ?? []).toHaveLength(3);

    // First layer: the token boundary, which is what makes the rule linear.
    expect(src).toContain('(?<![A-Za-z0-9_-])');
  });

  it('still detects PKCS#8, RSA and PGP private key headers', () => {
    // A real PEM body wraps base64 at 64 chars/line; a short body is treated as
    // a bare header (UI label) and suppressed, so use a full-length line.
    const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn';
    // Headers assembled from fragments: a contiguous PEM marker in a committed
    // file matches this very rule (the reason bench/generate-fixtures.cjs
    // splits them too).
    const headers = [
      ['-----BEGIN PRIV', 'ATE KEY-----'].join(''),
      ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join(''),
      // The real PGP header ends in `BLOCK-----`, which the rule previously did
      // not match at all; the old test manufactured a pass by deleting " BLOCK".
      ['-----BEGIN PGP PRIV', 'ATE KEY BLOCK-----'].join(''),
    ];
    for (const header of headers) {
      expect(scanner.scanContent(`${header}\n${body}\n`).map(m => m.type)).toContain(
        'ssh-private-key',
      );
    }
  });
});
