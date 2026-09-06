import { SecretScanner, type IgnoreDirectiveHits } from '../secret-scanner';

/**
 * Synthetic provider-shaped keys, joined at runtime. A committed provider-key
 * shape trips credential scanners regardless of the value being fake and the
 * file being a test, so no fragment matches a rule on its own.
 */
const ANTHROPIC_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

const AWS_ACCESS_KEY = ['AKIA', 'W7RQ', '3ZLP', 'K5MD', 'X2VC'].join('');

describe('inline ignore directives over a critical vendor-anchored finding', () => {
  const scanner = new SecretScanner();

  function hitsFor(content: string): IgnoreDirectiveHits {
    const hits: IgnoreDirectiveHits = { count: 0, lines: [] };
    scanner.scanContent(content, { filePath: 'src/app.ts', ignoreHits: hits });
    return hits;
  }

  it('counts a directive that hides a critical vendor-anchored finding separately', () => {
    const hits = hitsFor(`const k = "${ANTHROPIC_KEY}"; // vault-guard: ignore-line\n`);
    expect(hits.count).toBe(1);
    expect(hits.criticalVendorAnchored).toBe(1);
  });

  it('counts each such directive across several lines', () => {
    const hits = hitsFor(
      `const a = "${ANTHROPIC_KEY}"; // vault-guard: ignore-line\n` +
        `const b = "${AWS_ACCESS_KEY}"; // vault-guard: ignore-line\n`,
    );
    expect(hits.criticalVendorAnchored).toBe(2);
  });

  it('does not count a directive over a low-precision generic finding', () => {
    const hits = hitsFor(
      'const api_key = "Zq4Wm9Rb2Xt7Yn5Kd8Fp3Lv6Hs1Jc0Ge"; // vault-guard: ignore-line\n',
    );
    expect(hits.count).toBe(1);
    expect(hits.criticalVendorAnchored ?? 0).toBe(0);
  });

  it('leaves the count at zero when nothing was suppressed', () => {
    const hits = hitsFor(`const k = "${ANTHROPIC_KEY}";\n`);
    expect(hits.count).toBe(0);
    expect(hits.criticalVendorAnchored ?? 0).toBe(0);
  });
});
