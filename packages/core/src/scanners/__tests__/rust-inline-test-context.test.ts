import { SecretScanner } from '../secret-scanner';

/**
 * Rust's dominant unit-test convention puts the tests in the same file as the
 * production code, inside `#[cfg(test)] mod tests { … }`. No path heuristic can
 * see that, so the scanner reads the file's own module boundaries instead.
 *
 * All values below are synthetic and built for these tests.
 */
const PROD_KEY = 'Kq7mZr2xVb9nTd4wHs6yLc3p';
const TEST_KEY = 'Jd4pWn8sQe2vRb6yTc9mXf3z';
const VENDOR_TOKEN = ['ghp_', 'Kq7mZr2xVb9nTd4wHs6yLc3pJf8gRu5eNa1v'].join('');

const RUST_SOURCE = [
  'use crate::auth::Client;',
  '',
  'pub fn build_client() -> Client {',
  `    let api_key = "${PROD_KEY}";`,
  '    Client::new(api_key)',
  '}',
  '',
  '#[cfg(test)]',
  'mod tests {',
  '    use super::*;',
  '',
  '    #[test]',
  '    fn builds_with_a_throwaway_key() {',
  `        let api_key = "${TEST_KEY}";`,
  `        let token = "${VENDOR_TOKEN}";`,
  '        assert!(Client::new(api_key).is_ok());',
  '        assert!(Client::with_token(token).is_ok());',
  '    }',
  '}',
  '',
].join('\n');

describe('inline #[cfg(test)] modules downgrade downgrade-eligible rules', () => {
  const scanner = new SecretScanner();

  function severityOfKey(src: string, filePath: string, key: string): string | undefined {
    const line = src.slice(0, src.indexOf(key)).split('\n').length;
    return scanner.scanContent(src, { filePath }).find(m => m.line === line)?.severity;
  }

  it('downgrades a generic match inside the cfg(test) region', () => {
    expect(severityOfKey(RUST_SOURCE, 'src/client.rs', TEST_KEY)).toBe('low');
  });

  it('leaves the same rule at full severity before the attribute', () => {
    expect(severityOfKey(RUST_SOURCE, 'src/client.rs', PROD_KEY)).toBe('high');
  });

  it('keeps a vendor-anchored rule at critical inside the region', () => {
    expect(severityOfKey(RUST_SOURCE, 'src/client.rs', VENDOR_TOKEN)).toBe('critical');
  });

  it('reports every match, since the region downgrades and never suppresses', () => {
    const types = scanner.scanContent(RUST_SOURCE, { filePath: 'src/client.rs' }).map(m => m.type);
    expect(types.filter(t => t === 'api-key-generic')).toHaveLength(2);
    expect(types).toContain('github-token');
  });

  it('leaves a file with no cfg(test) attribute unchanged', () => {
    const src = [
      'pub fn build_client() -> Client {',
      `    let api_key = "${PROD_KEY}";`,
      '    Client::new(api_key)',
      '}',
      '',
      'pub fn build_other() -> Client {',
      `    let api_key = "${TEST_KEY}";`,
      '    Client::new(api_key)',
      '}',
      '',
    ].join('\n');
    const severities = scanner.scanContent(src, { filePath: 'src/client.rs' }).map(m => m.severity);
    expect(severities).toEqual(['high', 'high']);
  });

  it('does not apply the Rust region rule to a non-Rust file', () => {
    expect(severityOfKey(RUST_SOURCE, 'src/client.ts', TEST_KEY)).toBe('high');
  });
});

/**
 * The region downgrade must run AFTER deduplication, so that the ranking which
 * resolves two overlapping matches still sees the rules' declared severities.
 *
 * Nothing pinned that before: swapping the two steps kept the whole suite
 * green. This case separates them. A `redis-url` (critical, downgrade
 * eligible) and a lower-severity extra pattern cover the same span inside a
 * `#[cfg(test)]` module:
 *
 *   after dedupe  - dedupe keeps redis-url on rank, then demotes it to low
 *   before dedupe - redis-url is demoted first, so the extra pattern now
 *                   outranks it and dedupe keeps the WRONG match, at high
 *
 * The assertions below name both the surviving rule and its severity, so
 * either half of that swap fails.
 */
describe('inline test severity is applied after deduplication', () => {
  const DSN_PASSWORD = 'Kq7mZr2xVb9nTd4wHs6yLc3p';
  const DSN = `redis://svc_app:${DSN_PASSWORD}@db.prod.acme-corp.com:6379`;

  const SRC = [
    'pub fn connect() {}',
    '',
    '#[cfg(test)]',
    'mod tests {',
    '    #[test]',
    '    fn reads_the_dsn() {',
    `        let url = "${DSN}";`,
    '        assert!(connect_to(url).is_ok());',
    '    }',
    '}',
    '',
  ].join('\n');

  const scanner = new SecretScanner({
    extra_patterns: [
      { id: 'internal-host', regex: 'db\\.prod\\.acme-corp\\.com', severity: 'high' },
    ],
  });

  it('keeps the higher-ranked rule and then downgrades it', () => {
    const overlapping = scanner
      .scanContent(SRC, { filePath: 'src/db.rs' })
      .filter(m => m.type === 'redis-url' || m.type === 'internal-host');

    expect(overlapping).toHaveLength(1);
    expect(overlapping[0].type).toBe('redis-url');
    expect(overlapping[0].severity).toBe('low');
  });
});
