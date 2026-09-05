import { isTestFilePath, applyPathAwareSeverity } from '../path-severity';
import type { SecretMatch } from '../../types';

function match(type: string, severity: SecretMatch['severity']): SecretMatch {
  return { type, value: 'abcd…(20c)', line: 1, column: 0, offset: 0, matchLength: 20, severity };
}

describe('isTestFilePath', () => {
  it('recognizes common JS/TS test paths', () => {
    expect(isTestFilePath('src/__tests__/api.test.ts')).toBe(true);
    expect(isTestFilePath('packages/foo/tests/bar.spec.js')).toBe(true);
  });

  it('recognizes Go *_test.go files', () => {
    expect(isTestFilePath('internal/communicator/ssh/communicator_test.go')).toBe(true);
    expect(isTestFilePath('discovery/vultr/mock_test.go')).toBe(true);
  });

  it('recognizes Python test_*.py and *_test.py', () => {
    expect(isTestFilePath('t/unit/backends/test_mongodb.py')).toBe(true);
    expect(isTestFilePath('tests/integration/db_test.py')).toBe(true);
  });

  it('recognizes Rust *_tests.rs and *_test.rs files under src/', () => {
    expect(isTestFilePath('codex-rs/login/src/auth/auth_tests.rs')).toBe(true);
    expect(isTestFilePath('crates/core/src/client_test.rs')).toBe(true);
    expect(isTestFilePath('src/protocol/item_builders_tests.rs')).toBe(true);
  });

  it('does not treat ordinary Rust source as a test file', () => {
    expect(isTestFilePath('codex-rs/login/src/auth/auth.rs')).toBe(false);
    expect(isTestFilePath('src/latest.rs')).toBe(false);
    expect(isTestFilePath('src/contest.rs')).toBe(false);
  });

  it('recognizes Celery-style t/unit/ and t/integration/ trees', () => {
    expect(isTestFilePath('celery/t/unit/security/__init__.py')).toBe(true);
    expect(isTestFilePath('proj/t/integration/foo.py')).toBe(true);
  });

  it('recognizes examples/ and related fixture dirs', () => {
    expect(isTestFilePath('examples/complex/scripts/seed.js')).toBe(true);
    expect(isTestFilePath('pkg/sample/demo.ts')).toBe(true);
  });

  it('recognizes *test suffix directories', () => {
    expect(isTestFilePath('caddytest/a.localhost.key')).toBe(true);
    expect(isTestFilePath('integrationtest/fixture.pem')).toBe(true);
  });

  it('does not treat contest/ or latest/ as test dirs', () => {
    expect(isTestFilePath('contest/winner.ts')).toBe(false);
    expect(isTestFilePath('latest/release.ts')).toBe(false);
  });

  it('recognizes .env.example templates', () => {
    expect(isTestFilePath('examples/sendgrid/.env.example')).toBe(true);
    expect(isTestFilePath('.env.sample')).toBe(true);
    expect(isTestFilePath('backend/.env.production.example')).toBe(true);
    expect(isTestFilePath('backend/.env.development.example')).toBe(true);
  });

  it('does not mark production source paths', () => {
    expect(isTestFilePath('src/database.ts')).toBe(false);
    expect(isTestFilePath('lib/ansible/modules/expect.py')).toBe(false);
  });
});

describe('applyPathAwareSeverity on Rust test files', () => {
  it('downgrades a generic pattern in src/foo_tests.rs', () => {
    const [out] = applyPathAwareSeverity([match('api-key-generic', 'high')], 'src/foo_tests.rs');
    expect(out.severity).toBe('low');
  });

  it('leaves the same match alone in src/foo.rs', () => {
    const [out] = applyPathAwareSeverity([match('api-key-generic', 'high')], 'src/foo.rs');
    expect(out.severity).toBe('high');
  });

  it('keeps a vendor-anchored rule at full severity in a Rust test file', () => {
    const [out] = applyPathAwareSeverity([match('github-token', 'critical')], 'src/foo_tests.rs');
    expect(out.severity).toBe('critical');
  });
});
