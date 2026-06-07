import { isTestFilePath } from '../path-severity';

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
