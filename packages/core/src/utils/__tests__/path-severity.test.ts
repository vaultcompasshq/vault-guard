import { isTestFilePath, isLocalePath, applyPathAwareSeverity } from '../path-severity';
import type { SecretMatch } from '../../types';

function match(type: string, severity: SecretMatch['severity']): SecretMatch {
  return { type, value: 'abcd…(20c)', line: 1, column: 0, offset: 0, matchLength: 20, severity };
}

/**
 * The locale rule (design 2026-10-12, section 5): a locale path needs a locale
 * directory, and on one only four generic rules downgrade.
 */
describe('locale paths', () => {
  const NEVER_ON_LOCALE = ['postgresql-url', 'mysql-url', 'mongodb-url', 'redis-url', 'ssh-private-key', 'jwt-token'];
  const ALLOWED_ON_LOCALE = ['password-in-code', 'api-key-generic', 'secret-generic', 'bearer-token'];

  it.each(['db.ts', 'db.js', 'db.yml', 'ci.yml', 'sa.json', 'pg.js'])(
    'U14: two-letter basenames outside a locale directory keep full severity (%s)',
    name => {
      expect(isLocalePath(`loc/${name}`)).toBe(false);
      for (const id of [...NEVER_ON_LOCALE, ...ALLOWED_ON_LOCALE]) {
        expect(applyPathAwareSeverity([match(id, 'critical')], `loc/${name}`)[0].severity).toBe('critical');
      }
    },
  );

  it('U14: two-letter basenames outside a locale directory keep full severity', () => {
    expect(isLocalePath('src/en.json')).toBe(false);
    expect(isLocalePath('src/locales/de.json')).toBe(true);
  });

  it('U14: DSN, PEM and JWT rules are never downgraded on a locale path', () => {
    for (const p of ['src/locales/de.json', 'config/locales/en.yml', 'i18n/en.json', 'app/lang/x.ts']) {
      for (const id of NEVER_ON_LOCALE) {
        expect({ p, id, s: applyPathAwareSeverity([match(id, 'critical')], p)[0].severity }).toEqual({
          p,
          id,
          s: 'critical',
        });
      }
    }
  });

  it('U14: the four generic rules are downgraded on a locale path', () => {
    for (const id of ALLOWED_ON_LOCALE) {
      expect(applyPathAwareSeverity([match(id, 'high')], 'src/locales/de-DE.yaml')[0].severity).toBe('low');
    }
  });

  it('U14: a PEM under docs/locales is not downgraded', () => {
    expect(applyPathAwareSeverity([match('ssh-private-key', 'critical')], 'docs/locales/x.md')[0].severity).toBe(
      'critical',
    );
  });

  it('U14: a test path still downgrades the PEM and DSN rules', () => {
    expect(applyPathAwareSeverity([match('ssh-private-key', 'critical')], 'tests/locales/k.pem')[0].severity).toBe('low');
    expect(applyPathAwareSeverity([match('postgresql-url', 'critical')], 'tests/db.ts')[0].severity).toBe('low');
  });
});

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

describe('applyPathAwareSeverity judges context relative to the scan root', () => {
  const root = '/home/runner/work/docs/loadtest/repo';

  it('does not downgrade in src/config.ts when the ROOT path contains docs and loadtest', () => {
    const [out] = applyPathAwareSeverity(
      [match('ssh-private-key', 'critical')],
      `${root}/src/config.ts`,
      root,
    );
    expect(out.severity).toBe('critical');
  });

  it('still downgrades a real tests/ directory inside the root', () => {
    const [out] = applyPathAwareSeverity(
      [match('ssh-private-key', 'critical')],
      `${root}/tests/key.ts`,
      root,
    );
    expect(out.severity).toBe('low');
  });

  it('uses only the basename for a file outside the root', () => {
    const [out] = applyPathAwareSeverity(
      [match('ssh-private-key', 'critical')],
      '/srv/docs/tests/key.ts',
      root,
    );
    expect(out.severity).toBe('critical');
  });
});

describe('applyPathAwareSeverity does not downgrade vendor-anchored keys in docs', () => {
  it.each(['NOTES.md', 'CLAUDE.md', 'docs/x.md', 'website/page.mdx'])(
    'keeps an anthropic key at critical in %s',
    file => {
      const [out] = applyPathAwareSeverity([match('anthropic', 'critical')], file);
      expect(out.severity).toBe('critical');
    },
  );

  it.each(['CLAUDE.md', 'docs/runbook.md'])(
    'keeps a full-body PEM private key at critical in %s',
    file => {
      const [out] = applyPathAwareSeverity([match('ssh-private-key', 'critical')], file);
      expect(out.severity).toBe('critical');
    },
  );

  it('still downgrades a PEM under a tests/ fixture directory', () => {
    const [out] = applyPathAwareSeverity(
      [match('ssh-private-key', 'critical')],
      'tests/fixtures/key.pem',
    );
    expect(out.severity).toBe('low');
  });

  it('still downgrades a generic api-key match in docs', () => {
    const [out] = applyPathAwareSeverity([match('api-key-generic', 'high')], 'docs/x.md');
    expect(out.severity).toBe('low');
  });
});
