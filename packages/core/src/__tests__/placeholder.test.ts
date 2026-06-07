import {
  isPlaceholderSecret,
  isNonSecretConnectionString,
  isSampleJwt,
  isRedactedTemplateValue,
  isEnvVarNameToken,
} from '../utils/placeholder';
import { isInsidePythonTripleQuoted } from '../utils/doc-context';

describe('isPlaceholderSecret', () => {
  describe('standard tier (applies to all patterns)', () => {
    it("flags AWS's documented example access key", () => {
      expect(isPlaceholderSecret('AKIAIOSFODNN7EXAMPLE')).toBe(true);
    });

    it('flags common doc placeholders', () => {
      for (const v of [
        'your_api_key_here',
        'YOUR-TOKEN',
        'changeme',
        'REPLACE_ME',
        'this-is-a-placeholder',
        'redacted-value-removed',
      ]) {
        expect(isPlaceholderSecret(v)).toBe(true);
      }
    });

    it('flags pure character-repetition padding', () => {
      expect(isPlaceholderSecret('xxxxxxxxxxxx')).toBe(true);
      expect(isPlaceholderSecret('000000000000')).toBe(true);
    });

    it('does NOT flag realistic high-entropy credentials', () => {
      for (const v of [
        'AKIAZ3KYR7N4QWXB2FGH',
        'AKIA1234567890123456',
        'sk-ant-api03-9f3kLm2qPzXyA8',
        'ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
        'dQw4w9WgXcQ8sJ2kLpZ',
      ]) {
        expect(isPlaceholderSecret(v)).toBe(false);
      }
    });
  });

  describe('aggressive tier (generic / password patterns only)', () => {
    it('flags test-fixture words only when aggressive', () => {
      expect(isPlaceholderSecret('testPassword1234', { aggressive: true })).toBe(true);
      expect(isPlaceholderSecret('testPassword1234', { aggressive: false })).toBe(false);
    });

    it('flags common weak/sample values when aggressive', () => {
      for (const v of ['sampleApiKey1234567', 'demo-secret-value-x', 'fakeTokenValue1234']) {
        expect(isPlaceholderSecret(v, { aggressive: true })).toBe(true);
      }
    });

    it('flags pydantic-style docstring demo passwords when aggressive', () => {
      expect(isPlaceholderSecret('IAmSensitive', { aggressive: true })).toBe(true);
      expect(isPlaceholderSecret('IAmSensitiveBytes', { aggressive: true })).toBe(true);
    });

    it('still passes a realistic generated value under aggressive mode', () => {
      expect(isPlaceholderSecret('Zk9Qp2Lm7Rt4Wx8Bn1Vc', { aggressive: true })).toBe(false);
    });
  });

  it('returns false for empty input', () => {
    expect(isPlaceholderSecret('')).toBe(false);
  });
});

describe('isNonSecretConnectionString', () => {
  it('flags local / docker / reserved-TLD hosts regardless of password', () => {
    for (const url of [
      'postgres://prisma:prisma@localhost:5432/tests',
      'mysql://root:root@localhost:3306/tests',
      'mysql://root:root@mysql/tests', // docker-compose service name
      'redis://app:SomeRealLooking9Pw@127.0.0.1:6379',
      'postgresql://svc:s3cr3t@cache.local:5432/app',
      'mongodb://u:p@host.docker.internal:27017/db',
    ]) {
      expect(isNonSecretConnectionString(url)).toBe(true);
    }
  });

  it('flags placeholder / default / templated passwords on remote hosts', () => {
    for (const url of [
      'postgres://user:pass@db.example-corp.com:5432/db',
      'mysql://USER:PASSWORD@aws.connect.psdb.cloud/DATABASE',
      'postgres://app:${DB_PASSWORD}@db.prod.example-corp.com/main',
      'mongodb+srv://root:randompassword@cluster0.ab1cd.mongodb.net/mydb',
      'postgres://identifier:key@db.prisma.io:5432/postgres',
    ]) {
      expect(isNonSecretConnectionString(url)).toBe(true);
    }
  });

  it('does NOT flag a real remote DSN with a real password (recall preserved)', () => {
    for (const url of [
      'postgresql://svc_app:Xj8kP2mQ9zRv@db.prod.acme-corp.com:5432/main',
      'mysql://reporting:7Fk2Lm9QzXp1@analytics.internal-corp.io:3306/warehouse',
    ]) {
      expect(isNonSecretConnectionString(url)).toBe(false);
    }
  });

  it('returns false for strings that are not connection URLs', () => {
    expect(isNonSecretConnectionString('not a url')).toBe(false);
    expect(isNonSecretConnectionString('https://example.com')).toBe(false);
  });
});

describe('isSampleJwt', () => {
  const SAMPLE =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  it('flags the canonical jwt.io sample token', () => {
    expect(isSampleJwt(SAMPLE)).toBe(true);
  });

  it('does NOT flag a JWT with non-sample claims', () => {
    const real =
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmNfYXBwIiwicm9sZSI6ImFkbWluIn0.Zx9Kp2Lm7Rt4Wx8Bn1Qj5Vc';
    expect(isSampleJwt(real)).toBe(false);
  });

  it('returns false for non-JWT input', () => {
    expect(isSampleJwt('not.a.jwt')).toBe(false);
    expect(isSampleJwt('singlepart')).toBe(false);
  });
});

describe('isRedactedTemplateValue', () => {
  it('flags X-redacted vendor key templates', () => {
    expect(isRedactedTemplateValue('sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')).toBe(true);
    expect(isRedactedTemplateValue(['sk_live_', 'X'.repeat(48)].join(''))).toBe(true);
    expect(isRedactedTemplateValue('replace-with-long-random-secret')).toBe(true);
  });

  it('does not flag realistic generated keys', () => {
    expect(isRedactedTemplateValue('sk-ant-api03-9f3kLm2qPzXyA8')).toBe(false);
  });
});

describe('isEnvVarNameToken', () => {
  it('flags ALL_CAPS env var names', () => {
    expect(isEnvVarNameToken('PLAID_TOKEN_ENCRYPTION_KEY')).toBe(true);
  });

  it('rejects short or mixed-case values', () => {
    expect(isEnvVarNameToken('short')).toBe(false);
    expect(isEnvVarNameToken('MySecretPass123')).toBe(false);
  });
});

describe('isInsidePythonTripleQuoted', () => {
  const content = [
    'EXAMPLES = r"""',
    '- name: Case insensitive password string match',
    '  ansible.builtin.expect:',
    '    responses:',
    '      (?i)password: "MySekretPa$$word"',
    '"""',
  ].join('\n');

  it('detects offsets inside triple-quoted docstring examples', () => {
    const needle = 'MySekretPa$$word';
    const idx = content.indexOf(needle);
    expect(isInsidePythonTripleQuoted(content, idx)).toBe(true);
  });

  it('returns false outside triple quotes', () => {
    expect(isInsidePythonTripleQuoted('password = "realSecretValue12"\n', 0)).toBe(false);
  });
});
