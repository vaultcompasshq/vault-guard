import { SecretScanner } from '../secret-scanner';
import { isPasswordHash, isPemHeaderWithoutBody } from '../../utils/placeholder';
import { isTestFilePath, isLocalePath } from '../../utils/path-severity';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** Write `relPath` under a fresh temp dir and return the absolute path. */
function writeTemp(relPath: string, content: string): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-dogfood-'));
  const full = path.join(root, relPath);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

/**
 * Regressions for false positives found by scanning ~80k files of public
 * open-source code. Each case was the dominant noise source for its rule.
 */
describe('password hashes are not plaintext passwords', () => {
  const scanner = new SecretScanner();

  const hashes = [
    '$2b$12$UREFwsRUoyF0CRqGNK0LzO0HM/jLhgUCNNIJ9RJAqMUQ74crlJ1Vu', // bcrypt
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy',
    '$2y$10$abcdefghijklmnopqrstuvwxyz012345678901234567890123456',
    '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub',
    '$6$rounds=656000$YQm1pTCkGDBOQOvS$0PtCX0hMlyAOaLEQ4tOa1234',
    '$1$abcdefgh$ijklmnopqrstuvwxyz012',
    'pbkdf2_sha256$390000$abcdefghijkl$mnopqrstuvwxyz0123456789ABCDEF=',
  ];

  it.each(hashes)('does not report %s', hash => {
    const matches = scanner.scanContent(`{"password":"${hash}"}`);
    expect(matches.map(m => m.type)).not.toContain('password-in-code');
  });

  it.each(hashes)('isPasswordHash recognises %s', hash => {
    expect(isPasswordHash(hash)).toBe(true);
  });

  it('still reports a plaintext password literal', () => {
    const matches = scanner.scanContent(`{"password":"Tr0ub4dor&3xKcd99z"}`);
    expect(matches.map(m => m.type)).toContain('password-in-code');
  });

  it('does not treat an ordinary value beginning with $ as a hash', () => {
    expect(isPasswordHash('$uper$ecretPassw0rdValue')).toBe(false);
  });
});

describe('bare PEM headers carry no key material', () => {
  const scanner = new SecretScanner();

  it('does not report a PEM header used as a UI string constant', () => {
    const src = [
      "const certificateBeginsWith = '-----BEGIN CERTIFICATE-----';",
      "const privateKeyBeginsWith = '-----BEGIN RSA PRIVATE KEY-----';",
      '',
      'return <textarea placeholder={privateKeyBeginsWith} />;',
    ].join('\n');
    expect(scanner.scanContent(src).map(m => m.type)).not.toContain('ssh-private-key');
  });

  it('does not report a header followed only by a redaction marker', () => {
    const src = '-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----';
    expect(scanner.scanContent(src).map(m => m.type)).not.toContain('ssh-private-key');
  });

  it('still reports a header followed by real key material', () => {
    const src = [
      '-----BEGIN PRIVATE KEY-----',
      'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn',
      '0Wd0+wN653+urjWMRkWxU5W2NCCNLUDly3oKZ8sCAwEAAQJBAJvZ3Xk2Qm1cUx9p',
      '-----END PRIVATE KEY-----',
    ].join('\n');
    expect(scanner.scanContent(src).map(m => m.type)).toContain('ssh-private-key');
  });

  it('still reports a key embedded in JSON with escaped newlines', () => {
    const src =
      '{"clientKey": "-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49\\n-----END EC PRIVATE KEY-----"}';
    expect(scanner.scanContent(src).map(m => m.type)).toContain('ssh-private-key');
  });

  it('isPemHeaderWithoutBody is offset-based', () => {
    const withBody = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n';
    expect(isPemHeaderWithoutBody(withBody, 27)).toBe(false);
    expect(isPemHeaderWithoutBody("'-----BEGIN PRIVATE KEY-----';", 28)).toBe(true);
  });
});

describe('hyphen and underscore test-data directories', () => {
  it.each(['a/test-data/keys/x.pem', 'a/test_data/x.pem', 'a/testdata/x.pem', 'a/fixture/x.pem'])(
    'treats %s as a test path',
    p => {
      expect(isTestFilePath(p)).toBe(true);
    },
  );

  it('does not treat src/ as a test path', () => {
    expect(isTestFilePath('src/server/keys.pem')).toBe(false);
  });
});

describe('translation catalogues hold labels, not credentials', () => {
  const scanner = new SecretScanner();

  it('does not block on a translated label under a lang/ directory', () => {
    const matches = scanner.scan(
      writeTemp('app/src/lang/translations/de-DE.yaml', '    tfa_secret: Zwei-Faktor-Authentifizierung\n'),
    );
    expect(matches.every(m => m.severity === 'low')).toBe(true);
  });

  it.each([
    'app/src/lang/translations/de-DE.yaml',
    'src/locales/en.json',
    'frontend/i18n/pt_BR.yml',
    'ui/translations/nl-NL.yaml',
    'src/en.json',
  ])('treats %s as a locale path', p => {
    expect(isLocalePath(p)).toBe(true);
  });

  it.each(['src/server/config.json', 'packages/core/src/index.ts', 'src/language-service.ts'])(
    'does not treat %s as a locale path',
    p => {
      expect(isLocalePath(p)).toBe(false);
    },
  );
});
