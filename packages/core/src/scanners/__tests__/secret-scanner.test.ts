import { SecretScanner } from '../secret-scanner';
import fs from 'fs';
import path from 'path';
import os from 'os';

describe('SecretScanner', () => {
  let scanner: SecretScanner;
  let testFilePath: string;

  beforeEach(() => {
    scanner = new SecretScanner();
    testFilePath = path.join(__dirname, 'test-file.ts');
  });

  afterEach(() => {
    if (fs.existsSync(testFilePath)) fs.unlinkSync(testFilePath);
  });

  it('getActivePatternCount reflects disabled rules', () => {
    const full = new SecretScanner().getActivePatternCount();
    const minusOne = new SecretScanner({ severity_overrides: { anthropic: 'off' } }).getActivePatternCount();
    expect(minusOne).toBe(full - 1);
  });

  // ---------------------------------------------------------------------------
  // True positives — vendor-specific prefixes
  // ---------------------------------------------------------------------------

  describe('vendor-specific patterns', () => {
    it('detects Anthropic API key', () => {
      fs.writeFileSync(testFilePath, `const k = "sk-ant-api03-1234567890abcdefg";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('anthropic');
      expect(matches[0].severity).toBe('critical');
      expect(matches[0].value).toMatch(/^sk-a…\(\d+c\)$/);
    });

    it('detects Stripe live key', () => {
      const live = `${'sk'}_${'live'}_51AbCdEfGhIjKlMnOpQrStUvWx`;
      fs.writeFileSync(testFilePath, `const k = "${live}";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('stripe');
      expect(matches[0].severity).toBe('critical');
    });

    it('detects Stripe test key', () => {
      const testKey = `${'sk'}_${'test'}_51AbCDEFGHIJKLMNOPQRSTUVWXYZ`;
      fs.writeFileSync(testFilePath, `const k = "${testKey}";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('stripe-test');
      expect(matches[0].severity).toBe('high');
    });

    it('detects AWS access key', () => {
      fs.writeFileSync(testFilePath, `const k = "AKIA1234567890123456";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('aws-access');
      expect(matches[0].severity).toBe('critical');
    });

    it('detects GitHub token', () => {
      fs.writeFileSync(testFilePath, `const k = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'github-token')).toBe(true);
    });

    it('detects HuggingFace token', () => {
      fs.writeFileSync(testFilePath, `const k = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('huggingface');
    });

    it('detects SendGrid API key', () => {
      fs.writeFileSync(testFilePath, `const k = "SG.AAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'sendgrid-api')).toBe(true);
    });

    it('detects SSH private key header', () => {
      fs.writeFileSync(testFilePath, `-----BEGIN OPENSSH PRIVATE KEY-----`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('ssh-private-key');
    });

    it('detects PostgreSQL connection URL with a real remote host + password', () => {
      fs.writeFileSync(
        testFilePath,
        `const url = "postgresql://svc_app:Xj8kP2mQ9zRv@db.prod.acme-corp.com:5432/main";`,
      );
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'postgresql-url')).toBe(true);
    });

    it('detects JWT token', () => {
      fs.writeFileSync(testFilePath, `const t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.FAKE_SIG";`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'jwt-token')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Masking
  // ---------------------------------------------------------------------------

  describe('value masking', () => {
    it('redacts to a 4-char prefix + length tag (sk-a…(Nc))', () => {
      fs.writeFileSync(testFilePath, `const k = "sk-ant-api03-verylongkeyhere123456789";`);
      const matches = scanner.scan(testFilePath);
      expect(matches[0].value).not.toContain('verylongkeyhere123456789');
      expect(matches[0].value).not.toContain('sk-ant-api03');
      expect(matches[0].value).toMatch(/^sk-a…\(\d+c\)$/);
    });

    it('never includes the raw secret in any output formatter', async () => {
      const { formatJson, formatSarif } = await import('../../scan-output');
      const rawSecret = 'sk-ant-api03-verylongkeyhere123456789';
      fs.writeFileSync(testFilePath, `const k = "${rawSecret}";`);
      const matches = scanner.scan(testFilePath);
      const results = [{ file: testFilePath, matches }];
      const json = formatJson(results);
      const sarif = formatSarif(results);
      expect(json).not.toContain(rawSecret);
      expect(sarif).not.toContain(rawSecret);
      expect(json).not.toContain('verylongkeyhere');
      expect(sarif).not.toContain('verylongkeyhere');
    });
  });

  // ---------------------------------------------------------------------------
  // Deduplication
  // ---------------------------------------------------------------------------

  describe('deduplication', () => {
    it('reports exactly one match per distinct secret on different lines', () => {
      const stripeTest = `${'sk'}_${'test'}_51ABCDEFGHIJKLMNOPQRSTUVWXYZ`;
      const content = [
        `const anthropicKey = "sk-ant-api03-verylongkeyhere12345";`,
        `const stripeKey = "${stripeTest}";`,
        `const awsKey = "AKIA1234567890123456";`,
      ].join('\n');
      fs.writeFileSync(testFilePath, content);

      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(3);
      expect(matches.map(m => m.type)).toEqual(['anthropic', 'stripe-test', 'aws-access']);
    });
  });

  // ---------------------------------------------------------------------------
  // False positives — none of these should fire
  // ---------------------------------------------------------------------------

  describe('false positive suppression', () => {
    it('does NOT flag git commit SHAs', () => {
      fs.writeFileSync(testFilePath, `const sha = "9c7f1a4b2e6d5f3a8b0c1d2e3f4a5b6c7d8e9f01";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag MD5 hashes', () => {
      fs.writeFileSync(testFilePath, `const hash = "5d41402abc4b2a76b9719d911017c592";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag Google Analytics measurement IDs (UA- / G-)', () => {
      fs.writeFileSync(testFilePath, `const id = "UA-12345678-1";\nconst g = "G-ABCDEF1234";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag SSH public keys', () => {
      fs.writeFileSync(testFilePath, `const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag Twilio Account SID (public identifier)', () => {
      const sid = `${'A'}${'C'}1234567890abcdef1234567890abcdef`;
      fs.writeFileSync(testFilePath, `const sid = "${sid}";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag a plain doc URL with user:pass', () => {
      fs.writeFileSync(testFilePath, `const url = "https://user:pass@example.com:443/healthz";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag a short random base64-ish string without context', () => {
      fs.writeFileSync(testFilePath, `const v = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd";`);
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('does NOT flag an unquoted assignment to a function-call result', () => {
      // Real Django csrf.py FP: `csrf_secret = _add_new_csrf_cookie(request)`
      // captured the callee `_add_new_csrf_cookie` as a generic secret.
      fs.writeFileSync(
        testFilePath,
        [
          'csrf_secret = _add_new_csrf_cookie(request)',
          'csrf_secret = _unmask_cipher_token(csrf_secret)',
          'apiKey = buildApiKeyFromEnvironment(config)',
        ].join('\n'),
      );
      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(0);
    });

    it('still flags a genuine unquoted secret assignment (no trailing paren)', () => {
      fs.writeFileSync(testFilePath, `secret = Zg7kP2mQxN4RvT8wYhLs6Fj`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'secret-generic')).toBe(true);
    });

    it('returns empty array for clean file', () => {
      fs.writeFileSync(testFilePath, `const msg = "Hello, world!";`);
      expect(scanner.scan(testFilePath)).toHaveLength(0);
    });

    it('returns empty array for non-existent file', () => {
      expect(scanner.scan('/does/not/exist.ts')).toHaveLength(0);
    });
  });

  // ---------------------------------------------------------------------------
  // Placeholder / example / test-fixture suppression
  // ---------------------------------------------------------------------------

  describe('placeholder suppression', () => {
    it("does NOT flag AWS's documented example access key", () => {
      fs.writeFileSync(testFilePath, `const k = "AKIAIOSFODNN7EXAMPLE";`);
      expect(scanner.scan(testFilePath)).toHaveLength(0);
    });

    it('does NOT flag a test-fixture password assignment', () => {
      fs.writeFileSync(testFilePath, `const password = 'testPasword1234';`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'password-in-code')).toBe(false);
    });

    it('does NOT flag a documented placeholder api key', () => {
      fs.writeFileSync(testFilePath, `api_key = "your_api_key_goes_here_xxxx"`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'api-key-generic')).toBe(false);
    });

    it('STILL flags a real-looking password assignment (recall preserved)', () => {
      fs.writeFileSync(testFilePath, `const password = "Zk9Qp2Lm7Rt4Wx8Bn1";`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'password-in-code')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Connection-string suppression (local / dev / example / placeholder DSNs)
  // ---------------------------------------------------------------------------

  describe('connection-string suppression', () => {
    const cases: Array<[string, string]> = [
      ['localhost host', 'postgres://prisma:prisma@localhost:5432/tests'],
      ['default root:root creds', 'mysql://root:root@localhost:3306/tests'],
      ['docker-compose service host', 'mysql://root:root@mysql/tests'],
      ['literal user:pass placeholder', 'postgres://user:pass@localhost:5432/db'],
      ['uppercase USER:PASSWORD template', 'mysql://USER:PASSWORD@aws.connect.psdb.cloud/DATABASE'],
      ['env-var interpolation password', 'postgres://app:${DB_PASSWORD}@db.prod.example-corp.com/main'],
      ['.local reserved TLD', 'postgresql://svc:s3cr3t@cache.local:5432/app'],
    ];

    it.each(cases)('does NOT flag %s', (_label, url) => {
      fs.writeFileSync(testFilePath, `const url = "${url}";`);
      const matches = scanner.scan(testFilePath);
      const dsn = matches.filter(m =>
        ['postgresql-url', 'mysql-url', 'mongodb-url', 'redis-url'].includes(m.type),
      );
      expect(dsn).toHaveLength(0);
    });

    it('STILL flags a real remote DSN with a real password (recall preserved)', () => {
      fs.writeFileSync(
        testFilePath,
        `const url = "postgresql://svc_app:Xj8kP2mQ9zRv@db.prod.acme-corp.com:5432/main";`,
      );
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'postgresql-url')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Sample JWT suppression (the ubiquitous jwt.io "John Doe" token)
  // ---------------------------------------------------------------------------

  describe('sample JWT suppression', () => {
    it('does NOT flag the canonical jwt.io sample token', () => {
      const sample =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
        '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
        '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
      fs.writeFileSync(testFilePath, `const t = "${sample}";`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'jwt-token')).toBe(false);
    });

    it('STILL flags a non-sample JWT (recall preserved)', () => {
      const real =
        'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdmNfYXBwIiwicm9sZSI6ImFkbWluIn0.Zx9Kp2Lm7Rt4Wx8Bn1Qj5Vc3Df6Gh0';
      fs.writeFileSync(testFilePath, `const t = "${real}";`);
      const matches = scanner.scan(testFilePath);
      expect(matches.some(m => m.type === 'jwt-token')).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // Path-aware severity (credential-shaped strings in test/fixture paths)
  // ---------------------------------------------------------------------------

  describe('path-aware severity', () => {
    it('downgrades a real remote DSN to low when the file is a test fixture', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pathsev-'));
      const testFile = path.join(dir, 'db.test.ts');
      try {
        fs.writeFileSync(
          testFile,
          `const url = "postgresql://svc_app:Xj8kP2mQ9zRv@db.prod.acme-corp.com:5432/main";`,
        );
        const matches = scanner.scan(testFile);
        const dsn = matches.find(m => m.type === 'postgresql-url');
        expect(dsn).toBeDefined();
        expect(dsn?.severity).toBe('low');
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });

    it('keeps full severity for the same DSN in a non-test path', () => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-pathsev-'));
      const srcFile = path.join(dir, 'database.ts');
      try {
        fs.writeFileSync(
          srcFile,
          `const url = "postgresql://svc_app:Xj8kP2mQ9zRv@db.prod.acme-corp.com:5432/main";`,
        );
        const matches = scanner.scan(srcFile);
        const dsn = matches.find(m => m.type === 'postgresql-url');
        expect(dsn?.severity).toBe('critical');
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // ---------------------------------------------------------------------------
  // Inline ignore directives
  // ---------------------------------------------------------------------------

  describe('inline ignore directives', () => {
    it('respects vault-guard: ignore-line on the secret line', () => {
      fs.writeFileSync(
        testFilePath,
        `const k = "sk-ant-api03-verylongkeyhere12345"; // vault-guard: ignore-line`,
      );
      expect(scanner.scan(testFilePath)).toHaveLength(0);
    });

    it('respects vault-guard: ignore-next-line on the preceding line', () => {
      fs.writeFileSync(
        testFilePath,
        `// vault-guard: ignore-next-line\nconst k = "sk-ant-api03-verylongkeyhere12345";`,
      );
      expect(scanner.scan(testFilePath)).toHaveLength(0);
    });

    it('still catches secrets on other lines when only one is suppressed', () => {
      const content = [
        `// vault-guard: ignore-next-line`,
        `const k1 = "sk-ant-api03-verylongkeyhere12345";`,
        `const k2 = "AKIA1234567890123456";`,
      ].join('\n');
      fs.writeFileSync(testFilePath, content);

      const matches = scanner.scan(testFilePath);
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('aws-access');
    });
  });

  // ---------------------------------------------------------------------------
  // matchLength field
  // ---------------------------------------------------------------------------

  describe('matchLength', () => {
    it('includes matchLength on each match', () => {
      fs.writeFileSync(testFilePath, `const k = "AKIA1234567890123456";`);
      const matches = scanner.scan(testFilePath);
      expect(matches[0].matchLength).toBeGreaterThan(0);
    });
  });

  describe('scanContent', () => {
    it('matches inline buffer same as file scan', () => {
      const text = `const k = "AKIA1234567890123456";`;
      const fromFile = (() => {
        fs.writeFileSync(testFilePath, text);
        return scanner.scan(testFilePath);
      })();
      const fromContent = scanner.scanContent(text);
      expect(fromContent.map(m => m.type)).toEqual(fromFile.map(m => m.type));
    });
  });
});
