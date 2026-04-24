import { SecretScanner } from '../secret-scanner';
import fs from 'fs';
import path from 'path';

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

    it('detects PostgreSQL connection URL', () => {
      fs.writeFileSync(testFilePath, `const url = "postgresql://user:hunter2@db.local:5432/prod";`);
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

    it('returns empty array for clean file', () => {
      fs.writeFileSync(testFilePath, `const msg = "Hello, world!";`);
      expect(scanner.scan(testFilePath)).toHaveLength(0);
    });

    it('returns empty array for non-existent file', () => {
      expect(scanner.scan('/does/not/exist.ts')).toHaveLength(0);
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
