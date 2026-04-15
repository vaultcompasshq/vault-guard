import { SecretScanner } from '@vaultcompass/vault-guard-core';
import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

describe('Pre-commit Hook Integration', () => {
  const testDir = path.join(process.cwd(), 'tmp-test-integration');
  const testFile = path.join(testDir, 'test-secret.ts');

  beforeAll(() => {
    // Create test directory
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up test file
    if (fs.existsSync(testFile)) {
      fs.unlinkSync(testFile);
    }
  });

  afterAll(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmdirSync(testDir);
    }
  });

  it('should detect secrets in test file', () => {
    // Create test file with secret
    fs.writeFileSync(testFile, "const apiKey = 'sk-ant-api123-test-key-for-testing';");

    const scanner = new SecretScanner();
    const matches = scanner.scan(testFile);

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].type).toBe('anthropic');
    expect(matches[0].severity).toBe('critical');
  });

  it('should mask secret values in output', () => {
    // Create test file with secret
    fs.writeFileSync(testFile, "const apiKey = 'sk-ant-api1234567890123456789012';");

    const scanner = new SecretScanner();
    const matches = scanner.scan(testFile);

    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].value).toMatch(/^sk-ant-api12\.\.\.$/); // Should be masked
    expect(matches[0].value).not.toContain('sk-ant-api1234567890123456789012'); // Should not contain full secret
  });

  it('should return empty array when no secrets found', () => {
    // Create test file without secrets
    fs.writeFileSync(testFile, "const message = 'hello world';");

    const scanner = new SecretScanner();
    const matches = scanner.scan(testFile);

    expect(matches).toEqual([]);
  });

  it('should handle multiple secrets in same file', () => {
    // Create test file with multiple secrets
    fs.writeFileSync(testFile, `
      const anthropicKey = 'sk-ant-api123';
      const openaiKey = 'sk-12345678901234567890123456789012345678901234';
      const stripeKey = 'sk_test_fakekey1234567890123456';
    `);

    const scanner = new SecretScanner();
    const matches = scanner.scan(testFile);

    expect(matches.length).toBeGreaterThanOrEqual(3);
  });
});
