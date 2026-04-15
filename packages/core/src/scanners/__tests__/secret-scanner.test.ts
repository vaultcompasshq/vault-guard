import { SecretScanner } from '../secret-scanner';
import { SecretMatch } from '../../types';
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
    if (fs.existsSync(testFilePath)) {
      fs.unlinkSync(testFilePath);
    }
  });

  describe('scan', () => {
    it('should detect Anthropic API key', () => {
      // Arrange
      const content = `
const apiKey = "sk-ant-api03-1234567890abcdefg";
console.log(apiKey);
`;
      fs.writeFileSync(testFilePath, content);

      // Act
      const matches = scanner.scan(testFilePath);

      // Assert
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('anthropic');
      expect(matches[0].line).toBe(2);
      expect(matches[0].value).toMatch(/^sk-ant-api03\.\.\.$/);  // Exact match for our mask
      expect(matches[0].severity).toBe('critical');
    });

    it('should detect Stripe API key', () => {
      // Arrange
      const content = `
const stripeKey = "sk_test_fake1234567890abcdefghijklmnop";
`;
      fs.writeFileSync(testFilePath, content);

      // Act
      const matches = scanner.scan(testFilePath);

      // Assert
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('stripe');
      expect(matches[0].severity).toBe('critical');
    });

    it('should detect AWS access key', () => {
      // Arrange
      const content = `
const awsKey = "AKIA1234567890123456";
`;
      fs.writeFileSync(testFilePath, content);

      // Act
      const matches = scanner.scan(testFilePath);

      // Assert
      expect(matches).toHaveLength(1);
      expect(matches[0].type).toBe('aws-access');
      expect(matches[0].severity).toBe('critical');
    });

    it('should return empty array when no secrets found', () => {
      // Arrange
      const content = `
const message = "Hello, world!";
console.log(message);
`;
      fs.writeFileSync(testFilePath, content);

      // Act
      const matches = scanner.scan(testFilePath);

      // Assert
      expect(matches).toHaveLength(0);
    });

    it('should detect multiple secrets in same file', () => {
      // Arrange
      const content = `
const anthropicKey = "sk-ant-api03-verylongkeyhere12345";
const stripeKey = "sk_test_fakekeyherefortesting123456";
const awsKey = "AKIA1234567890123456";
`;
      fs.writeFileSync(testFilePath, content);

      // Act
      const matches = scanner.scan(testFilePath);

      // Assert
      expect(matches).toHaveLength(3);
      expect(matches[0].type).toBe('anthropic');
      expect(matches[1].type).toBe('stripe');
      expect(matches[2].type).toBe('aws-access');
    });

    it('should mask secret values in output', () => {
      // Arrange
      const content = `
const key = "sk-ant-api03-verylongkeyhere123456789";
`;
      fs.writeFileSync(testFilePath, content);

      // Act
      const matches = scanner.scan(testFilePath);

      // Assert
      expect(matches[0].value).not.toContain('verylongkeyhere123456789');
      expect(matches[0].value).toMatch(/^sk-ant-api03\.\.\.$/);  // Exact match for our mask
    });
  });
});
