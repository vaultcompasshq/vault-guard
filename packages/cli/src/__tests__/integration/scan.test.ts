import * as fs from 'fs';
import * as path from 'path';
import { SecretScanner, getAllFiles } from '@vaultcompass/vault-guard-core';

describe('Scan Command Integration', () => {
  const testDir = path.join(process.cwd(), 'tmp-test-scan');
  const testFile = path.join(testDir, 'clean.ts');
  const secretFile = path.join(testDir, 'secret.ts');

  beforeAll(() => {
    // Create test directory
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    // Create test file without secrets
    fs.writeFileSync(testFile, "const message = 'hello world';");

    // Create test file with secrets
    fs.writeFileSync(secretFile, "const apiKey = 'sk-ant-api1234567890123456789012';");
  });

  afterAll(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.unlinkSync(testFile);
      fs.unlinkSync(secretFile);
      fs.rmdirSync(testDir);
    }
  });

  describe('Single File Scanning', () => {
    it('should scan single file without errors', () => {
      const scanner = new SecretScanner();

      expect(() => {
        scanner.scan(testFile);
      }).not.toThrow();
    });

    it('should find no secrets in clean file', () => {
      const scanner = new SecretScanner();
      const matches = scanner.scan(testFile);

      expect(matches).toEqual([]);
    });

    it('should find secrets in file with secrets', () => {
      const scanner = new SecretScanner();
      const matches = scanner.scan(secretFile);

      expect(matches.length).toBeGreaterThan(0);
      expect(matches[0].type).toBe('anthropic');
    });
  });

  describe('Directory Scanning', () => {
    it('should get all files from directory', () => {
      const files = getAllFiles(testDir);

      expect(files.length).toBe(2);
      expect(files).toContain(testFile);
      expect(files).toContain(secretFile);
    });

    it('should scan all files in directory', () => {
      const scanner = new SecretScanner();
      const files = getAllFiles(testDir);
      let results = 0;

      for (const file of files) {
        const matches = scanner.scan(file);
        if (matches.length > 0) {
          results++;
        }
      }

      expect(results).toBe(1); // Only secretFile has secrets
    });

    it('should handle empty directory', () => {
      const emptyDir = path.join(process.cwd(), 'tmp-test-empty');

      try {
        fs.mkdirSync(emptyDir);
        const files = getAllFiles(emptyDir);

        expect(files).toEqual([]);
      } finally {
        fs.rmdirSync(emptyDir);
      }
    });
  });

  describe('Edge Cases', () => {
    it('should handle non-existent file gracefully', () => {
      const scanner = new SecretScanner();
      const nonExistentFile = path.join(testDir, 'does-not-exist.ts');

      expect(() => {
        scanner.scan(nonExistentFile);
      }).not.toThrow();
    });

    it('should handle non-existent directory gracefully', () => {
      expect(() => {
        getAllFiles(path.join(testDir, 'does-not-exist'));
      }).not.toThrow();
    });

    it('should return empty results for non-existent file', () => {
      const scanner = new SecretScanner();
      const nonExistentFile = path.join(testDir, 'does-not-exist.ts');
      const matches = scanner.scan(nonExistentFile);

      expect(matches).toEqual([]);
    });
  });
});
