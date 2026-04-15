import { TokenCounter } from '../token-counter';
import fs from 'fs';
import path from 'path';

describe('TokenCounter', () => {
  let tokenCounter: TokenCounter;
  let testDir: string;
  let testFile: string;

  beforeEach(() => {
    tokenCounter = new TokenCounter();
    testDir = path.join(process.cwd(), 'tmp-test-token-counter');
    testFile = path.join(testDir, 'test.ts');

    // Create test directory
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  describe('estimateTokens', () => {
    it('should return 0 for empty string', () => {
      const result = tokenCounter.estimateTokens('');
      expect(result).toBe(0);
    });

    it('should return 0 for undefined input', () => {
      const result = tokenCounter.estimateTokens(undefined as unknown as string);
      expect(result).toBe(0);
    });

    it('should estimate tokens for natural language text', () => {
      const text = 'This is a simple test with some words in it.';
      const result = tokenCounter.estimateTokens(text);
      expect(result).toBeGreaterThan(0);
      expect(result).toBeLessThan(20); // Should be reasonable
    });

    it('should estimate tokens for code with symbols', () => {
      const code = `
        function test() {
          const x = { a: 1, b: 2 };
          return x.a + x.b;
        }
      `;
      const result = tokenCounter.estimateTokens(code);
      expect(result).toBeGreaterThan(0);
      // Code should have higher token count due to symbols
      expect(result).toBeGreaterThan(10);
    });

    it('should handle code-like content with high symbol density', () => {
      const code = '{}[]();,:.<>+-*/%=|^&!~?';
      const result = tokenCounter.estimateTokens(code);
      expect(result).toBeGreaterThan(0);
    });

    it('should apply code density multiplier for symbol-heavy content', () => {
      const naturalText = 'the quick brown fox jumps over the lazy dog';
      const codeText = 'const { foo, bar } = baz;';

      const naturalTokens = tokenCounter.estimateTokens(naturalText);
      const codeTokens = tokenCounter.estimateTokens(codeText);

      // Code with same character count should have higher estimate
      expect(codeTokens).toBeGreaterThan(naturalTokens);
    });

    it('should ensure minimum estimate based on character length', () => {
      const shortText = 'hi';
      const result = tokenCounter.estimateTokens(shortText);
      expect(result).toBeGreaterThan(0);
    });
  });

  describe('countTokensInFile', () => {
    it('should return 0 for non-existent file', () => {
      const result = tokenCounter.countTokensInFile('/non/existent/file.ts');
      expect(result).toBe(0);
    });

    it('should count tokens in existing file', () => {
      const content = 'function test() { return 42; }';
      fs.writeFileSync(testFile, content, 'utf-8');

      const result = tokenCounter.countTokensInFile(testFile);
      expect(result).toBeGreaterThan(0);
    });

    it('should handle empty file', () => {
      fs.writeFileSync(testFile, '', 'utf-8');

      const result = tokenCounter.countTokensInFile(testFile);
      expect(result).toBe(0);
    });

    it('should handle large file', () => {
      const largeContent = 'function test() { return 42; }'.repeat(1000);
      fs.writeFileSync(testFile, largeContent, 'utf-8');

      const result = tokenCounter.countTokensInFile(testFile);
      expect(result).toBeGreaterThan(1000);
    });
  });

  describe('calculateCost', () => {
    it('should calculate cost for Anthropic', () => {
      const inputTokens = 1_000_000;
      const outputTokens = 500_000;

      const result = tokenCounter.calculateCost('anthropic', inputTokens, outputTokens);

      // Expected: (1M * $3) + (0.5M * $15) = $3 + $7.5 = $10.5
      expect(result).toBeCloseTo(10.5, 1);
    });

    it('should calculate cost for OpenAI', () => {
      const inputTokens = 1_000_000;
      const outputTokens = 500_000;

      const result = tokenCounter.calculateCost('openai', inputTokens, outputTokens);

      // Expected: (1M * $5) + (0.5M * $15) = $5 + $7.5 = $12.5
      expect(result).toBeCloseTo(12.5, 1);
    });

    it('should handle zero tokens', () => {
      const result = tokenCounter.calculateCost('anthropic', 0, 0);
      expect(result).toBe(0);
    });

    it('should handle only input tokens', () => {
      const result = tokenCounter.calculateCost('anthropic', 1_000_000, 0);
      expect(result).toBeCloseTo(3.0, 1);
    });

    it('should handle only output tokens', () => {
      const result = tokenCounter.calculateCost('anthropic', 0, 1_000_000);
      expect(result).toBeCloseTo(15.0, 1);
    });
  });

  describe('generateReport', () => {
    it('should generate report for directory with files', () => {
      // Create test files
      const tsFile = path.join(testDir, 'test.ts');
      const jsFile = path.join(testDir, 'test.js');
      const txtFile = path.join(testDir, 'test.txt');

      fs.writeFileSync(tsFile, 'function test() { return 42; }', 'utf-8');
      fs.writeFileSync(jsFile, 'const x = 1;', 'utf-8');
      fs.writeFileSync(txtFile, 'Some text content', 'utf-8');

      const report = tokenCounter.generateReport(testDir);

      expect(report.totalTokens).toBeGreaterThan(0);
      expect(report.estimatedCost).toBeGreaterThan(0);
      expect(report.breakdown['.ts']).toBeDefined();
      expect(report.breakdown['.js']).toBeDefined();
      expect(report.breakdown['.txt']).toBeDefined();
    });

    it('should handle empty directory', () => {
      const report = tokenCounter.generateReport(testDir);

      expect(report.totalTokens).toBe(0);
      expect(report.estimatedCost).toBe(0);
      expect(Object.keys(report.breakdown).length).toBe(0);
    });

    it('should ignore node_modules directory', () => {
      const nodeModulesDir = path.join(testDir, 'node_modules');
      const testFile = path.join(nodeModulesDir, 'package.json');

      fs.mkdirSync(nodeModulesDir, { recursive: true });
      fs.writeFileSync(testFile, '{"name": "test"}', 'utf-8');

      const report = tokenCounter.generateReport(testDir);

      // Should not count files in node_modules
      expect(report.totalTokens).toBe(0);
    });

    it('should ignore common binary and build files', () => {
      const pngFile = path.join(testDir, 'test.png');
      const distDir = path.join(testDir, 'dist');
      const jsFile = path.join(distDir, 'bundle.js');

      fs.writeFileSync(pngFile, 'fake image content', 'utf-8');
      fs.mkdirSync(distDir, { recursive: true });
      fs.writeFileSync(jsFile, 'console.log("test");', 'utf-8');

      const report = tokenCounter.generateReport(testDir);

      // Should not count PNG or files in dist
      expect(report.totalTokens).toBe(0);
    });

    it('should aggregate tokens by file extension', () => {
      const tsFile1 = path.join(testDir, 'file1.ts');
      const tsFile2 = path.join(testDir, 'file2.ts');
      const jsFile = path.join(testDir, 'file.js');

      fs.writeFileSync(tsFile1, 'const x = 1;', 'utf-8');
      fs.writeFileSync(tsFile2, 'const y = 2;', 'utf-8');
      fs.writeFileSync(jsFile, 'const z = 3;', 'utf-8');

      const report = tokenCounter.generateReport(testDir);

      expect(report.breakdown['.ts']).toBeGreaterThan(0);
      expect(report.breakdown['.js']).toBeGreaterThan(0);
      // .ts should have more tokens (2 files vs 1 file)
      expect(report.breakdown['.ts']).toBeGreaterThan(report.breakdown['.js']);
    });

    it('should handle files without extension', () => {
      const noExtFile = path.join(testDir, 'Makefile');
      fs.writeFileSync(noExtFile, 'build:\n\techo "building"', 'utf-8');

      const report = tokenCounter.generateReport(testDir);

      expect(report.totalTokens).toBeGreaterThan(0);
      expect(report.breakdown['(no ext)']).toBeGreaterThan(0);
    });
  });

  describe('edge cases', () => {
    it('should handle very long strings', () => {
      const longString = 'a'.repeat(1_000_000);
      const result = tokenCounter.estimateTokens(longString);
      expect(result).toBeGreaterThan(0);
    });

    it('should handle special characters', () => {
      const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      const result = tokenCounter.estimateTokens(specialChars);
      expect(result).toBeGreaterThan(0);
    });

    it('should handle mixed content', () => {
      const mixed = `
        // This is a comment
        function calculate(x: number, y: number): number {
          return x + y;
        }
        Some text here too!
      `;
      const result = tokenCounter.estimateTokens(mixed);
      expect(result).toBeGreaterThan(0);
    });
  });
});
