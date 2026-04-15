import fs from 'fs';
import path from 'path';
import { TokenReport } from '../types';

export class TokenCounter {
  private tokenRates = {
    anthropic: {
      input: 3.0, // $3 per million tokens
      output: 15.0 // $15 per million tokens
    },
    openai: {
      input: 5.0,
      output: 15.0
    }
  };

  /**
   * Count tokens in a file (rough estimation)
   * Real implementation would use tiktoken or similar
   */
  countTokensInFile(filePath: string): number {
    if (!fs.existsSync(filePath)) {
      return 0;
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    return this.estimateTokens(content);
  }

  /**
   * Estimate token count from text with improved accuracy
   * Accounts for code density, symbols, and whitespace
   */
  estimateTokens(text: string): number {
    if (!text || text.length === 0) {
      return 0;
    }

    // Count whitespace-separated words
    const words = text.split(/\s+/).filter(w => w.length > 0);
    const wordCount = words.length;

    // Count symbols and operators (more common in code)
    const symbolMatches = text.match(/[{}[\]();,:.<>+\-*/%=|^&!~?]/g);
    const symbolCount = symbolMatches ? symbolMatches.length : 0;

    // Base estimate: words + symbols (rough approximation)
    let tokenEstimate = wordCount + symbolCount;

    // Adjust for code density (code typically has higher token/word ratio)
    // If text has many symbols relative to words, it's likely code
    const symbolToWordRatio = wordCount > 0 ? symbolCount / wordCount : 0;
    if (symbolToWordRatio > 0.5) {
      // Code-like content: increase estimate
      tokenEstimate = Math.floor(tokenEstimate * 1.3);
    } else if (symbolToWordRatio < 0.1) {
      // Natural language: decrease slightly (words are better tokens)
      tokenEstimate = Math.floor(tokenEstimate * 0.9);
    }

    // Ensure minimum estimate
    return Math.max(tokenEstimate, Math.ceil(text.length / 8));
  }

  /**
   * Calculate cost from token usage
   */
  calculateCost(provider: 'anthropic' | 'openai', inputTokens: number, outputTokens: number): number {
    const rates = this.tokenRates[provider];
    const inputCost = (inputTokens / 1_000_000) * rates.input;
    const outputCost = (outputTokens / 1_000_000) * rates.output;
    return inputCost + outputCost;
  }

  /**
   * Generate token report for a directory
   */
  generateReport(directoryPath: string): TokenReport {
    let totalTokens = 0;
    const breakdown: Record<string, number> = {};

    const files = this.getAllFiles(directoryPath);

    for (const file of files) {
      const tokens = this.countTokensInFile(file);
      if (tokens > 0) {
        const ext = this.getExtension(file);
        breakdown[ext] = (breakdown[ext] || 0) + tokens;
        totalTokens += tokens;
      }
    }

    // Estimate cost (assuming Anthropic)
    const estimatedCost = (totalTokens / 1_000_000) * 3.0;

    return {
      totalTokens,
      estimatedCost,
      breakdown
    };
  }

  private getAllFiles(dirPath: string): string[] {
    const files: string[] = [];
    const items = fs.readdirSync(dirPath);

    for (const item of items) {
      const fullPath = path.join(dirPath, item);
      const stat = fs.statSync(fullPath);

      if (stat.isDirectory() && !this.shouldIgnore(item)) {
        files.push(...this.getAllFiles(fullPath));
      } else if (stat.isFile() && !this.shouldIgnoreFile(fullPath)) {
        files.push(fullPath);
      }
    }

    return files;
  }

  private shouldIgnore(name: string): boolean {
    return ['node_modules', '.git', 'dist', 'build', 'coverage', '.next'].includes(name);
  }

  private shouldIgnoreFile(filePath: string): boolean {
    const ext = this.getExtension(filePath);
    return ['.png', '.jpg', '.jpeg', '.gif', '.pdf', '.zip', '.lock', '.log'].includes(ext);
  }

  private getExtension(filePath: string): string {
    const parts = filePath.split('.');
    return parts.length > 1 ? `.${parts[parts.length - 1]}` : '(no ext)';
  }
}
