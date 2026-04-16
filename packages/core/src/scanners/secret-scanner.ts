import fs from 'fs';
import { SecretMatch } from '../types';
import { ScanError } from '../errors';

export class SecretScanner {
  private patterns: Map<string, { regex: RegExp; severity: SecretMatch['severity'] }>;

  constructor() {
    this.patterns = new Map([
      // AI/ML API Keys
      ['anthropic', { regex: /sk-ant-[a-zA-Z0-9_-]{20,}/g, severity: 'critical' }],
      ['openai', { regex: /sk-[a-zA-Z0-9]{48}/g, severity: 'critical' }],
      ['cohere', { regex: /[a-zA-Z0-9]{40}\b/g, severity: 'critical' }],
      ['huggingface', { regex: /hf_[a-zA-Z0-9]{34}/g, severity: 'critical' }],
      ['replicate', { regex: /r8_[a-zA-Z0-9]{32}/g, severity: 'critical' }],

      // Payment Processors
      ['stripe', { regex: /sk_live_[a-zA-Z0-9]{24,}/g, severity: 'critical' }],
      ['stripe-test', { regex: /sk_test_[a-zA-Z0-9]{24,}/g, severity: 'high' }],
      ['paypal', { regex: /access_token\$production\$[a-zA-Z0-9]{20,}/g, severity: 'critical' }],

      // Cloud Providers
      ['aws-access', { regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' }],
      ['aws-secret', { regex: /[a-zA-Z0-9/+]{40}\b/g, severity: 'critical' }],
      ['gcp-service-account', { regex: /"type":\s*"service_account"/g, severity: 'critical' }],
      ['gcp-api-key', { regex: /AIza[a-zA-Z0-9_-]{35}/g, severity: 'critical' }],
      ['gcp-oauth', { regex: /[0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com/g, severity: 'critical' }],
      ['azure-storage', { regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/g, severity: 'critical' }],

      // Database URLs
      ['postgresql-url', { regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^\s]+/g, severity: 'critical' }],
      ['mysql-url', { regex: /mysql:\/\/[^:]+:[^@]+@[^:]+:\d+\/[^\s]+/g, severity: 'critical' }],
      ['mongodb-url', { regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[^:]+:\d+/g, severity: 'critical' }],
      ['redis-url', { regex: /redis:\/\/[^:]+:[^@]+@[^:]+:\d+/g, severity: 'critical' }],
      ['elasticsearch-url', { regex: /https?:\/\/[^:]+:[^@]+@[^:]+:\d+/g, severity: 'critical' }],

      // Version Control
      ['github-token', { regex: /gh[pous]_[a-zA-Z0-9]{36}/g, severity: 'critical' }],
      ['gitlab-token', { regex: /glpat-[a-zA-Z0-9_-]{20}/g, severity: 'critical' }],
      ['bitbucket-token', { regex: /BBDC-[a-zA-Z0-9_-]{40}/g, severity: 'critical' }],

      // CI/CD
      ['circleci-token', { regex: /[a-zA-Z0-9_-]{40}/g, severity: 'critical' }],
      ['jenkins-token', { regex: /[a-zA-Z0-9]{32}/g, severity: 'critical' }],

      // Infrastructure
      ['ansible-vault', { regex: /\$ANSIBLE_VAULT;1\.1;AES256\n[a-zA-Z0-9+/=]+/g, severity: 'critical' }],
      ['kubernetes-token', { regex: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, severity: 'critical' }],

      // Communication
      ['slack-webhook', { regex: /hooks\.slack\.com\/services\/[A-Z0-9]{9}\/[A-Z0-9]{9}\/[a-zA-Z0-9]{24}/g, severity: 'critical' }],
      ['slack-token', { regex: /xox[baprs]-[a-zA-Z0-9-]{10,}/g, severity: 'critical' }],
      ['discord-webhook', { regex: /discord\.com\/api\/webhooks\/[0-9]{17,20}\/[a-zA-Z0-9_-]{60,}/g, severity: 'critical' }],

      // Email Services
      ['sendgrid-api', { regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'critical' }],
      ['mailgun-api', { regex: /key-[a-zA-Z0-9]{32}/g, severity: 'critical' }],
      ['twilio-account', { regex: /AC[a-zA-Z0-9]{32}/g, severity: 'critical' }],

      // Monitoring & Analytics
      ['newrelic-api', { regex: /NRAK-[a-zA-Z0-9]{26}/g, severity: 'critical' }],
      ['google-analytics', { regex: /UA-[0-9]+-[0-9]+/g, severity: 'high' }],
      ['google-analytics-4', { regex: /G-[A-Z0-9]{10}/g, severity: 'high' }],

      // Authentication Tokens
      ['jwt-token', { regex: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, severity: 'high' }],
      ['bearer-token', { regex: /Bearer [a-zA-Z0-9_-]{20,}/g, severity: 'high' }],
      ['api-key-generic', { regex: /api[_-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/g, severity: 'high' }],
      ['secret-generic', { regex: /secret["']?\s*[:=]\s*["']?[a-zA-Z0-9_-]{20,}/g, severity: 'high' }],
      ['password-in-code', { regex: /password["']?\s*[:=]\s*["']?[a-zA-Z0-9_-]{8,}/g, severity: 'high' }],

      // SSH Keys
      ['ssh-private-key', { regex: /-----BEGIN [A-Z]+ PRIVATE KEY-----/g, severity: 'critical' }],
      ['ssh-rsa-public', { regex: /ssh-rsa [a-zA-Z0-9/+=]+ .+/g, severity: 'medium' }],
      ['ssh-ed25519-public', { regex: /ssh-ed25519 [a-zA-Z0-9]+ .+/g, severity: 'medium' }],
    ]);
  }

  scan(filePath: string): SecretMatch[] {
    if (!fs.existsSync(filePath)) {
      return [];
    }

    const content = fs.readFileSync(filePath, 'utf-8');

    // Build line index for O(log n) line number lookup
    const lineIndex = this.buildLineIndex(content);

    const matches: SecretMatch[] = [];

    for (const [type, { regex, severity }] of this.patterns) {
      let match;
      // Reset regex state
      regex.lastIndex = 0;

      while ((match = regex.exec(content)) !== null) {
        const line = this.getLineNumberFromIndex(lineIndex, match.index);
        const masked = this.maskValue(match[0], type);

        matches.push({
          type,
          value: masked,
          line,
          column: match.index,
          severity
        });
      }
    }

    return matches;
  }

  /**
   * Build an index of newline positions for efficient line number lookup
   */
  private buildLineIndex(content: string): number[] {
    const lineIndex = [0]; // First line starts at position 0
    for (let i = 0; i < content.length; i++) {
      if (content[i] === '\n') {
        lineIndex.push(i + 1); // Next line starts after newline
      }
    }
    return lineIndex;
  }

  /**
   * Get line number from position using binary search on line index
   */
  private getLineNumberFromIndex(lineIndex: number[], index: number): number {
    let left = 0;
    let right = lineIndex.length - 1;

    while (left <= right) {
      const mid = Math.floor((left + right) / 2);
      if (lineIndex[mid] <= index) {
        left = mid + 1;
      } else {
        right = mid - 1;
      }
    }

    return left;
  }

  private maskValue(value: string, type: string): string {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const _type = type; // Type parameter reserved for future masking strategies
    // Show first 12 chars, then mask with ...
    const prefixLength = 12;
    if (value.length <= prefixLength) {
      // If too short, show first part + ...
      const showLength = Math.max(3, value.length - 3);
      return value.substring(0, showLength) + '...';
    }
    return value.substring(0, prefixLength) + '...';
  }
}
