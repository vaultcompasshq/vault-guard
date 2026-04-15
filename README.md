# Vault Guard

Security and optimization layer for AI-native coding. Stop committing secrets, track token usage, and code safer with AI tools.

## Install

```bash
npm install -g @vaultcompass/vault-guard
```

## Usage

### Scan for secrets

```bash
vault-guard scan .
```

Scans your codebase for API keys, tokens, and other secrets. Blocks commits if found.

### Install pre-commit hook

```bash
vault-guard install-hook
```

Automatically scan before every commit. Never commit a secret again.

### Check token usage

```bash
vault-guard tokens
```

See how many tokens you're using and estimate costs.

### Quick check

```bash
vault-guard check src/api.ts
```

Check specific files for secrets.

## What it detects

- AI/ML API keys (Anthropic, OpenAI, Cohere, HuggingFace)
- Payment processors (Stripe, PayPal)
- Cloud providers (AWS, GCP, Azure)
- Database URLs (PostgreSQL, MongoDB, Redis)
- Version control tokens (GitHub, GitLab, Bitbucket)
- Communication (Slack, Discord webhooks)
- SSH keys, JWT tokens, passwords

## Development

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install
pnpm build
pnpm test
```

## License

MIT

---

Vault Guard is built and maintained by [Vault & Compass](https://vaultcompass.io)
