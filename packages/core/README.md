# @vaultcompass/vault-guard-core

The scanning engine behind [Vault Guard](https://github.com/vaultcompasshq/vault-guard), as a library: vendor-anchored patterns, entropy gating, baselines, and SARIF/JSON output, with no CLI to shell out to. For building your own CI checks, editor plugins, or security tooling.

## Install

```bash
npm install @vaultcompass/vault-guard-core
```

Requires **Node.js 22+**.

## Quickstart

**Scan a file for secrets**

```typescript
import { SecretScanner } from '@vaultcompass/vault-guard-core';

const scanner = new SecretScanner();
const matches = scanner.scan('/path/to/file.ts');

for (const m of matches) {
  console.log(m.type, m.severity, `line ${m.line}`);
}
```

**Load repo config**

```typescript
import { loadConfig } from '@vaultcompass/vault-guard-core';

const config = loadConfig('/path/to/repo');
const scanner = new SecretScanner(config);
```

**Format results as JSON or SARIF**

```typescript
import {
  SecretScanner,
  formatJson,
  formatSarif,
} from '@vaultcompass/vault-guard-core';

const scanner = new SecretScanner();
const results = [{ file: 'src/api.ts', matches: scanner.scan('src/api.ts') }];

const json = formatJson(results);
const sarif = formatSarif(results, { cwd: process.cwd() });
```

## What it detects

Built-in patterns cover AI/ML API keys (Anthropic, OpenAI, HuggingFace), cloud credentials (AWS, GCP, Azure), payment processors (Stripe, PayPal), database URLs, VCS tokens, SSH private keys, JWTs, and entropy-gated generic assignments.

Full rule reference: [docs/RULES.md](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/RULES.md)

## Main exports

| Export | Description |
|--------|-------------|
| `SecretScanner` | Scan files and text for secrets |
| `TokenCounter` | Rough on-disk token estimates |
| `PreCommitHook` | Install pre-commit hooks (native, Husky, Lefthook) |
| `loadConfig` / `validateVaultGuardConfig` | `.vault-guard.json` loading and validation |
| `formatJson` / `formatSarif` | Structured output for CI and GitHub Code Scanning |
| `fingerprintForMatch` | Baseline fingerprinting (no raw secrets stored) |
| `scanTextFileAsync` / `scanTextFileSync` | Stream-aware file scanning |
| `getGitStagedFilePaths` | Staged-file enumeration for hooks |

## Prefer the CLI?

Most users should install the full CLI instead:

```bash
npm install -g @vaultcompass/vault-guard
```

This package is for building integrations (MCP servers, CI plugins, custom tooling) on top of the same engine.

## Documentation

- [GitHub repository](https://github.com/vaultcompasshq/vault-guard)
- [Configuration schema](https://github.com/vaultcompasshq/vault-guard/blob/main/schemas/vault-guard-config.json)
- [Product scope & JSON output](https://github.com/vaultcompasshq/vault-guard/blob/main/docs/PRODUCT_SCOPE.md)

## License

MIT. [Vault & Compass LLC](https://vaultcompass.io)
