# Built-in secret patterns

Generated from `BUILTIN_PATTERNS` in `packages/core/src/scanners/secret-scanner.ts`.
Run `pnpm build && node scripts/gen-rules-doc.cjs` after touching that map.
Do not hand-edit this file; CI rejects drift (see `.github/workflows/ci.yml`).

## Pattern selection

The built-in set is deliberately narrow. Each entry either matches a structured token shape (`sk-`, `AKIA…`, `xox[baprs]-…`, `gh[pousor]_…`) or anchors a generic shape to a keyword context (`api_key=`, `password=`, `Bearer …`).

Unanchored generic patterns (raw 32-char hex, MD5/SHA1 shapes, base64 blobs) are intentionally absent; they generate too many false positives on legitimate hashes, hex colors, and asset fingerprints to be useful as a default.

## Entropy gate

Patterns with a `Min entropy` value drop matches whose Shannon entropy falls below the threshold. This is what stops `password = "password123"` from being flagged as a `password-in-code` hit, and what keeps `api_key = "REPLACE_ME_BEFORE_PROD"` from setting off `api-key-generic`. Patterns without an entropy threshold are structured enough that the regex itself is the gate.

## Patterns

| ID | Severity | Min entropy | Regex flags | Regex source |
| --- | --- | --- | --- | --- |
| `anthropic` | critical | - | `g` | `sk-ant-[a-zA-Z0-9_-]{20,}` |
| `openai-project` | critical | - | `g` | `sk-proj-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}` |
| `openai-svcacct` | critical | - | `g` | `sk-svcacct-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}` |
| `openai-admin` | critical | - | `g` | `sk-admin-[A-Za-z0-9_-]{20,100}T3BlbkFJ[A-Za-z0-9_-]{20,100}` |
| `openai` | critical | - | `g` | `(?<![A-Za-z0-9_-])sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20,}` |
| `huggingface` | critical | - | `g` | `hf_[a-zA-Z0-9]{34,}` |
| `replicate` | critical | - | `g` | `r8_[a-zA-Z0-9]{32}` |
| `stripe` | critical | - | `g` | `sk_live_[a-zA-Z0-9]{24,}` |
| `stripe-test` | high | - | `g` | `sk_test_[a-zA-Z0-9]{24,}` |
| `paypal` | critical | - | `g` | `access_token\\$production\\$[a-zA-Z0-9]{20,}` |
| `aws-access` | critical | - | `g` | `AKIA[0-9A-Z]{16}` |
| `aws-secret-context` | critical | - | `gi` | `(?:aws_secret_access_key\|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*["']?([a-zA-Z0-9/+]{40})` |
| `gcp-service-account` | critical | - | `g` | `"type":\\s*"service_account"` |
| `gcp-api-key` | critical | - | `g` | `AIza[a-zA-Z0-9_-]{35}` |
| `gcp-oauth` | low | - | `g` | `[0-9]+-[a-zA-Z0-9_]{32}\\.apps\\.googleusercontent\\.com` |
| `azure-storage` | critical | - | `g` | `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}` |
| `postgresql-url` | critical | - | `g` | `postgres(?:ql)?:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)?\\/\\S+` |
| `mysql-url` | critical | - | `g` | `mysql:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)?\\/\\S+` |
| `mongodb-url` | critical | - | `g` | `mongodb(?:\\+srv)?:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)?` |
| `redis-url` | critical | - | `g` | `rediss?:\\/\\/[^:@\\s]+:[^@\\s]+@[^:\\s/]+(?::\\d+)` |
| `github-token` | critical | - | `g` | `gh[pousor]_[a-zA-Z0-9]{36}` |
| `github-pat` | critical | - | `g` | `github_pat_[a-zA-Z0-9_]{82}` |
| `gitlab-token` | critical | - | `g` | `glpat-[a-zA-Z0-9_-]{20}` |
| `bitbucket-token` | critical | - | `g` | `BBDC-[a-zA-Z0-9_-]{40}` |
| `slack-webhook` | critical | - | `g` | `hooks\\.slack\\.com\\/services\\/[A-Z0-9]{9,}\\/[A-Z0-9]{9,}\\/[a-zA-Z0-9]{20,}` |
| `slack-token` | critical | - | `g` | `xox[baprs]-[a-zA-Z0-9-]{10,}` |
| `discord-webhook` | critical | - | `g` | `discord\\.com\\/api\\/webhooks\\/[0-9]{17,20}\\/[a-zA-Z0-9_-]{60,}` |
| `sendgrid-api` | critical | - | `g` | `SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}` |
| `resend-api` | critical | 3.5 | `g` | `(?<![A-Za-z0-9_])re_[a-zA-Z0-9]{32,}` |
| `mailgun-api` | critical | 3.5 | `g` | `key-[a-zA-Z0-9]{32}` |
| `npm-token` | critical | - | `g` | `npm_[a-zA-Z0-9]{36}` |
| `newrelic-api` | critical | - | `g` | `NRAK-[a-zA-Z0-9]{26}` |
| `shopify-admin` | critical | - | `g` | `shp(?:ss\|at\|ca)_[a-zA-Z0-9]{32}` |
| `ssh-private-key` | critical | - | `g` | `-----BEGIN [A-Z ]+ PRIVATE KEY-----` |
| `jwt-token` | high | - | `g` | `eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+` |
| `bearer-token` | high | 3.5 | `g` | `Bearer [a-zA-Z0-9_-]{20,}` |
| `api-key-generic` | high | 3.5 | `gi` | `api[_-]?key["']?\\s*[:=]\\s*["']?([a-zA-Z0-9_-]{20,})` |
| `secret-generic` | high | 3.5 | `gi` | `secret["']?\\s*[:=]\\s*["']?([a-zA-Z0-9_-]{20,})` |
| `password-in-code` | high | 3.2 | `gi` | `(?<![a-zA-Z0-9_-])password["']?\\s*[:=]\\s*["']([a-zA-Z0-9_\\-!@#$%^&*]{12,})` |
