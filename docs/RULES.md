# Built-in secret patterns

Generated from `BUILTIN_PATTERNS` in `packages/core/src/scanners/secret-scanner.ts`.
Run `pnpm build && node scripts/gen-rules-doc.cjs` after touching that map.
Do not hand-edit this file; CI rejects drift (see `.github/workflows/ci.yml`).

## Pattern selection

The built-in set is deliberately narrow. Each entry either matches a structured token shape (`sk-`, `AKIA…`, `xox[baprs]-…`, `gh[pousor]_…`) or anchors a generic shape to a keyword context (`api_key=`, `password=`, `Bearer …`).

Unanchored generic patterns (raw 32-char hex, MD5/SHA1 shapes, base64 blobs) are intentionally absent; they generate too many false positives on legitimate hashes, hex colors, and asset fingerprints to be useful as a default.

## Entropy gate

Patterns with a `Min entropy` value drop matches whose Shannon entropy falls below the threshold. This is what stops `password = "password123"` from being flagged as a `password-in-code` hit, and what keeps `api_key = "REPLACE_ME_BEFORE_PROD"` from setting off `api-key-generic`. Patterns without an entropy threshold are structured enough that the regex itself is the gate.

## Sequential-run gate

Shannon entropy counts how often each character occurs and throws the order away. A strict alphabet run uses every character exactly once, which is the flattest frequency distribution there is, so `api_key = "abcdefghijklmnopqrstuvwxyz0123456789"` scores at the top of the range and walks straight through the entropy gate. No threshold fixes that: order is the signal, and entropy does not look at order.

A separate check runs ahead of the entropy gate and drops any value where at least 75% of the characters sit inside runs of three or more consecutive code points, ascending or descending. That covers `abcdef…`, `zyxwvu…`, and the same short run repeated. A value that is half run and half random scores 50% and survives, because a real credential can contain an incidental run. Values shorter than 12 characters are never checked: at that length coverage says nothing, since a four-character value is trivially "all run".

Unlike the entropy gate this one applies to vendor-anchored patterns too, which have no entropy threshold of their own, and that is where it earns its keep, since `ghp_abcdefghij…` and `AKIAABCDEFGH…` are how a fake key gets typed by hand. It is safe there for the same reason it is useful: a real provider key comes from a random source and cannot be the alphabet. The fixed vendor prefix counts toward the length but is not itself a run, which is why the threshold sits at 75% rather than higher: `AKIA` plus a 16-character run is only 80% covered.

That safety argument holds only for machine-issued credentials. For anything a person types, a run is a WEAK secret rather than a fake one, and suppressing it destroys the finding instead of demoting it. Rules whose value is human-chosen are therefore exempt from this check and are gated by entropy alone: `password-in-code`, and the four connection-string rules (`postgresql-url`, `mysql-url`, `mongodb-url`, `redis-url`), whose secret is the password component of the DSN. `password-in-code` matters most here, because its minimum capture is 12 characters, the same as this check's minimum value length, so an ordinary weak password sat exactly on the boundary.

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
| `groq` | critical | - | `g` | `(?<![A-Za-z0-9_-])gsk_[a-zA-Z0-9]{52}` |
| `openrouter` | critical | - | `g` | `sk-or-v1-[a-f0-9]{64}` |
| `xai` | critical | - | `g` | `(?<![A-Za-z0-9_-])xai-[a-zA-Z0-9]{80}` |
| `perplexity` | critical | - | `g` | `(?<![A-Za-z0-9_-])pplx-[a-zA-Z0-9]{40,}` |
| `mistral` | critical | - | `g` | `(?:mistral_api_key\|MISTRAL_API_KEY)\\s*[=:]\\s*["']?([a-zA-Z0-9]{32})` |
| `together-ai` | critical | - | `g` | `(?:together_api_key\|TOGETHER_API_KEY)\\s*[=:]\\s*["']?([a-f0-9]{64})` |
| `fireworks-ai` | critical | - | `g` | `(?<![A-Za-z0-9_-])fw_[a-zA-Z0-9]{24,}` |
| `langsmith` | critical | - | `g` | `lsv2_(?:pt\|sk)_[a-f0-9]{32}_[a-f0-9]{10}` |
| `deepseek` | critical | - | `g` | `(?:deepseek_api_key\|DEEPSEEK_API_KEY)\\s*[=:]\\s*["']?(sk-[a-f0-9]{32})` |
| `stripe` | critical | - | `g` | `sk_live_[a-zA-Z0-9]{24,}` |
| `stripe-test` | high | - | `g` | `sk_test_[a-zA-Z0-9]{24,}` |
| `paypal` | critical | - | `g` | `access_token\\$production\\$[a-zA-Z0-9]{20,}` |
| `aws-access` | critical | - | `g` | `AKIA[0-9A-Z]{16}` |
| `aws-secret-context` | critical | - | `gi` | `(?:aws_secret_access_key\|AWS_SECRET_ACCESS_KEY)\\s*[=:]\\s*["']?([a-zA-Z0-9/+]{40})` |
| `gcp-service-account` | critical | - | `g` | `"type":\\s*"service_account"` |
| `gcp-api-key` | critical | - | `g` | `AIza[a-zA-Z0-9_-]{35}` |
| `gcp-oauth` | low | - | `g` | `[0-9]{1,64}-[a-zA-Z0-9_]{32}\\.apps\\.googleusercontent\\.com` |
| `azure-storage` | critical | - | `g` | `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{20,}` |
| `postgresql-url` | critical | - | `g` | `postgres(?:ql)?:\\/\\/[^:@\\s]{1,256}:[^@\\s]{1,256}@[^:\\s/]{1,256}(?::\\d{1,8})?\\/\\S{1,1024}` |
| `mysql-url` | critical | - | `g` | `mysql:\\/\\/[^:@\\s]{1,256}:[^@\\s]{1,256}@[^:\\s/]{1,256}(?::\\d{1,8})?\\/\\S{1,1024}` |
| `mongodb-url` | critical | - | `g` | `mongodb(?:\\+srv)?:\\/\\/[^:@\\s]{1,256}:[^@\\s]{1,256}@[^:\\s/]{1,256}(?::\\d{1,8})?` |
| `redis-url` | critical | - | `g` | `rediss?:\\/\\/[^:@\\s]{1,256}:[^@\\s]{1,256}@[^:\\s/]{1,256}(?::\\d{1,8})` |
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
| `supabase-token` | critical | - | `g` | `(?<![A-Za-z0-9_-])sbp_[a-f0-9]{40}` |
| `supabase-secret` | critical | - | `g` | `(?<![A-Za-z0-9_-])sb_secret_[a-zA-Z0-9_-]{20,}` |
| `vercel-blob` | critical | - | `g` | `vercel_blob_rw_[a-zA-Z0-9]{20,}_[a-zA-Z0-9]{20,}` |
| `planetscale` | critical | - | `g` | `pscale_(?:tkn\|pw)_[a-zA-Z0-9_-]{32,}` |
| `doppler-token` | critical | - | `g` | `dp\\.(?:pt\|st\|sa\|scim\|audit)\\.[a-zA-Z0-9]{40,}` |
| `databricks-token` | critical | - | `g` | `(?<![A-Za-z0-9_-])dapi[a-f0-9]{32}` |
| `cloudflare-token` | critical | - | `g` | `(?:cloudflare_api_token\|CLOUDFLARE_API_TOKEN)\\s*[=:]\\s*["']?([a-zA-Z0-9_-]{40})` |
| `notion-token` | critical | - | `g` | `(?<![A-Za-z0-9_-])(?:ntn_[a-zA-Z0-9]{40,}\|secret_[a-zA-Z0-9]{43})` |
| `airtable-pat` | critical | - | `g` | `(?<![A-Za-z0-9_-])pat[a-zA-Z0-9]{14}\\.[a-f0-9]{64}` |
| `figma-token` | critical | - | `g` | `(?<![A-Za-z0-9_-])figd_[a-zA-Z0-9_-]{40,}` |
| `newrelic-api` | critical | - | `g` | `NRAK-[a-zA-Z0-9]{26}` |
| `sentry-dsn` | low | - | `g` | `https:\\/\\/[a-f0-9]{32}@o\\d+\\.ingest\\.(?:[a-z]{2}\\.)?sentry\\.io\\/\\d+` |
| `shopify-admin` | critical | - | `g` | `shp(?:ss\|at\|ca)_[a-zA-Z0-9]{32}` |
| `ssh-private-key` | critical | - | `g` | `-----BEGIN (?:[A-Z0-9]+(?: [A-Z0-9]+)? )?PRIVATE KEY(?: BLOCK)?-----` |
| `jwt-token` | high | - | `g` | `(?<![A-Za-z0-9_-])eyJ[a-zA-Z0-9_-]{1,4096}\\.[a-zA-Z0-9_-]{1,4096}\\.[a-zA-Z0-9_-]{1,4096}` |
| `bearer-token` | high | 3.5 | `g` | `Bearer [a-zA-Z0-9_-]{20,}` |
| `api-key-generic` | high | 3.5 | `gi` | `api[_-]?key["']?\\s*[:=]\\s*["']?([a-zA-Z0-9_-]{20,})` |
| `secret-generic` | high | 3.5 | `gi` | `secret["']?\\s*[:=]\\s*["']?([a-zA-Z0-9_-]{20,})` |
| `password-in-code` | high | 3.2 | `gi` | `(?<![a-zA-Z0-9_-])password["']?\\s*[:=]\\s*["']([a-zA-Z0-9_\\-!@#$%^&*]{12,})` |
