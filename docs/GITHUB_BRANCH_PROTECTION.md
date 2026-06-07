# GitHub branch protection & org hygiene

Apply these in **GitHub → Settings → Branches → Branch protection rules** for `main` (and optionally `develop`).

## Recommended rule set

| Rule | Why |
|------|-----|
| **Require a pull request before merging** | Review + CI gate; avoids direct pushes that skip checks. |
| **Required approvals ≥ 1** | Even solo maintainers can use a **bot** or self-PR for audit trail. |
| **Dismiss stale pull request approvals when new commits are pushed** | Ensures CI + diff reviewed for the final SHA. |
| **Require status checks to pass** | Add jobs: `test (22.x)`, `lint`, and `CodeQL` (GHAS PR gate) from `.github/workflows/ci.yml` and code scanning. |
| **Require branches to be up to date before merging** | Prevents green CI on an old base that fails after merge. |
| **Require conversation resolution before merging** | Clears review threads. |
| **Include administrators** | So admins cannot bypass accidentally. |
| **Allow force pushes** | **Off** on `main`. |
| **Allow deletions** | **Off** on `main`. |

## Tag / release protection

- Restrict who can create matching refs `v*` if your org supports **rulesets** (recommended over classic rules for tags).
- Ensure **only** GitHub Actions (or trusted maintainers) can run `release.yml`: it publishes npm via **Trusted Publishing (OIDC)**; each `@vaultcompass/*` package must list workflow `release.yml` on npm. No long-lived `NPM_TOKEN` is required when OIDC is configured.

## Supply chain (already in-repo)

- Dependabot: `.github/dependabot.yml` (npm + GitHub Actions).
- CodeQL: `.github/workflows/codeql.yml` (pinned action SHAs).
- OpenSSF Scorecard: `.github/workflows/scorecard.yml`.
- Third-party Actions in CI/release use **full commit SHAs** where practical.

## Optional: rulesets (GitHub Enterprise / newer repos)

Use **Repository rulesets** to require workflows, block force-push, and require signed commits if your org policy demands it.
