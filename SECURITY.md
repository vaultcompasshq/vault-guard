# Security policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Send details to **security@vaultcompass.io** (or the contact listed on
[vaultcompass.io](https://vaultcompass.io) if that address changes). Include:

- A description of the issue and its impact
- Steps to reproduce (proof-of-concept if possible)
- Affected versions / components (`@vaultcompass/vault-guard` CLI,
  `@vaultcompass/vault-guard-core`, GitHub Action, etc.)

We aim to acknowledge receipt within **5 business days** and coordinate a fix
and disclosure timeline with you.

## Scope

In scope: secret handling bugs in Vault Guard, credential leakage in CI or
documentation, supply-chain issues in official packages and Docker images.

Out of scope: generic regex false positives (report as a normal issue unless
they cause a security boundary failure), third-party dependencies (report to
the upstream maintainer; we still welcome coordinated notification).

## npm provenance

Published `@vaultcompass/*` packages are built from this repository’s tagged
releases with **npm provenance** enabled where configured in CI.

## `vault-guard proxy` (MVP)

The optional local forwarder only targets **`https://api.anthropic.com`** (fixed
hostname — not a generic open proxy). Bind to **`127.0.0.1`** for workstation use;
binding to `0.0.0.0` or a LAN interface exposes the process to others who could
relay traffic through your machine. Request and non-stream response bodies are
capped to avoid accidental memory exhaustion; streaming responses are piped
without buffering the full body.
