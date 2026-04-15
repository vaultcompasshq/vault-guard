# Contributing

## Setup

```bash
git clone https://github.com/vaultcompasshq/vault-guard.git
cd vault-guard
pnpm install
pnpm build
pnpm test
```

**Requirements:**
- Node.js >= 18.0.0
- pnpm >= 8.0.0

## Project Structure

```
packages/
├── core/          # Secret scanning, token counting
│   └── src/
│       ├── scanners/
│       ├── types.ts
│       └── utils/
└── cli/           # CLI interface
    └── src/
        ├── commands/
        └── utils/
```

## Development

Run tests: `pnpm test`
Lint: `pnpm lint`
Build: `pnpm build`

## Adding New Secret Patterns

Edit `packages/core/src/scanners/secret-scanner.ts`:

```typescript
['service-name', { regex: /pattern/g, severity: 'critical' }]
```

## Commit Format

```
type(scope): description

feat(core): add Stripe key detection
fix(cli): handle missing directory
docs: update README
```

## Testing

Write tests in `__tests__/` directories next to source files.

```typescript
describe('Feature', () => {
  it('should do something', () => {
    expect(result).toBe(expected);
  });
});
```

Current test coverage: 78 passing tests

## PR Process

1. Fork & branch
2. Make changes
3. Ensure tests pass
4. Submit PR

Keep PRs focused. Include tests for new features.
