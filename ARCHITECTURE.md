# Architecture

## Overview

Vault Guard is a monorepo with two packages:

- **`@vaultcompass/vault-guard-core`**: Scanning engine
- **`@vaultcompass/vault-guard`**: CLI interface

## Core Components

### SecretScanner

Regex-based pattern matching for 75+ service API keys.

```typescript
const scanner = new SecretScanner();
const results = scanner.scan('file.ts');
// Returns: SecretMatch[]
```

**Pattern format:**
```typescript
['service-name', { regex: /pattern/g, severity: 'critical' }]
```

### TokenCounter

Estimates tokens using word + symbol count with density adjustment.

```typescript
const counter = new TokenCounter();
const tokens = counter.estimateTokens('code here');
```

**Algorithm:**
1. Count words (whitespace-separated)
2. Count symbols (brackets, operators)
3. Apply density multiplier (code vs natural language)
4. Ensure minimum estimate

### PreCommitHook

Manages git pre-commit hooks for automated scanning.

```typescript
const hook = new PreCommitHook();
hook.install(); // Returns {success, message}
```

## File Discovery

`getAllFilesAsync()` traverses directories with:

- Symbolic link protection
- `.gitignore` pattern matching (with negation support)
- Binary file filtering
- File size limits (10MB max)

## CLI Architecture

Commands → Scanner → Results → Display

```
scan.ts → scanFilesAsync() → SecretScanner.scan() → chalk output
check.ts → scanFilesAsync() → SecretScanner.scan() → exit code
```

Shared logic in `scan-utils.ts`:
- `scanFilesAsync()` - Async scanning with progress
- `displayScanResults()` - Formatted output
- `getSeverityColor()` - Color mapping

## Data Flow

1. User runs CLI command
2. Command calls shared scan utility
3. Scan utility discovers files (respects .gitignore)
4. For each file: check binary/size → scan content
5. Collect matches → format output → set exit code

## Error Handling

- File access errors: silent skip (continue scanning)
- Invalid paths: log warning, continue
- Scanner errors: propagate to caller
- CLI errors: display message, exit code 1

## Extension Points

**Adding new patterns:** Edit `secret-scanner.ts`
**Adding new commands:** Create in `cli/src/commands/`
**Modifying scanning logic:** Edit `scan-utils.ts`
**New file filters:** Edit `file-utils.ts`

## Dependencies

- `chalk`: Terminal colors
- `commander`: CLI argument parsing
- `jest`: Testing framework
- `typescript`: Type system

No runtime dependencies for core package.