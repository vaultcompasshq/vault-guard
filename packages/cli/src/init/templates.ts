/** Stable init template version — bump when file contents change materially. */
export const INIT_TEMPLATE_VERSION = '1';

export const MANIFEST_RELATIVE_PATH = '.vault-guard/manifest.json';

export const MANAGED_FILE_PATHS = [
  '.vault-guard.json',
  '.github/workflows/vault-guard.yml',
  '.vault-guard/mcp-snippet.json',
  '.vault-guard/agent-rules.md',
  MANIFEST_RELATIVE_PATH,
] as const;

export type ManagedFilePath = (typeof MANAGED_FILE_PATHS)[number];

export function defaultVaultGuardConfigJson(): string {
  return `${JSON.stringify(
    {
      ignore: {
        patterns: ['**/__tests__/**', 'fixtures/**', 'bench/fixtures/**'],
      },
    },
    null,
    2,
  )}\n`;
}

export function githubWorkflowYaml(): string {
  return `name: Vault Guard

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: vaultcompasshq/vault-guard@v1.1.2
        with:
          version: latest
          path: .
          format: sarif
          sarif-output: vault-guard-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: vault-guard-results.sarif
`;
}

export function mcpSnippetJson(): string {
  return `${JSON.stringify(
    {
      mcpServers: {
        'vault-guard': {
          command: 'npx',
          args: ['-y', '@vaultcompass/vault-guard-mcp'],
        },
      },
    },
    null,
    2,
  )}\n`;
}

export function agentRulesMarkdown(): string {
  return `# Vault Guard — agent guardrails

Vault Guard is the local secret scanner for this repository. Follow these rules
before writing, editing, or committing code.

## Before applying edits

1. Call the Vault Guard MCP tool \`scan_text\` on any proposed file content that
   may contain credentials (API keys, tokens, connection strings, private keys).
2. If findings are returned, do **not** write the secret material. Redact or
   replace with environment variables / placeholders and scan again.
3. For whole files on disk, use \`scan_file\`. For directories, use
   \`scan_workspace\`.

## Before committing

- Ensure \`vault-guard scan --staged\` passes (pre-commit hook enforces this).
- Never use \`git commit --no-verify\` to bypass secret checks unless the user
  explicitly requests an emergency bypass.

## Merge MCP config (manual)

Copy the \`mcpServers\` block from \`.vault-guard/mcp-snippet.json\` into your
editor MCP config (e.g. \`~/.cursor/mcp.json\` or Claude Desktop config). Vault
Guard does not modify files outside this repository.

## History scanning

Vault Guard does not scan Git history. Use Gitleaks or TruffleHog for retroactive
history mining alongside Vault Guard's working-tree protection.
`;
}

export function templateContentForPath(relativePath: ManagedFilePath): string {
  switch (relativePath) {
    case '.vault-guard.json':
      return defaultVaultGuardConfigJson();
    case '.github/workflows/vault-guard.yml':
      return githubWorkflowYaml();
    case '.vault-guard/mcp-snippet.json':
      return mcpSnippetJson();
    case '.vault-guard/agent-rules.md':
      return agentRulesMarkdown();
    default:
      throw new Error(`No template for ${relativePath}`);
  }
}

export interface InitManifest {
  initVersion: string;
  templateVersion: string;
  createdAt: string;
  hookManager?: string;
  hookPath?: string;
  files: Array<{ path: string; action: 'created' }>;
}

export function buildManifestContent(
  files: Array<{ path: string; action: 'created' }>,
  hook?: { manager: string; path: string },
): string {
  const manifest: InitManifest = {
    initVersion: '1',
    templateVersion: INIT_TEMPLATE_VERSION,
    createdAt: new Date().toISOString(),
    files,
    ...(hook ? { hookManager: hook.manager, hookPath: hook.path } : {}),
  };
  return `${JSON.stringify(manifest, null, 2)}\n`;
}
