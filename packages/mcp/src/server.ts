import path from 'path';
import fs from 'fs';
import { z } from 'zod';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import {
  SecretScanner,
  loadConfig,
  ConfigError,
  TokenCounter,
  formatJson,
  formatSarif,
  type FileScanResult,
  type JsonRunMetadata,
} from '@vaultcompass/vault-guard-core';
import { TelemetryStore, TelemetryUnavailableError } from '@vaultcompass/vault-guard-telemetry';
import { scanWorkspaceDirectory } from './workspace-scan';

// Injected by esbuild (`define`) at build time from package.json. Falls back
// to a dev sentinel under ts-jest / unbundled execution where it is undefined.
declare const __VG_MCP_VERSION__: string | undefined;
const SERVER_VERSION =
  typeof __VG_MCP_VERSION__ !== 'undefined' ? __VG_MCP_VERSION__ : '0.0.0-dev';

export interface McpServerOptions {
  /**
   * Factory for the telemetry store. Injectable for tests; defaults to a real
   * {@link TelemetryStore}. Telemetry is strictly optional: if the factory
   * throws {@link TelemetryUnavailableError} (e.g. missing `better-sqlite3`
   * native bindings under `npx`), the scan tools remain fully functional and
   * only `record_session_event` degrades.
   */
  telemetryFactory?: () => TelemetryStore;
}

/**
 * Build a scanner for the current MCP request.
 *
 * Policy: the MCP server runs as a stdio child of an editor / agent. If the
 * user has a typo in `.vault-guard.json` we must not take the host down —
 * log to stderr (visible in the editor's MCP output channel) and fall back
 * to default config. The CLI surface, by contrast, hard-fails on
 * `ConfigError` because a human is at the terminal to read the message.
 */
function makeScanner(): SecretScanner {
  const cwd = process.cwd();
  let cfg;
  try {
    cfg = loadConfig(cwd);
  } catch (e) {
    if (e instanceof ConfigError) {
      process.stderr.write(
        `vault-guard MCP: ignoring broken config at ${e.filePath} — ${e.message}\n`,
      );
      cfg = {};
    } else {
      throw e;
    }
  }
  return new SecretScanner(cfg);
}

function toolPayload(obj: unknown): { content: Array<{ type: 'text'; text: string }> } {
  return {
    content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }],
  };
}

export function createMcpServer(options: McpServerOptions = {}): McpServer {
  const server = new McpServer(
    { name: 'vault-guard', version: SERVER_VERSION },
    {
      capabilities: {
        tools: {},
      },
      instructions:
        'Vault Guard MCP: scan workspaces/files/text for secrets (SARIF-shaped JSON), report token estimates, and record opt-in session/usage events to local ~/.vault-guard/usage.sqlite.',
    },
  );

  // Telemetry is optional and lazily constructed. The scan tools (the primary
  // value of this server) must never be taken down by a missing/incompatible
  // `better-sqlite3` binding, so we never build the store eagerly and we never
  // let TelemetryUnavailableError escape `record_session_event`.
  const telemetryFactory = options.telemetryFactory ?? ((): TelemetryStore => new TelemetryStore());
  let telemetry: TelemetryStore | null = null;
  let telemetryUnavailable = false;

  function getTelemetry(): TelemetryStore | null {
    if (telemetry) return telemetry;
    if (telemetryUnavailable) return null;
    try {
      telemetry = telemetryFactory();
      return telemetry;
    } catch (e) {
      if (e instanceof TelemetryUnavailableError) {
        telemetryUnavailable = true;
        process.stderr.write(
          `vault-guard MCP: telemetry unavailable; session events will not be recorded: ${e.message}\n`,
        );
        return null;
      }
      throw e;
    }
  }

  const tokenCounter = new TokenCounter();

  server.registerTool(
    'scan_workspace',
    {
      title: 'Scan workspace directory',
      description:
        'Run the Vault Guard secret scanner on a directory (respects .gitignore). Returns JSON, SARIF string, and summary.',
      inputSchema: {
        root: z.string().optional().describe('Directory to scan (default: process.cwd())'),
      },
    },
    async ({ root }) => {
      const scanner = makeScanner();
      const dir = path.resolve(process.cwd(), root ?? '.');
      const t0 = Date.now();
      const { results, filesScanned, bytesScanned } = await scanWorkspaceDirectory(dir, scanner);
      const run: JsonRunMetadata = {
        duration_ms: Date.now() - t0,
        files_scanned: filesScanned,
        bytes_scanned: bytesScanned,
        patterns_active: scanner.getActivePatternCount(),
      };
      return toolPayload({
        summary: {
          files_with_secrets: results.length,
          total_matches: results.reduce((n, r) => n + r.matches.length, 0),
        },
        json: JSON.parse(formatJson(results, { cwd: dir, run })) as unknown,
        sarif: formatSarif(results, { cwd: dir, run }),
        results,
      });
    },
  );

  server.registerTool(
    'scan_file',
    {
      title: 'Scan a single file',
      description: 'Scan one file on disk for secrets. Returns JSON + SARIF.',
      inputSchema: {
        file_path: z.string().describe('Absolute or relative path to a file'),
      },
    },
    async ({ file_path }) => {
      const scanner = makeScanner();
      const fp = path.resolve(process.cwd(), file_path);
      if (!fs.existsSync(fp) || !fs.statSync(fp).isFile()) {
        return toolPayload({ error: 'not_a_file', path: fp });
      }
      const t0 = Date.now();
      const matches = scanner.scan(fp);
      const st = fs.statSync(fp);
      const run: JsonRunMetadata = {
        duration_ms: Date.now() - t0,
        files_scanned: 1,
        bytes_scanned: st.size,
        patterns_active: scanner.getActivePatternCount(),
      };
      const results: FileScanResult[] = matches.length ? [{ file: fp, matches }] : [];
      return toolPayload({
        summary: { files_with_secrets: results.length, total_matches: matches.length },
        json: JSON.parse(formatJson(results, { cwd: process.cwd(), run })) as unknown,
        sarif: formatSarif(results, { cwd: process.cwd(), run }),
      });
    },
  );

  server.registerTool(
    'scan_text',
    {
      title: 'Scan pasted text',
      description:
        'Scan arbitrary UTF-8 text (e.g. proposed AI edit). Optional virtual_path for SARIF artifact URI only.',
      inputSchema: {
        text: z.string().describe('UTF-8 content to scan'),
        virtual_path: z
          .string()
          .optional()
          .describe('Synthetic path label for SARIF (default: inline://snippet)'),
      },
    },
    async ({ text, virtual_path }) => {
      const scanner = makeScanner();
      const t0 = Date.now();
      const matches = scanner.scanContent(text);
      const label = virtual_path ?? 'inline://snippet';
      const results: FileScanResult[] = matches.length ? [{ file: label, matches }] : [];
      const bytes = Buffer.byteLength(text, 'utf8');
      const run: JsonRunMetadata = {
        duration_ms: Date.now() - t0,
        files_scanned: 1,
        bytes_scanned: bytes,
        patterns_active: scanner.getActivePatternCount(),
      };
      return toolPayload({
        summary: { total_matches: matches.length },
        // virtual_path is a label, not a real path; skip relativization to preserve it verbatim.
        json: JSON.parse(formatJson(results, { cwd: null, run })) as unknown,
        sarif: formatSarif(results, { cwd: null, run }),
      });
    },
  );

  server.registerTool(
    'report_token_usage',
    {
      title: 'Estimate token usage',
      description:
        'Rough on-disk token estimate for paths (same heuristic as vault-guard tokens). Does not call cloud APIs.',
      inputSchema: {
        paths: z.array(z.string()).optional().describe('Files or directories to include (default: cwd)'),
      },
    },
    async ({ paths }) => {
      const targets = paths && paths.length > 0 ? paths : [process.cwd()];
      let total = 0;
      const breakdown: Record<string, number> = {};
      const walkFile = (file: string): void => {
        try {
          if (!fs.existsSync(file)) return;
          const st = fs.statSync(file);
          if (st.isFile()) {
            const n = tokenCounter.countTokensInFile(file);
            total += n;
            const ext = path.extname(file) || '(no-ext)';
            breakdown[ext] = (breakdown[ext] ?? 0) + n;
          } else if (st.isDirectory()) {
            const entries = fs.readdirSync(file, { withFileTypes: true });
            for (const e of entries) {
              if (e.name === 'node_modules' || e.name === '.git') continue;
              walkFile(path.join(file, e.name));
            }
          }
        } catch {
          /* skip */
        }
      };
      for (const t of targets) {
        walkFile(path.resolve(process.cwd(), t));
      }
      const estCostAnthropic = tokenCounter.calculateCost('anthropic', total, 0);
      return toolPayload({
        total_tokens_estimated: total,
        breakdown,
        est_cost_usd_anthropic_input_only: Math.round(estCostAnthropic * 10_000) / 10_000,
      });
    },
  );

  server.registerTool(
    'record_session_event',
    {
      title: 'Record session / accuracy event',
      description:
        'Append an opt-in local telemetry row (e.g. accept/revert/secret_blocked). Stored under ~/.vault-guard/usage.sqlite only.',
      inputSchema: {
        event_type: z.string().describe('e.g. accept | reject | revert | secret_blocked | completion'),
        model: z.string().optional(),
        cwd: z.string().optional(),
        language: z.string().optional(),
        lines_accepted: z.number().int().optional(),
        lines_suggested: z.number().int().optional(),
        lines_reverted: z.number().int().optional(),
        extra: z.record(z.string(), z.any()).optional(),
      },
    },
    async args => {
      const store = getTelemetry();
      if (!store) {
        return toolPayload({ ok: false, telemetry: 'unavailable' });
      }
      store.recordSession({
        eventType: args.event_type,
        model: args.model,
        cwd: args.cwd,
        language: args.language,
        linesAccepted: args.lines_accepted,
        linesSuggested: args.lines_suggested,
        linesReverted: args.lines_reverted,
        extra: args.extra,
      });
      return toolPayload({ ok: true });
    },
  );

  return server;
}
