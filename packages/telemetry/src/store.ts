import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { TokenCounter } from '@vaultcompass/vault-guard-core';

// Lazy native-binding loader uses createRequire so that:
// (a) the native binding is not loaded at module import time (saves startup
//     cost and allows graceful degradation on platforms without pre-built binaries)
// (b) @typescript-eslint/no-require-imports is not violated
const _require = createRequire(__filename);

// ---------------------------------------------------------------------------
// TelemetryUnavailableError
// ---------------------------------------------------------------------------

/**
 * Thrown when `better-sqlite3` native bindings are missing or incompatible.
 *
 * This happens when:
 *   - The package was installed with `--ignore-scripts` (skips node-gyp compile)
 *   - The Node.js ABI changed after install (e.g. nvm version switch)
 *   - The pre-built binary is missing for the current platform/arch
 *
 * Callers that don't strictly need telemetry should catch this and degrade
 * gracefully (e.g. `statusline` and `suggest-model`). The `proxy` command
 * intentionally lets this propagate — it is the primary telemetry writer and
 * should fail loudly rather than silently discard usage data.
 *
 * @example
 * ```ts
 * try {
 *   const store = new TelemetryStore();
 *   const payload = store.getStatuslinePayload();
 *   console.log(payload);
 * } catch (err) {
 *   if (err instanceof TelemetryUnavailableError) {
 *     console.error('Telemetry unavailable:', err.message);
 *   } else {
 *     throw err;
 *   }
 * }
 * ```
 */
export class TelemetryUnavailableError extends Error {
  constructor(cause: unknown) {
    const msg =
      `better-sqlite3 native bindings could not be loaded.\n` +
      `Re-install to rebuild them: npm install -g @vaultcompass/vault-guard\n` +
      `Underlying error: ${String(cause)}`;
    super(msg);
    this.name = 'TelemetryUnavailableError';
  }
}

// ---------------------------------------------------------------------------
// Lazy DB loader
// ---------------------------------------------------------------------------

type DatabaseType = import('better-sqlite3').Database;
type DatabaseConstructor = typeof import('better-sqlite3');

let _DbClass: DatabaseConstructor | null = null;

function getDbClass(): DatabaseConstructor {
  if (_DbClass) return _DbClass;
  try {
    // Dynamic import to defer native binding load until first use.
    // We need synchronous access here (TelemetryStore constructor is sync),
    // so we use createRequire from the module system rather than top-level await.
    const mod = _require('better-sqlite3') as DatabaseConstructor;
    _DbClass = mod;
    return _DbClass;
  } catch (err) {
    throw new TelemetryUnavailableError(err);
  }
}

export interface UsageRecordInput {
  createdAt?: Date;
  provider?: 'anthropic' | 'openai' | 'unknown';
  model?: string | null;
  cwd?: string | null;
  inputTokens: number;
  outputTokens: number;
  estCostUsd?: number;
  source?: string | null;
}

export interface SessionRecordInput {
  createdAt?: Date;
  eventType: string;
  model?: string | null;
  cwd?: string | null;
  language?: string | null;
  linesAccepted?: number;
  linesSuggested?: number;
  linesReverted?: number;
  extra?: Record<string, unknown>;
}

export interface StatuslineJson {
  secrets_today: number;
  tokens_today_input: number;
  tokens_today_output: number;
  est_cost_usd: number;
  model: string | null;
  window_start_utc: string;
}

export interface ModelSuggestion {
  suggested_model: string | null;
  reason: string;
  by_model: Array<{
    model: string;
    usage_events: number;
    revert_rate: number | null;
    avg_cost_usd: number;
  }>;
}

function defaultDbPath(): string {
  const dir = path.join(os.homedir(), '.vault-guard');
  return path.join(dir, 'usage.sqlite');
}

function utcDayStart(d = new Date()): string {
  return d.toISOString().slice(0, 10);
}

export class TelemetryStore {
  private readonly db: DatabaseType;
  private readonly counter = new TokenCounter();

  constructor(dbPath?: string) {
    const resolved = dbPath ?? defaultDbPath();
    const dir = path.dirname(resolved);
    fs.mkdirSync(dir, { recursive: true });
    // getDbClass() throws TelemetryUnavailableError if bindings missing.
    this.db = new (getDbClass())(resolved);
    this.db.pragma('journal_mode = WAL');
    this.initSchema();
  }

  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS usage_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        provider TEXT,
        model TEXT,
        cwd TEXT,
        input_tokens INTEGER NOT NULL DEFAULT 0,
        output_tokens INTEGER NOT NULL DEFAULT 0,
        est_cost_usd REAL NOT NULL DEFAULT 0,
        source TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_events(created_at);

      CREATE TABLE IF NOT EXISTS session_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        event_type TEXT NOT NULL,
        model TEXT,
        cwd TEXT,
        language TEXT,
        lines_accepted INTEGER,
        lines_suggested INTEGER,
        lines_reverted INTEGER,
        extra_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_session_created ON session_events(created_at);
      CREATE INDEX IF NOT EXISTS idx_session_type ON session_events(event_type);
    `);
  }

  close(): void {
    this.db.close();
  }

  /**
   * Force a WAL checkpoint (TRUNCATE) and close the database.
   *
   * Why: in WAL mode the main DB file lags behind the `-wal` sidecar until a
   * checkpoint runs. If the process is killed (SIGINT/SIGTERM during proxy
   * shutdown) without checkpointing, recent rows live only in the WAL and
   * survive only as long as that file does. TRUNCATE both checkpoints and
   * shrinks the WAL to zero so the next reader sees an up-to-date main file
   * with no recovery surprises.
   *
   * Best-effort: if the pragma fails (e.g. handle already closed by another
   * shutdown path) we still attempt to close the underlying handle.
   */
  closeAndCheckpoint(): void {
    try {
      this.db.pragma('wal_checkpoint(TRUNCATE)');
    } catch {
      // Handle may already be in a shutting-down state; safe to ignore.
    }
    try {
      this.db.close();
    } catch {
      // Best-effort: nothing useful we can do on shutdown if close throws.
    }
  }

  recordUsage(input: UsageRecordInput): void {
    const created = (input.createdAt ?? new Date()).toISOString();
    let cost = input.estCostUsd;
    if (cost === undefined) {
      const p = input.provider ?? 'anthropic';
      if (p === 'anthropic' || p === 'openai') {
        cost = this.counter.calculateCost(p, input.inputTokens, input.outputTokens);
      } else {
        cost = 0;
      }
    }
    const stmt = this.db.prepare(`
      INSERT INTO usage_events (created_at, provider, model, cwd, input_tokens, output_tokens, est_cost_usd, source)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      created,
      input.provider ?? 'unknown',
      input.model ?? null,
      input.cwd ?? null,
      input.inputTokens,
      input.outputTokens,
      cost,
      input.source ?? null,
    );
  }

  recordSession(input: SessionRecordInput): void {
    const created = (input.createdAt ?? new Date()).toISOString();
    const extra =
      input.extra && Object.keys(input.extra).length > 0 ? JSON.stringify(input.extra) : null;
    const stmt = this.db.prepare(`
      INSERT INTO session_events (
        created_at, event_type, model, cwd, language,
        lines_accepted, lines_suggested, lines_reverted, extra_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      created,
      input.eventType,
      input.model ?? null,
      input.cwd ?? null,
      input.language ?? null,
      input.linesAccepted ?? null,
      input.linesSuggested ?? null,
      input.linesReverted ?? null,
      extra,
    );
  }

  /** Count session events that represent blocked secrets today (UTC date). */
  secretsBlockedToday(day = utcDayStart()): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS c FROM session_events
         WHERE event_type = 'secret_blocked' AND substr(created_at, 1, 10) = ?`,
      )
      .get(day) as { c: number };
    return row.c;
  }

  getStatuslinePayload(now = new Date()): StatuslineJson {
    const day = utcDayStart(now);
    const windowStart = `${day}T00:00:00.000Z`;

    const usage = this.db
      .prepare(
        `SELECT
           COALESCE(SUM(input_tokens), 0) AS tin,
           COALESCE(SUM(output_tokens), 0) AS tout,
           COALESCE(SUM(est_cost_usd), 0) AS cost
         FROM usage_events
         WHERE substr(created_at, 1, 10) = ?`,
      )
      .get(day) as { tin: number; tout: number; cost: number };

    const lastModel = this.db
      .prepare(
        `SELECT model FROM usage_events
         WHERE substr(created_at, 1, 10) = ? AND model IS NOT NULL AND model != ''
         ORDER BY created_at DESC LIMIT 1`,
      )
      .get(day) as { model: string } | undefined;

    return {
      secrets_today: this.secretsBlockedToday(day),
      tokens_today_input: usage.tin,
      tokens_today_output: usage.tout,
      est_cost_usd: Math.round(usage.cost * 10_000) / 10_000,
      model: lastModel?.model ?? null,
      window_start_utc: windowStart,
    };
  }

  /**
   * Heuristic model hint from the last 7 days of session + usage data.
   * Prefer models with more usage and lower revert_rate when session metrics exist.
   */
  suggestModel(opts: { cwd?: string; language?: string } = {}): ModelSuggestion {
    const since = new Date();
    since.setUTCDate(since.getUTCDate() - 7);
    const sinceIso = since.toISOString();

    const usageByModel = this.db
      .prepare(
        `SELECT model AS m,
                COUNT(*) AS n,
                AVG(est_cost_usd) AS avg_cost
         FROM usage_events
         WHERE created_at >= ? AND model IS NOT NULL AND model != ''
         GROUP BY model`,
      )
      .all(sinceIso) as Array<{ m: string; n: number; avg_cost: number }>;

    const revertRows = this.db
      .prepare(
        `SELECT model AS m,
                SUM(COALESCE(lines_reverted, 0)) AS rev,
                SUM(COALESCE(lines_suggested, 0)) AS sug
         FROM session_events
         WHERE created_at >= ?
           AND event_type IN ('apply', 'completion', 'revert')
           AND model IS NOT NULL AND model != ''
         GROUP BY model`,
      )
      .all(sinceIso) as Array<{ m: string; rev: number; sug: number }>;

    const revertMap = new Map<string, { rev: number; sug: number }>();
    for (const r of revertRows) {
      revertMap.set(r.m, { rev: r.rev, sug: r.sug });
    }

    const by_model = usageByModel.map(u => {
      const rr = revertMap.get(u.m);
      let revert_rate: number | null = null;
      if (rr && rr.sug > 0) {
        revert_rate = rr.rev / rr.sug;
      }
      return {
        model: u.m,
        usage_events: u.n,
        revert_rate,
        avg_cost_usd: Math.round((u.avg_cost ?? 0) * 10_000) / 10_000,
      };
    });

    if (by_model.length === 0) {
      return {
        suggested_model: null,
        reason: 'No recent usage with a model label. Use the proxy or MCP report_token_usage first.',
        by_model: [],
      };
    }

    by_model.sort((a, b) => {
      const ar = a.revert_rate ?? 0.5;
      const br = b.revert_rate ?? 0.5;
      if (ar !== br) return ar - br;
      return b.usage_events - a.usage_events;
    });

    const best = by_model[0];
    let reason = `Lowest observed revert pressure among recent models (${best.usage_events} logged usage row(s)).`;
    if (opts.language) reason += ` Context: language=${opts.language}.`;
    if (opts.cwd) reason += ` cwd hint recorded.`;

    return {
      suggested_model: best.model,
      reason,
      by_model,
    };
  }
}
