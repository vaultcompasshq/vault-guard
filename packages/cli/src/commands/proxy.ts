import * as http from 'http';
import * as https from 'https';
import path from 'path';
import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

/** Bound request buffering to reduce accidental OOM from huge bodies. */
const MAX_REQUEST_BYTES = 32 * 1024 * 1024;
/** Bound non-stream upstream response buffering. */
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

/**
 * Minimal opt-in Anthropic forwarder: POST /v1/messages → api.anthropic.com.
 * Non-streaming responses parse `usage` for local SQLite telemetry.
 * Streaming requests are forwarded but token counts are logged as 0 (MVP).
 */
export async function proxyCommand(listen: string): Promise<void> {
  const store = new TelemetryStore();
  const [host, portStr] = parseListen(listen);
  const port = Number(portStr);
  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid port in --listen "${listen}"`);
  }

  if (!isLoopbackHost(host)) {
    process.stderr.write(
      `Warning: binding to ${host} exposes this proxy on the network. Prefer 127.0.0.1 for local-only use.\n`,
    );
  }

  const server = http.createServer((req, res) => {
    const u = req.url ?? '/';
    if (req.method !== 'POST' || !u.startsWith('/v1/messages')) {
      res.statusCode = 404;
      res.setHeader('content-type', 'text/plain; charset=utf-8');
      res.end(
        'vault-guard proxy (MVP): only POST /v1/messages is forwarded to https://api.anthropic.com\n',
      );
      return;
    }

    const chunks: Buffer[] = [];
    let received = 0;
    let requestAborted = false;
    req.on('data', c => {
      if (requestAborted) return;
      const b = c as Buffer;
      received += b.length;
      if (received > MAX_REQUEST_BYTES) {
        requestAborted = true;
        res.statusCode = 413;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ error: 'payload_too_large', max_bytes: MAX_REQUEST_BYTES }));
        req.destroy();
        return;
      }
      chunks.push(b);
    });
    req.on('end', () => {
      if (requestAborted) return;
      const bodyBuf = Buffer.concat(chunks);
      let bodyJson: { stream?: boolean; model?: string } = {};
      try {
        bodyJson = JSON.parse(bodyBuf.toString('utf8')) as typeof bodyJson;
      } catch {
        /* forward raw body */
      }

      const apiKey =
        (typeof req.headers['x-api-key'] === 'string' ? req.headers['x-api-key'] : undefined) ??
        process.env.ANTHROPIC_API_KEY ??
        '';
      if (!apiKey) {
        res.statusCode = 401;
        res.setHeader('content-type', 'application/json');
        res.end(
          JSON.stringify({
            error: 'missing_api_key',
            message: 'Set ANTHROPIC_API_KEY or send x-api-key header',
          }),
        );
        return;
      }

      const anthropicVersion =
        (typeof req.headers['anthropic-version'] === 'string'
          ? req.headers['anthropic-version']
          : undefined) ?? '2023-06-01';

      const cwd = process.cwd();
      const opts: https.RequestOptions = {
        hostname: 'api.anthropic.com',
        port: 443,
        path: u.startsWith('/') ? u : `/${u}`,
        method: 'POST',
        headers: {
          'content-type': (req.headers['content-type'] as string) ?? 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': anthropicVersion,
          'content-length': String(bodyBuf.length),
        },
      };

      const preq = https.request(opts, pres => {
        const stream = Boolean(bodyJson.stream);
        if (stream) {
          const headers = { ...pres.headers };
          res.writeHead(pres.statusCode ?? 502, headers);
          pres.pipe(res);
          pres.on('end', () => {
            store.recordUsage({
              provider: 'anthropic',
              model: typeof bodyJson.model === 'string' ? bodyJson.model : null,
              cwd,
              inputTokens: 0,
              outputTokens: 0,
              estCostUsd: 0,
              source: 'proxy-stream',
            });
          });
          return;
        }

        const outChunks: Buffer[] = [];
        let outLen = 0;
        pres.on('data', d => {
          const b = d as Buffer;
          outLen += b.length;
          if (outLen > MAX_RESPONSE_BYTES) {
            res.statusCode = 502;
            res.setHeader('content-type', 'text/plain; charset=utf-8');
            res.end('upstream response exceeded max buffer size');
            pres.destroy();
            return;
          }
          outChunks.push(b);
        });
        pres.on('end', () => {
          const raw = Buffer.concat(outChunks);
          const ct = pres.headers['content-type'];
          res.writeHead(pres.statusCode ?? 502, typeof ct === 'string' ? { 'content-type': ct } : {});
          res.end(raw);

          try {
            const parsed = JSON.parse(raw.toString('utf8')) as {
              model?: string;
              usage?: { input_tokens?: number; output_tokens?: number };
            };
            const input = parsed.usage?.input_tokens ?? 0;
            const output = parsed.usage?.output_tokens ?? 0;
            const model = parsed.model ?? (typeof bodyJson.model === 'string' ? bodyJson.model : null);
            store.recordUsage({
              provider: 'anthropic',
              model,
              cwd,
              inputTokens: input,
              outputTokens: output,
              source: 'proxy',
            });
          } catch {
            store.recordUsage({
              provider: 'anthropic',
              model: typeof bodyJson.model === 'string' ? bodyJson.model : null,
              cwd,
              inputTokens: 0,
              outputTokens: 0,
              source: 'proxy-parse-failed',
            });
          }
        });
      });

      preq.on('error', e => {
        res.statusCode = 502;
        res.setHeader('content-type', 'text/plain; charset=utf-8');
        res.end(String(e));
      });

      preq.write(bodyBuf);
      preq.end();
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(port, host, () => resolve());
    server.on('error', reject);
  });

  process.stderr.write(
    `vault-guard proxy listening on http://${host}:${port}\n` +
      `Forward Anthropic traffic here (e.g. ANTHROPIC_BASE_URL=http://${host}:${port}). ` +
      `Non-stream JSON responses log usage to ${path.join('~', '.vault-guard', 'usage.sqlite')}.\n`,
  );
}

function parseListen(listen: string): [string, string] {
  const m = /^(.*):(\d+)$/.exec(listen.trim());
  if (!m) {
    throw new Error(`Invalid --listen "${listen}" (expected host:port, e.g. 127.0.0.1:8765)`);
  }
  return [m[1], m[2]];
}

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1' || h === '[::1]';
}
