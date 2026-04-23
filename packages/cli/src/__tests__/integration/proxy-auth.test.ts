// Must be hoisted before imports so proxy.ts gets the mocked module.
jest.mock('https');

import * as http from 'http';
import * as https from 'https';
import { proxyCommand } from '../../commands/proxy';
import { postToProxy, setupUpstreamMock, makeTmpDbPath } from './proxy-test-helpers';
import { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';

// ---------------------------------------------------------------------------
// Isolated telemetry DB
// ---------------------------------------------------------------------------

const DB_PATH = makeTmpDbPath();

jest.mock('@vaultcompass/vault-guard-telemetry', () => {
  const actual = jest.requireActual<typeof import('@vaultcompass/vault-guard-telemetry')>(
    '@vaultcompass/vault-guard-telemetry',
  );
  return {
    ...actual,
    TelemetryStore: class extends actual.TelemetryStore {
      constructor() {
        super(DB_PATH);
      }
    },
  };
});

const mockHttps = https as unknown as { request: jest.Mock };

beforeEach(() => {
  mockHttps.request.mockReset();
});

describe('proxy auth + bind security', () => {
  // -------------------------------------------------------------------------
  // Bind refusal
  // -------------------------------------------------------------------------

  it('refuses to start when bound to 0.0.0.0 without --allow-public', async () => {
    await expect(proxyCommand({ listen: '0.0.0.0:0' })).rejects.toThrow(
      /Refusing to bind non-loopback/,
    );
  });

  it('starts successfully when bound to 0.0.0.0 with --allow-public', async () => {
    setupUpstreamMock(mockHttps);
    const handle = await proxyCommand({ listen: '0.0.0.0:0', allowPublic: true });
    expect(handle.server.listening).toBe(true);
    await handle.shutdown('test-cleanup');
  });

  it.each([
    ['127.0.0.1', '127.0.0.1:0'],
    ['localhost', 'localhost:0'],
  ])('starts on loopback variant %s', async (_label, listenStr) => {
    setupUpstreamMock(mockHttps);
    const handle = await proxyCommand({ listen: listenStr });
    expect(handle.server.listening).toBe(true);
    await handle.shutdown('test-cleanup');
  });

  // -------------------------------------------------------------------------
  // Authentication
  // -------------------------------------------------------------------------

  it('returns 401 when x-api-key is missing and allowEnvFallback is off', async () => {
    setupUpstreamMock(mockHttps);
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(port, '/v1/messages', { model: 'claude-3' });
      expect(result.status).toBe(401);
      const parsed = JSON.parse(result.body) as { error: string; message: string };
      expect(parsed.error).toBe('missing_api_key');
      expect(parsed.message).toMatch(/--allow-env-fallback|restart proxy/);
    } finally {
      if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
      await handle.shutdown('test-cleanup');
    }
  });

  it('returns 401 when allowEnvFallback is on but ANTHROPIC_API_KEY is not set', async () => {
    setupUpstreamMock(mockHttps);
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    const handle = await proxyCommand({ listen: '127.0.0.1:0', allowEnvFallback: true });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(port, '/v1/messages', { model: 'claude-3' });
      expect(result.status).toBe(401);
      const parsed = JSON.parse(result.body) as { error: string; message: string };
      expect(parsed.error).toBe('missing_api_key');
      expect(parsed.message).toMatch(/ANTHROPIC_API_KEY/);
    } finally {
      if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
      await handle.shutdown('test-cleanup');
    }
  });

  it('forwards request and passes x-api-key to upstream when header present', async () => {
    const { capturedHeaders } = setupUpstreamMock(mockHttps, {
      body: JSON.stringify({ model: 'claude-3', usage: { input_tokens: 10, output_tokens: 5 } }),
    });

    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3' },
        { 'x-api-key': 'test-key-abc' },
      );
      expect(result.status).toBe(200);
      expect(capturedHeaders[0]?.['x-api-key']).toBe('test-key-abc');
    } finally {
      await handle.shutdown('test-cleanup');
    }
  });

  it('uses env key fallback when allowEnvFallback is on and env var is set', async () => {
    const { capturedHeaders } = setupUpstreamMock(mockHttps, {
      body: JSON.stringify({ model: 'claude-3', usage: { input_tokens: 5, output_tokens: 2 } }),
    });

    const saved = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = 'env-test-key-xyz';

    const handle = await proxyCommand({ listen: '127.0.0.1:0', allowEnvFallback: true });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(port, '/v1/messages', { model: 'claude-3' });
      expect(result.status).toBe(200);
      expect(capturedHeaders[0]?.['x-api-key']).toBe('env-test-key-xyz');
    } finally {
      if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
      else delete process.env.ANTHROPIC_API_KEY;
      await handle.shutdown('test-cleanup');
    }
  });

  it('caller x-api-key takes precedence over env var', async () => {
    const { capturedHeaders } = setupUpstreamMock(mockHttps, {
      body: JSON.stringify({ model: 'claude-3', usage: { input_tokens: 1, output_tokens: 1 } }),
    });

    const saved = process.env.ANTHROPIC_API_KEY;
    process.env.ANTHROPIC_API_KEY = 'env-should-not-be-used';

    const handle = await proxyCommand({ listen: '127.0.0.1:0', allowEnvFallback: true });
    const { port } = handle.server.address() as { port: number };

    try {
      const result = await postToProxy(
        port,
        '/v1/messages',
        { model: 'claude-3' },
        { 'x-api-key': 'caller-key' },
      );
      expect(result.status).toBe(200);
      expect(capturedHeaders[0]?.['x-api-key']).toBe('caller-key');
    } finally {
      if (saved !== undefined) process.env.ANTHROPIC_API_KEY = saved;
      else delete process.env.ANTHROPIC_API_KEY;
      await handle.shutdown('test-cleanup');
    }
  });

  it('returns 404 for non-/v1/messages paths', async () => {
    setupUpstreamMock(mockHttps);
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };
    try {
      const result = await postToProxy(port, '/some/other/path', {}, { 'x-api-key': 'k' });
      expect(result.status).toBe(404);
    } finally {
      await handle.shutdown('test-cleanup');
    }
  });

  it('returns 413 when request body exceeds the 32 MB cap', async () => {
    setupUpstreamMock(mockHttps);
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    const { port } = handle.server.address() as { port: number };

    try {
      const chunkSize = 64 * 1024;
      const totalBytes = 33 * 1024 * 1024;
      const chunk = Buffer.alloc(chunkSize, 'x');

      const status = await new Promise<number>((resolve, reject) => {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const req = require('http').request(
          {
            hostname: '127.0.0.1',
            port,
            path: '/v1/messages',
            method: 'POST',
            headers: { 'content-type': 'application/json', 'x-api-key': 'k' },
          },
          (res: http.IncomingMessage) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode ?? 0));
          },
        );
        req.on('error', () => resolve(0));
        let sent = 0;
        const writeChunk = () => {
          while (sent < totalBytes) {
            const ok = req.write(chunk) as boolean;
            sent += chunkSize;
            if (!ok) {
              req.once('drain', writeChunk);
              return;
            }
          }
          req.end();
        };
        writeChunk();
      });

      expect(status).toBe(413);
      expect(mockHttps.request).not.toHaveBeenCalled();
    } finally {
      await handle.shutdown('test-cleanup');
    }
  });
});
