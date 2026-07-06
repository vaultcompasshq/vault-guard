import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { TelemetryStore, TelemetryUnavailableError } from '@vaultcompass/vault-guard-telemetry';
import { createMcpServer } from '../server';
import fs from 'fs';
import os from 'os';
import path from 'path';

type ToolResult = { content: Array<{ type: string; text: string }> };

function parse(res: unknown): Record<string, unknown> {
  const r = res as ToolResult;
  return JSON.parse(r.content[0].text) as Record<string, unknown>;
}

/** A no-op telemetry store standing in for a working SQLite-backed store. */
function fakeStore(): TelemetryStore {
  return { recordSession: () => {} } as unknown as TelemetryStore;
}

/** Factory that simulates missing `better-sqlite3` native bindings. */
function unavailableFactory(): () => TelemetryStore {
  return () => {
    throw new TelemetryUnavailableError(new Error('no native bindings'));
  };
}

// A value that matches the built-in `anthropic` detector (sk-ant- + >=20 chars).
const SECRET = 'sk-ant-api03-A1b2C3d4E5f6G7h8J9k0L1m2';

async function connect(server: ReturnType<typeof createMcpServer>): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return client;
}

describe('createMcpServer', () => {
  it('registers the five Vault Guard tools', async () => {
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore }));
    const { tools } = await client.listTools();
    expect(tools.map(t => t.name).sort()).toEqual(
      ['record_session_event', 'report_token_usage', 'scan_file', 'scan_text', 'scan_workspace'].sort(),
    );
    await client.close();
  });

  it('scan_text detects a secret in pasted content', async () => {
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore }));
    const res = await client.callTool({ name: 'scan_text', arguments: { text: `const key = "${SECRET}";` } });
    const payload = parse(res);
    expect((payload.summary as { total_matches: number }).total_matches).toBeGreaterThanOrEqual(1);
    await client.close();
  });

  it('scan_file rejects paths outside the workspace root', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-root-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-outside-'));
    try {
      const outsideFile = path.join(outside, 'secret.ts');
      fs.writeFileSync(outsideFile, `const key = "${SECRET}";`, 'utf8');
      const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
      const res = await client.callTool({ name: 'scan_file', arguments: { file_path: outsideFile } });
      expect(parse(res)).toMatchObject({ error: 'path_outside_workspace' });
      await client.close();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('scan_file allows files inside the workspace root', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-root-'));
    try {
      fs.writeFileSync(path.join(root, 'secret.ts'), `const key = "${SECRET}";`, 'utf8');
      const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
      const res = await client.callTool({ name: 'scan_file', arguments: { file_path: 'secret.ts' } });
      const payload = parse(res);
      expect((payload.summary as { total_matches: number }).total_matches).toBeGreaterThanOrEqual(1);
      await client.close();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('scan_file rejects symlinks that resolve outside the workspace root', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-root-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-outside-'));
    try {
      const outsideFile = path.join(outside, 'secret.ts');
      const linkPath = path.join(root, 'link.ts');
      fs.writeFileSync(outsideFile, `const key = "${SECRET}";`, 'utf8');
      try {
        fs.symlinkSync(outsideFile, linkPath);
      } catch {
        return;
      }
      const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
      const res = await client.callTool({ name: 'scan_file', arguments: { file_path: 'link.ts' } });
      expect(parse(res)).toMatchObject({ error: 'path_outside_workspace' });
      await client.close();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('scan_workspace rejects traversal outside the workspace root', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-root-'));
    try {
      const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
      const res = await client.callTool({ name: 'scan_workspace', arguments: { root: '..' } });
      expect(parse(res)).toMatchObject({ error: 'path_outside_workspace' });
      await client.close();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  it('report_token_usage rejects paths outside the workspace root', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-root-'));
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-outside-'));
    try {
      const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
      const res = await client.callTool({ name: 'report_token_usage', arguments: { paths: [outside] } });
      expect(parse(res)).toMatchObject({ error: 'path_outside_workspace' });
      await client.close();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  it('scan_workspace applies .vault-guard.json ignore paths', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-root-'));
    try {
      fs.writeFileSync(
        path.join(root, '.vault-guard.json'),
        JSON.stringify({ ignore: { paths: ['ignored.ts'] } }),
        'utf8',
      );
      fs.writeFileSync(path.join(root, 'ignored.ts'), `const key = "${SECRET}";`, 'utf8');
      const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
      const res = await client.callTool({ name: 'scan_workspace', arguments: { root: '.' } });
      const payload = parse(res);
      expect((payload.summary as { total_matches: number }).total_matches).toBe(0);
      await client.close();
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

  // Regression: a missing/incompatible better-sqlite3 binding must NOT crash the
  // server or disable scanning. Telemetry is optional; scanning is the product.
  it('still constructs and scans when telemetry is unavailable', async () => {
    expect(() => createMcpServer({ telemetryFactory: unavailableFactory() })).not.toThrow();

    const client = await connect(createMcpServer({ telemetryFactory: unavailableFactory() }));
    const res = await client.callTool({ name: 'scan_text', arguments: { text: `x = "${SECRET}"` } });
    expect((parse(res).summary as { total_matches: number }).total_matches).toBeGreaterThanOrEqual(1);
    await client.close();
  });

  it('record_session_event degrades to ok:false when telemetry is unavailable', async () => {
    const stderr = jest.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      const client = await connect(createMcpServer({ telemetryFactory: unavailableFactory() }));
      const res = await client.callTool({
        name: 'record_session_event',
        arguments: { event_type: 'secret_blocked' },
      });
      const payload = parse(res);
      expect(payload.ok).toBe(false);
      expect(payload.telemetry).toBe('unavailable');
      await client.close();
    } finally {
      stderr.mockRestore();
    }
  });

  it('record_session_event records the event and returns ok:true when telemetry works', async () => {
    const calls: Array<Record<string, unknown>> = [];
    const store = {
      recordSession: (x: Record<string, unknown>) => {
        calls.push(x);
      },
    } as unknown as TelemetryStore;

    const client = await connect(createMcpServer({ telemetryFactory: () => store }));
    const res = await client.callTool({
      name: 'record_session_event',
      arguments: { event_type: 'revert', model: 'claude-x', lines_reverted: 3 },
    });

    expect(parse(res).ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ eventType: 'revert', model: 'claude-x', linesReverted: 3 });
    await client.close();
  });
});
