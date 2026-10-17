import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { SecretScanner, type ClockMeasure, type ScanClock } from '@vaultcompass/vault-guard-core';
import type { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';
import { createMcpServer } from '../server';
import { scanWorkspaceDirectory } from '../workspace-scan';

/**
 * U10 and U16 of the 2026-10-17 design: MCP scan_workspace shares the core
 * classifier and budget; scan_file is unchanged.
 */

const KEY = ['AKIA', 'Q7MZR2XVB9', 'NTD4WH'].join('');
const KEY_LINE = `aws_access_key_id = ${KEY}\n`;

function seeded(n: number, seed = 7): Buffer {
  const out = Buffer.alloc(n);
  let x = seed;
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out[i] = x & 0xff;
  }
  return out;
}

const realMp4 = (n: number): Buffer =>
  Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]), seeded(n - 12)]);

function git(cwd: string, args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}

function repo(files: Record<string, string | Buffer>): string {
  const d = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-bin-')));
  git(d, ['init', '-q', '-b', 'main']);
  git(d, ['config', 'user.email', 'test@example.invalid']);
  git(d, ['config', 'user.name', 'Test']);
  git(d, ['config', 'commit.gpgsign', 'false']);
  fs.mkdirSync(path.join(d, 'src'), { recursive: true });
  fs.writeFileSync(path.join(d, 'src/ok.ts'), 'export const ok = 1;\n');
  for (const [rel, data] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true });
    fs.writeFileSync(path.join(d, rel), data);
  }
  git(d, ['add', '-A', '-f']);
  git(d, ['commit', '-q', '-m', 'init']);
  return d;
}

function scripted(measure: ClockMeasure, cpu: number[]): ScanClock {
  let c = 0;
  let w = 0;
  let cc = 0;
  let wc = 0;
  return {
    measure,
    cpuMs: () => {
      if (cc % 2 === 1) c += cpu[(cc - 1) / 2] ?? 0;
      cc++;
      return c;
    },
    wallMs: () => {
      if (wc % 2 === 1) w += cpu[(wc - 1) / 2] ?? 0;
      wc++;
      return w;
    },
  };
}

describe('U10: scan_workspace uses the core classifier and budget', () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it("on A2's tree it finds the key in credentials.png and reports the mismatch", async () => {
    const d = repo({ 'config/credentials.png': KEY_LINE });
    dirs.push(d);
    const o = await scanWorkspaceDirectory(d, new SecretScanner());
    expect(o.results.some(r => r.file.endsWith('credentials.png'))).toBe(true);
    expect(o.binaryTypeMismatch).toEqual([{ file: path.join(d, 'config/credentials.png'), family: 'image' }]);
    expect(o.binaryFilesSkipped).toBe(0);
  });

  it('the mismatch list is sorted by file, not left in completion order', async () => {
    // Untracked, so each is read from disk concurrently rather than answered in
    // order by the one cat-file process. The first file by name is the slowest
    // to read and scan, so it completes last; the list must still come back
    // sorted (design section 5).
    const d = repo({});
    dirs.push(d);
    const big = Buffer.from('word '.repeat(2 * 1024 * 1024));
    fs.mkdirSync(path.join(d, 'a'));
    fs.mkdirSync(path.join(d, 'b'));
    fs.mkdirSync(path.join(d, 'c'));
    fs.writeFileSync(path.join(d, 'a/first.mov'), big);
    fs.writeFileSync(path.join(d, 'b/second.png'), 'just text\n');
    fs.writeFileSync(path.join(d, 'c/third.bin'), 'more text\n');
    const o = await scanWorkspaceDirectory(d, new SecretScanner());
    expect(o.binaryTypeMismatch.map(m => path.relative(d, m.file))).toEqual([
      'a/first.mov',
      'b/second.png',
      'c/third.bin',
    ]);
    expect(o.binaryTypeMismatch.map(m => m.family)).toEqual(['video', 'image', 'other']);
  });

  it("on A8's tree it reports the skip of a 40 MiB real-header .mp4", async () => {
    const d = repo({ 'media/clip.mp4': realMp4(40 * 1024 * 1024) });
    dirs.push(d);
    const o = await scanWorkspaceDirectory(d, new SecretScanner());
    expect(o.unscannable).toEqual([]);
    expect(o.binaryFilesSkipped).toBe(1);
    expect(o.binaryFilesSkippedByFamily.video).toBe(1);
    expect(o.filesScanned).toBe(1);
  }, 120_000);

  it('the budget re-time applies through the same seam', async () => {
    const d = repo({});
    dirs.push(d);
    const retimed = await scanWorkspaceDirectory(d, new SecretScanner(), 10, [], 5000, scripted('thread-cpu', [6000, 100]));
    expect(retimed.scanBudgetRetimed).toBe(1);
    expect(retimed.overBudget).toEqual([]);
    const twice = await scanWorkspaceDirectory(d, new SecretScanner(), 10, [], 5000, scripted('thread-cpu', [6000, 6000]));
    expect(twice.overBudget).toEqual([
      expect.objectContaining({ elapsed_ms: 6000, budget_ms: 5000, reason: expect.stringContaining('twice') }),
    ]);
  });

  it('the scan_workspace JSON run carries the binary counts', async () => {
    const d = repo({ 'a.png': Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), seeded(64)]), 'b.mov': 'text\n' });
    dirs.push(d);
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: d }));
    try {
      const res = parse(await client.callTool({ name: 'scan_workspace', arguments: { root: '.' } }));
      const run = (res.json as { run: Record<string, unknown> }).run;
      expect(run.binary_files_skipped).toBe(1);
      expect(run.binary_type_mismatch).toEqual([{ file: 'b.mov', family: 'video' }]);
      expect(run.binary_type_mismatch_scanned).toBe(1);
      expect(run.scan_budget_retimed).toBe(0);
      expect(run.binary_worktree_copies_skipped).toBe(0);
    } finally {
      await client.close();
    }
  });
});

type ToolResult = { content: Array<{ type: string; text: string }> };
const parse = (res: unknown): Record<string, unknown> =>
  JSON.parse((res as ToolResult).content[0].text) as Record<string, unknown>;
const fakeStore = (): TelemetryStore =>
  ({ isAvailable: () => true, recordSession: () => {} }) as unknown as TelemetryStore;

async function connect(server: ReturnType<typeof createMcpServer>): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return client;
}

describe('U16: scan_file is unchanged', () => {
  let root: string;
  beforeEach(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-file-')));
  });
  afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

  it('a real-header .mp4 is scanned as text: no skip, no count, no budget entry', async () => {
    // A key inside the media bytes: only a scan as text can find it.
    const mp4 = Buffer.concat([realMp4(4096), Buffer.from(`\n${KEY_LINE}`), seeded(1024, 9)]);
    fs.writeFileSync(path.join(root, 'clip.mp4'), mp4);
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
    try {
      const res = parse(await client.callTool({ name: 'scan_file', arguments: { file_path: 'clip.mp4' } }));
      const run = (res.json as { run: Record<string, unknown> }).run;
      expect(run.files_scanned).toBe(1);
      expect(run.bytes_scanned).toBe(mp4.length);
      expect(run.binary_files_skipped).toBeUndefined();
      expect(res.over_budget).toBeUndefined();
      expect((res.summary as { total_matches: number }).total_matches).toBeGreaterThanOrEqual(1);
    } finally {
      await client.close();
    }
  });

  it("A2's credentials.png returns the key", async () => {
    fs.writeFileSync(path.join(root, 'credentials.png'), KEY_LINE);
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: root }));
    try {
      const res = parse(await client.callTool({ name: 'scan_file', arguments: { file_path: 'credentials.png' } }));
      expect((res.summary as { total_matches: number }).total_matches).toBeGreaterThanOrEqual(1);
    } finally {
      await client.close();
    }
  });
});
