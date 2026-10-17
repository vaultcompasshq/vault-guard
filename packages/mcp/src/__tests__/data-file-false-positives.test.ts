import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { TelemetryStore } from '@vaultcompass/vault-guard-telemetry';
import { createMcpServer } from '../server';

/**
 * A22 (MCP rows) and U10 of the 2026-10-17 data-file design: the MCP tools
 * get the demotion through scanContent and the same groups through the
 * shared formatters; their summaries carry demoted_matches and match_groups,
 * and total_matches keeps counting matches.
 */

function seeded(n: number, seed: number): Buffer {
  const out = Buffer.alloc(n);
  let x = seed >>> 0 || 1;
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

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const alnum = (n: number, seed: number): string => {
  const b = seeded(n * 2, seed);
  let s = '';
  for (let i = 0; i < n; i++) s += ALNUM[b[i * 2] % ALNUM.length];
  return s;
};
/** Built at run time; synthetic. */
const KEY = ['AI', 'za'].join('') + alnum(35, 3);
const PNG_HEAD = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);

function runWithKey(chars: number): string {
  const b64 = Buffer.concat([PNG_HEAD, seeded(chars, 12)]).toString('base64').replace(/=/g, '').slice(0, chars - KEY.length);
  const mid = Math.floor(b64.length / 2);
  return b64.slice(0, mid) + KEY + b64.slice(mid);
}

const SVG = `<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,${runWithKey(16384)}"/></svg>\n`;
const NOTEBOOK = JSON.stringify({ outputs: [{ data: { 'image/png': runWithKey(8192) } }] }) + '\n';

function jwt(i: number): string {
  const enc = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
  return [enc({ alg: 'HS256', typ: 'JWT' }), enc({ sub: `row-${i}` }), alnum(43, 5000 + i)].join('.');
}
const CSV = ['a,b,c,token', ...Array.from({ length: 40 }, (_, i) => `${i},x,y,${jwt(i)}`)].join('\n') + '\n';

function git(cwd: string, args: string[]): void {
  execFileSync('git', args, { cwd, stdio: 'ignore' });
}

function repo(files: Record<string, string>): string {
  const d = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-data-')));
  git(d, ['init', '-q', '-b', 'main']);
  git(d, ['config', 'user.email', 'test@example.invalid']);
  git(d, ['config', 'user.name', 'Test']);
  git(d, ['config', 'commit.gpgsign', 'false']);
  for (const [rel, data] of Object.entries({ 'src/ok.ts': 'export const ok = 1;\n', ...files })) {
    fs.mkdirSync(path.dirname(path.join(d, rel)), { recursive: true });
    fs.writeFileSync(path.join(d, rel), data);
  }
  git(d, ['add', '-A', '-f']);
  git(d, ['commit', '-q', '-m', 'init']);
  return d;
}

type ToolResult = { content: Array<{ type: string; text: string }> };
type Doc = { run: Record<string, unknown>; results: Array<{ file: string; matches: Array<Record<string, unknown>>; groups?: unknown[] }> };
const parse = (res: unknown): Record<string, unknown> => JSON.parse((res as ToolResult).content[0].text) as Record<string, unknown>;
const fakeStore = (): TelemetryStore => ({ isAvailable: () => true, recordSession: () => {} }) as unknown as TelemetryStore;

async function connect(server: ReturnType<typeof createMcpServer>): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test-client', version: '0.0.0' });
  await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);
  return client;
}

describe('A22 (MCP): every tool gives the same severity and record', () => {
  const dirs: string[] = [];
  afterAll(() => {
    for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
  });

  const records = (doc: Doc) =>
    doc.results
      .flatMap(r => r.matches.map(m => [r.file, m.type, m.severity, (m.demotion as { reason: string } | undefined)?.reason]))
      .sort();

  it('scan_workspace', async () => {
    const d = repo({ 'assets/logo.svg': SVG, 'nb/plot.ipynb': NOTEBOOK });
    dirs.push(d);
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: d }));
    try {
      const res = parse(await client.callTool({ name: 'scan_workspace', arguments: { root: '.' } }));
      expect(records(res.json as Doc)).toEqual([
        ['assets/logo.svg', 'gcp-api-key', 'low', 'data-uri-binary-payload'],
        ['nb/plot.ipynb', 'gcp-api-key', 'low', 'base64-binary-run'],
      ]);
      expect(res.summary).toMatchObject({ total_matches: 2, demoted_matches: 2, match_groups: 0 });
      const sarif = JSON.parse(res.sarif as string);
      expect(sarif.runs[0].results.map((x: { level: string }) => x.level)).toEqual(['note', 'note']);
    } finally {
      await client.close();
    }
  });

  it.each([
    ['assets/logo.svg', SVG, 'data-uri-binary-payload'],
    ['nb/plot.ipynb', NOTEBOOK, 'base64-binary-run'],
  ])('scan_file and scan_text on %s', async (rel, body, reason) => {
    const d = repo({ [rel]: body });
    dirs.push(d);
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: d }));
    try {
      const file = parse(await client.callTool({ name: 'scan_file', arguments: { file_path: rel } }));
      const fm = (file.json as Doc).results[0].matches[0];
      expect([fm.severity, (fm.demotion as { reason: string }).reason, (fm.demotion as { from: string }).from]).toEqual(['low', reason, 'critical']);
      expect(file.summary).toMatchObject({ total_matches: 1, demoted_matches: 1, match_groups: 0 });
      const text = parse(await client.callTool({ name: 'scan_text', arguments: { text: body } }));
      const tm = (text.json as Doc).results[0].matches[0];
      expect([tm.severity, (tm.demotion as { reason: string }).reason]).toEqual(['low', reason]);
      expect(text.summary).toMatchObject({ total_matches: 1, demoted_matches: 1, match_groups: 0 });
    } finally {
      await client.close();
    }
  });
});

describe('the planted cases (section 9.4, P1 and P2) through scan_workspace', () => {
  it('a key in one CSV cell and keys in text-typed data: URIs are critical, not demoted, not grouped', async () => {
    const tok = (r: number, c: number): string => seeded(30, 100000 + r * 16 + c).toString('base64');
    const p1 =
      ['c0,c1,c2,c3,c4,c5,c6,c7', ...Array.from({ length: 1000 }, (_, r) => Array.from({ length: 8 }, (_, c) => (c === 6 ? jwt(r) : r === 501 && c === 2 ? KEY : tok(r, c))).join(','))].join('\n') +
      '\n';
    const p2a = `<a href="data:text/html,<script>var k='${KEY}'</script>">x</a>\n`;
    const json = Buffer.from(JSON.stringify({ items: Array.from({ length: 80 }, (_, i) => ({ id: i, name: `item ${i}` })) })).toString('base64').replace(/=/g, '');
    const p2b = `<script src="data:application/json;base64,${json.slice(0, 1200)}${KEY}${json.slice(1200, 2400)}"></script>\n`;
    const d = repo({ 'data/p1.csv': p1, 'p2a.html': p2a, 'p2b.html': p2b });
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: d }));
    try {
      const res = parse(await client.callTool({ name: 'scan_workspace', arguments: { root: '.' } }));
      const doc = res.json as Doc;
      for (const f of ['data/p1.csv', 'p2a.html', 'p2b.html']) {
        const gcp = doc.results.find(r => r.file === f)?.matches.filter(m => m.type === 'gcp-api-key') ?? [];
        expect(gcp.map(m => [m.severity, m.demotion, m.group_id])).toEqual([['critical', undefined, undefined]]);
      }
      const p1Groups = (doc.results.find(r => r.file === 'data/p1.csv')?.groups ?? []) as Array<{ rule: string; members: number }>;
      expect(p1Groups.map(g => [g.rule, g.members])).toEqual([['jwt-token', 1000]]);
    } finally {
      await client.close();
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});

describe('U10: MCP summaries count matches, and state groups and demotions beside them', () => {
  it('a CSV column of 40 JWTs: total_matches 40, match_groups 1, every member a JSON match', async () => {
    const d = repo({ 'data/users.csv': CSV });
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: d }));
    try {
      for (const [name, args] of [
        ['scan_workspace', { root: '.' }],
        ['scan_file', { file_path: 'data/users.csv' }],
        ['scan_text', { text: CSV }],
      ] as const) {
        const res = parse(await client.callTool({ name, arguments: args }));
        expect(res.summary).toMatchObject({ total_matches: 40, match_groups: 1, demoted_matches: 0 });
        const doc = res.json as Doc;
        expect(doc.results[0].matches).toHaveLength(40);
        expect(doc.results[0].groups).toHaveLength(1);
        expect(doc.run).toMatchObject({ match_groups: 1, grouped_matches: 40, demoted_matches: 0 });
      }
    } finally {
      await client.close();
      fs.rmSync(d, { recursive: true, force: true });
    }
  });

  it('a clean workspace states the counts at zero', async () => {
    const d = repo({});
    const client = await connect(createMcpServer({ telemetryFactory: fakeStore, workspaceRoot: d }));
    try {
      const res = parse(await client.callTool({ name: 'scan_workspace', arguments: { root: '.' } }));
      expect(res.summary).toMatchObject({ total_matches: 0, demoted_matches: 0, match_groups: 0 });
      expect((res.json as Doc).run).toMatchObject({
        demoted_matches: 0,
        demoted_by_reason: { 'data-uri-binary-payload': 0, 'base64-binary-run': 0 },
        match_groups: 0,
        grouped_matches: 0,
      });
    } finally {
      await client.close();
      fs.rmSync(d, { recursive: true, force: true });
    }
  });
});
