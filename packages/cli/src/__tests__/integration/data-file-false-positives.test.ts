import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import {
  BINARY_TYPES,
  SecretScanner,
  applyBaseline,
  fingerprintForMatch,
  parseBaselineText,
  type FileScanResult,
} from '@vaultcompass/vault-guard-core';
import { baselineCommand } from '../../commands/baseline';
import { scanCommand } from '../../commands/scan';
import { capture, commitAll, git, initRepo, tmpDir, write } from './git-fixture';
import { seeded } from './binary-fixtures';
import { JPEG_HEAD, PNG_HEAD, alnum, csv, f17Svg, gcpKey, jwt, payload, runWithKey, token40 } from './data-file-fixtures';

/**
 * The 2026-10-17 data-file design, section 10.1: a key-shaped match inside
 * confirmed encoded media is demoted to low (never skipped), and repeats in
 * a data file are grouped for presentation only. Every fixture also holds a
 * clean src/ok.ts, so no row passes through "nothing was scanned".
 */

type Mode = 'plain' | 'trust-base' | 'staged';
type Json = {
  run: Record<string, unknown>;
  summary: { files: number; secrets: number };
  results: Array<{
    file: string;
    matches: Array<Record<string, unknown> & { type: string; severity: string; line: number; offset: number }>;
    groups?: Array<Record<string, unknown>>;
  }>;
  trustBase?: { proposals: string[]; attributesChanged?: boolean };
};

const KEY = gcpKey(3);
const itPosix = process.platform === 'win32' ? it.skip : it;

describe('data-file false positives: demotion and grouping', () => {
  const originalCwd = process.cwd();
  const dirs: string[] = [];

  afterEach(() => {
    process.chdir(originalCwd);
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function fresh(): string {
    const d = tmpDir('vg-data-');
    dirs.push(d);
    initRepo(d);
    write(d, 'src/ok.ts', 'export const ok = 1;\n');
    return d;
  }

  /** Plain and trust-base commit `files` on top of a tagged base; staged only stages them. */
  async function runMode(
    mode: Mode,
    files: Record<string, Buffer | string>,
    opts: { format?: 'json' | 'text' | 'sarif'; failOn?: string; base?: Record<string, string> } = {},
  ) {
    const d = fresh();
    for (const [rel, data] of Object.entries(opts.base ?? {})) write(d, rel, data);
    commitAll(d, 'base');
    git(d, ['tag', 'base']);
    for (const [rel, data] of Object.entries(files)) write(d, rel, data);
    if (mode === 'staged') git(d, ['add', '-A', '-f']);
    else commitAll(d, 'head');
    process.chdir(d);
    const format = opts.format ?? 'json';
    const r = await capture(() =>
      mode === 'staged'
        ? scanCommand('.', format, true, opts.failOn)
        : mode === 'trust-base'
          ? scanCommand('.', format, false, opts.failOn, 'base')
          : scanCommand('.', format, false, opts.failOn),
    );
    const doc = format === 'json' ? (JSON.parse(r.stdout) as Json) : (undefined as unknown as Json);
    return { ...r, dir: d, doc };
  }

  const matchesOf = (doc: Json, file?: string) =>
    doc.results.filter(r => file === undefined || r.file === file).flatMap(r => r.matches);
  const blockingOf = (doc: Json): number => {
    const rank: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
    const gate = rank[String(doc.run.fail_on)];
    return matchesOf(doc).filter(m => rank[m.severity] >= gate).length;
  };

  // -------------------------------------------------------------------------
  // Demotion fixtures
  // -------------------------------------------------------------------------

  describe('A1: one gcp-api-key in one cell of a 1000-row, 8-column CSV is critical, not demoted, not grouped', () => {
    const body = csv(1000, (r, c) => (c === 6 ? jwt(r) : r === 417 && c === 3 ? KEY : token40(r, c)));
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s', async mode => {
      const r = await runMode(mode, { 'data/p1.csv': body });
      expect(r.code).toBe(1);
      const gcp = matchesOf(r.doc).filter(m => m.type === 'gcp-api-key');
      expect(gcp).toHaveLength(1);
      expect(gcp[0].severity).toBe('critical');
      expect(gcp[0].demotion).toBeUndefined();
      expect(gcp[0].group_id).toBeUndefined();
      // The JWT column does group.
      expect(r.doc.run.match_groups).toBe(1);
      expect(r.doc.run.grouped_matches).toBe(1000);
      expect(r.doc.run.demoted_matches).toBe(0);
    });
  });

  describe('A2: a CSV column of 500 distinct JWTs is one grouped line, 500 matches, 500 blocking', () => {
    const body = csv(500, (r, c) => (c === 6 ? jwt(r) : `v${r}x${c}`));

    it('default gate: exit 1, one group of 500, 500 entries, blocking 500', async () => {
      const r = await runMode('plain', { 'data/users.csv': body });
      expect(r.code).toBe(1);
      expect(matchesOf(r.doc)).toHaveLength(500);
      expect(r.doc.summary.secrets).toBe(500);
      expect(r.doc.run.blocking_matches).toBe(500);
      expect(r.doc.run.match_groups).toBe(1);
      expect(r.doc.run.grouped_matches).toBe(500);
      const [g] = r.doc.results[0].groups ?? [];
      expect(g).toMatchObject({ rule: 'jwt-token', basis: 'column', delimiter: ',', column: 6, members: 500, distinct_values: 500, severity: 'high', demoted: false });
      for (const m of matchesOf(r.doc)) expect(m.group_id).toBe(g.group_id);
    });

    it('--fail-on critical: exit 0', async () => {
      const r = await runMode('plain', { 'data/users.csv': body }, { failOn: 'critical' });
      expect(r.code).toBe(0);
      expect(r.doc.run.blocking_matches).toBe(0);
    });

    it('U9: text prints one line naming column 7, 500 matches and five line numbers', async () => {
      const r = await runMode('plain', { 'data/users.csv': body }, { format: 'text' });
      expect(r.code).toBe(1);
      const lines = r.log.split('\n').filter(l => l.includes('jwt-token'));
      expect(lines).toHaveLength(1);
      expect(lines[0]).toContain('data/users.csv:2:');
      expect(lines[0]).toContain('and 499 more in column 7 of this delimited file (500 matches, 500 distinct values; lines 2, 3, 4, 5, 6, ...)');
      expect(r.log).toContain('Found 500 secrets (500 of them in 1 group)');
      expect(r.log).toContain('Grouped findings show their first 5 lines; --format json lists every match.');
      expect(r.log).not.toContain('were demoted to low');
    });

    it('U8: SARIF has one result per match, group properties, and partialFingerprints equal to the JSON fingerprints', async () => {
      const j = await runMode('plain', { 'data/users.csv': body });
      process.chdir(j.dir);
      const s = await capture(() => scanCommand('.', 'sarif'));
      const sarif = JSON.parse(s.stdout);
      const results = sarif.runs[0].results as Array<{ partialFingerprints: Record<string, string>; properties: Record<string, unknown> }>;
      expect(results).toHaveLength(500);
      const jm = matchesOf(j.doc);
      results.forEach((res, i) => {
        expect(res.partialFingerprints['vault-guard/v1']).toBe(jm[i].fingerprint);
        expect(res.partialFingerprints['vault-guard/v2']).toBe(jm[i].content_fingerprint);
        expect(res.properties['vault-guard/group']).toBe(jm[i].group_id);
        expect(res.properties['vault-guard/group_size']).toBe(500);
      });
      const props = sarif.runs[0].properties.vault_guard_run;
      for (const k of ['demoted_matches', 'demoted_by_reason', 'match_groups', 'grouped_matches']) expect(props[k]).toEqual(j.doc.run[k]);
    });

    it('U7: blocking_matches equals the matches at or above run.fail_on', async () => {
      const r = await runMode('plain', { 'data/users.csv': body });
      expect(r.doc.run.blocking_matches).toBe(blockingOf(r.doc));
    });
  });

  describe('A3: a demoted group never hides a critical key in the same column', () => {
    const body = csv(
      30,
      (r, c) => (c !== 2 ? `r${r}c${c}` : r < 6 ? runWithKey(PNG_HEAD, 2048, gcpKey(40 + r)) : r === 6 ? KEY : 'none'),
      3,
    );

    it('one low demoted group of 6 and the critical key on its own line; exit 1', async () => {
      const r = await runMode('plain', { 'data/mixed.csv': body });
      expect(r.code).toBe(1);
      const groups = r.doc.results[0].groups ?? [];
      expect(groups).toHaveLength(1);
      expect(groups[0]).toMatchObject({ members: 6, severity: 'low', demoted: true, column: 2 });
      const crit = matchesOf(r.doc).filter(m => m.severity === 'critical');
      expect(crit).toHaveLength(1);
      expect(crit[0].group_id).toBeUndefined();
      expect(crit[0].line).toBe(8);
      expect(r.doc.run.blocking_matches).toBe(blockingOf(r.doc));
      expect(r.doc.run.blocking_matches).toBe(1);
    });

    it('text: two lines in the column, the group and the critical key', async () => {
      const r = await runMode('plain', { 'data/mixed.csv': body }, { format: 'text' });
      const lines = r.log.split('\n').filter(l => l.includes('gcp-api-key'));
      expect(lines).toHaveLength(2);
      expect(lines[0]).toMatch(/ low {2}gcp-api-key .*and 5 more in column 3/);
      expect(lines[1]).toMatch(/data\/mixed\.csv:8:\d+ {2}critical {2}gcp-api-key/);
    });
  });

  describe('A4: the F17 shape, a one-line 800 KB SVG with an AIza run in its PNG payload', () => {
    const svg = f17Svg(KEY);

    it('default gate: exit 0, the finding at low with the record', async () => {
      const r = await runMode('plain', { 'assets/logo.svg': svg });
      expect(r.code).toBe(0);
      const [m] = matchesOf(r.doc);
      expect(m.type).toBe('gcp-api-key');
      expect(m.severity).toBe('low');
      expect(m.demotion).toMatchObject({ from: 'critical', reason: 'data-uri-binary-payload', media_type: 'image/png', family: 'image', format: '.png' });
      expect(r.doc.run.demoted_matches).toBe(1);
      expect(r.doc.run.demoted_by_reason).toEqual({ 'data-uri-binary-payload': 1, 'base64-binary-run': 0 });
      expect(r.doc.run.blocking_matches).toBe(0);
      expect(r.doc.run.blocking_matches).toBe(blockingOf(r.doc));
    });

    it('--fail-on low: exit 1', async () => {
      const r = await runMode('plain', { 'assets/logo.svg': svg }, { failOn: 'low' });
      expect(r.code).toBe(1);
      expect(r.doc.run.blocking_matches).toBe(1);
    });

    it('U9: text prints the reason and the note', async () => {
      const r = await runMode('plain', { 'assets/logo.svg': svg }, { format: 'text' });
      const len = svg.length - svg.indexOf('base64,') - 'base64,'.length - '"/></svg>\n'.length;
      expect(r.log).toContain(`(demoted from critical: inside an ${len}-character data:image/png;base64 payload that decodes to a png image)`);
      expect(r.log).toContain('1 finding(s) were demoted to low because they sit inside encoded media; --fail-on low blocks on them.');
    });

    it('U8: partialFingerprints are the 1.11.0 formulas', async () => {
      const j = await runMode('plain', { 'assets/logo.svg': svg });
      const [m] = matchesOf(j.doc);
      const v1 = createHash('sha256').update(`assets/logo.svg|gcp-api-key|1|${m.offset}|${KEY.length}`, 'utf8').digest('hex');
      expect(m.fingerprint).toBe(v1);
      const digest = createHash('sha256').update(KEY, 'utf8').digest('hex');
      const v2 = createHash('sha256').update(`vg-fp-v2\0assets/logo.svg\0gcp-api-key\0${digest}`, 'utf8').digest('hex');
      expect(m.content_fingerprint).toBe(v2);
      process.chdir(j.dir);
      const s = JSON.parse((await capture(() => scanCommand('.', 'sarif'))).stdout);
      expect(s.runs[0].results[0].partialFingerprints).toEqual({ 'vault-guard/v1': v1, 'vault-guard/v2': v2 });
      expect(s.runs[0].results[0].level).toBe('note');
      expect(s.runs[0].results[0].properties).toMatchObject({ 'vault-guard/demoted_from': 'critical', 'vault-guard/demotion_reason': 'data-uri-binary-payload' });
    });
  });

  describe('A5: a key in a plaintext data:text/html URI keeps critical', () => {
    it('critical, no demotion', async () => {
      const r = await runMode('plain', { 'page.html': `<a href="data:text/html,<script>var k='${KEY}'</script>">x</a>\n` });
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('critical');
      expect(m.demotion).toBeUndefined();
    });
  });

  describe('A6: a key pasted raw into a data:application/json;base64 payload keeps critical', () => {
    it('critical, no demotion', async () => {
      const json = JSON.stringify({ items: Array.from({ length: 60 }, (_, i) => ({ id: i, name: `item number ${i}` })) });
      const b64 = Buffer.from(json).toString('base64').replace(/=/g, '').slice(0, 2048);
      const run = b64.slice(0, 1000) + KEY + b64.slice(1000);
      const r = await runMode('plain', { 'page.html': `<script src="data:application/json;base64,${run}"></script>\n` });
      expect(run.length).toBeGreaterThan(1024);
      const [m] = matchesOf(r.doc).filter(x => x.type === 'gcp-api-key');
      expect(m.severity).toBe('critical');
      expect(m.demotion).toBeUndefined();
    });
  });

  describe('A7: data:image/png declared over a payload that decodes to ASCII text keeps critical', () => {
    it('critical', async () => {
      const text = Buffer.from('lorem ipsum dolor sit amet '.repeat(80)).toString('base64').replace(/=/g, '').slice(0, 2048);
      const run = text.slice(0, 1000) + KEY + text.slice(1000);
      const r = await runMode('plain', { 'page.html': `<img src="data:image/png;base64,${run}">\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
  });

  describe('A8: a data:image/svg+xml;base64 payload is never demoted', () => {
    it('critical', async () => {
      const svgText = `<svg xmlns="http://www.w3.org/2000/svg">${'<rect x="1" y="2" width="3" height="4"/>'.repeat(80)}</svg>`;
      const b64 = Buffer.from(svgText).toString('base64').replace(/=/g, '').slice(0, 4096);
      const run = b64.slice(0, 2000) + KEY + b64.slice(2000);
      const r = await runMode('plain', { 'page.css': `.a{background:url("data:image/svg+xml;base64,${run}")}\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
  });

  describe('A9: a key flush against the end of a PNG payload keeps critical', () => {
    it('against the closing quote, and against == padding', async () => {
      const p = payload(PNG_HEAD, 2048);
      const r = await runMode('plain', {
        'a.html': `<img src="data:image/png;base64,${p}${KEY}">\n`,
        'b.html': `<img src="data:image/png;base64,${p}${gcpKey(4)}==">\n`,
      });
      const ms = matchesOf(r.doc);
      expect(ms).toHaveLength(2);
      for (const m of ms) {
        expect(m.severity).toBe('critical');
        expect(m.demotion).toBeUndefined();
      }
    });
  });

  describe('A10: a notebook-shaped bare PNG run is demoted under any name', () => {
    const nb = JSON.stringify({ cells: [{ outputs: [{ data: { 'image/png': runWithKey(PNG_HEAD, 50 * 1024, KEY), 'text/plain': ['<Figure>'] } }] }] }) + '\n';
    it.each(['plot.ipynb', 'plot.json', 'plot.txt'])('%s: low, base64-binary-run, .png', async name => {
      const r = await runMode('plain', { [name]: nb });
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('low');
      expect(m.demotion).toMatchObject({ from: 'critical', reason: 'base64-binary-run', format: '.png', family: 'image' });
      expect(m.demotion).not.toHaveProperty('media_type');
    });
  });

  describe('A11: a bare run of seeded random bytes keeps critical', () => {
    it('critical, and the seed is checked to carry no table signature', async () => {
      const head = seeded(16, 0x5eed1);
      for (const row of BINARY_TYPES.values()) {
        for (const sig of row.signatures) {
          const hit = sig.every(p => p.bytes.every((x, i) => head[p.offset + i] === x));
          expect(hit).toBe(false);
        }
      }
      const r = await runMode('plain', { 'blob.json': `{"payload":"${runWithKey(head, 8192, KEY, undefined, 0x5eed2)}"}\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
  });

  describe('A11b: bare runs with two-byte media signatures keep critical', () => {
    it.each([
      ['an MP3 frame sync', [0xff, 0xfb]],
      ['an AAC header F1', [0xff, 0xf1]],
      ['an AAC header F9', [0xff, 0xf9]],
      ['a gzip header', [0x1f, 0x8b]],
    ])('%s', async (_name, sig) => {
      const r = await runMode('plain', { 'blob.json': `{"payload":"${runWithKey(Buffer.from(sig), 4096, KEY)}"}\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
  });

  describe('A12: printable signatures confirm only under a declared type', () => {
    const gif = Buffer.concat([Buffer.from('GIF89a'), Buffer.from([0x10, 0x00, 0x10, 0x00, 0xf7, 0x00, 0x00])]);
    const pdf = Buffer.concat([Buffer.from('%PDF-1.4\n%'), Buffer.from([0xe2, 0xe3, 0xcf, 0xd3, 0x0a, 0x01, 0x02])]);
    it.each([
      ['GIF89a', gif],
      ['%PDF-', pdf],
    ])('bare %s run: critical', async (_n, head) => {
      const r = await runMode('plain', { 'blob.json': `{"payload":"${runWithKey(head, 4096, KEY)}"}\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
    it.each([
      ['image/gif', gif, '.gif'],
      ['application/pdf', pdf, '.pdf'],
    ])('A12b: data:%s;base64 with the same payload: low', async (type, head, format) => {
      const r = await runMode('plain', { 'page.html': `<embed src="data:${type};base64,${runWithKey(head, 4096, KEY)}">\n` });
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('low');
      expect(m.demotion).toMatchObject({ reason: 'data-uri-binary-payload', media_type: type, format });
    });
  });

  describe('A13: the run length boundary', () => {
    it('1023 characters: critical; 1024: low', async () => {
      const r = await runMode('plain', {
        'a.html': `<img src="data:image/png;base64,${runWithKey(PNG_HEAD, 1023, KEY)}">\n`,
        'b.html': `<img src="data:image/png;base64,${runWithKey(PNG_HEAD, 1024, gcpKey(4))}">\n`,
      });
      expect(matchesOf(r.doc, 'a.html')[0].severity).toBe('critical');
      const b = matchesOf(r.doc, 'b.html')[0];
      expect(b.severity).toBe('low');
      expect((b.demotion as { run_length: number }).run_length).toBe(1024);
    });
  });

  describe('A14: a run mixing + and _ is not decoded', () => {
    it('critical', async () => {
      const run = runWithKey(PNG_HEAD, 4096, KEY);
      expect(/[+/]/.test(run)).toBe(true);
      const mixed = run.slice(0, 3000) + '_' + run.slice(3001);
      expect(mixed.includes(KEY)).toBe(true);
      const r = await runMode('plain', { 'page.html': `<img src="data:image/png;base64,${mixed}">\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
  });

  describe('A26: a JPEG under a declared image/png type keeps critical', () => {
    it('critical', async () => {
      const r = await runMode('plain', { 'page.html': `<img src="data:image/png;base64,${runWithKey(JPEG_HEAD, 4096, KEY)}">\n` });
      expect(matchesOf(r.doc)[0].severity).toBe('critical');
    });
  });

  describe('A28: data: URIs with parameters and in upper case', () => {
    it.each(['data:image/png;name=logo.png;base64,', 'data:image/png;charset=binary;base64,', 'DATA:IMAGE/PNG;BASE64,'])('%s: low, media_type image/png', async prefix => {
      const r = await runMode('plain', { 'page.html': `<img src="${prefix}${runWithKey(PNG_HEAD, 4096, KEY)}">\n` });
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('low');
      expect((m.demotion as { media_type: string }).media_type).toBe('image/png');
    });
  });

  describe('A17: --trust-base, head control files cannot steer the demotion', () => {
    it('same demotion as A4, proposals listed, exit 0 under the base default gate', async () => {
      const r = await runMode('trust-base', {
        'assets/logo.svg': f17Svg(KEY, 64 * 1024),
        '.vault-guard.json': JSON.stringify({ severity_overrides: { 'gcp-api-key': 'critical' }, content_demotion: false }) + '\n',
        '.gitattributes': '*.svg -text\n',
      });
      expect(r.code).toBe(0);
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('low');
      expect((m.demotion as { reason: string }).reason).toBe('data-uri-binary-payload');
      expect(r.doc.trustBase?.proposals.length).toBeGreaterThanOrEqual(2);
      expect(r.doc.trustBase?.attributesChanged).toBe(true);
    });
  });

  describe('A21: a no-op demotion is not recorded, and the path changes nothing', () => {
    it('override to low: low, no record, demoted_matches 0', async () => {
      const r = await runMode('plain', {
        'assets/logo.svg': f17Svg(KEY, 64 * 1024),
        '.vault-guard.json': JSON.stringify({ severity_overrides: { 'gcp-api-key': 'low' } }) + '\n',
      });
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('low');
      expect(m.demotion).toBeUndefined();
      expect(r.doc.run.demoted_matches).toBe(0);
    });

    it('the SVG under docs/: low with the record, as in A4', async () => {
      const r = await runMode('plain', { 'docs/logo.svg': f17Svg(KEY, 64 * 1024) });
      const [m] = matchesOf(r.doc);
      expect(m.severity).toBe('low');
      expect(m.demotion).toMatchObject({ from: 'critical', reason: 'data-uri-binary-payload' });
    });
  });

  describe('A22: every CLI mode gives the same severity and record on A4 and A10', () => {
    const files = {
      'assets/logo.svg': f17Svg(KEY, 64 * 1024),
      'nb/plot.ipynb': JSON.stringify({ outputs: [{ data: { 'image/png': runWithKey(PNG_HEAD, 8192, gcpKey(5)) } }] }) + '\n',
    };
    const shape = (doc: Json) =>
      doc.results
        .map(r => r.matches.map(m => [r.file, m.type, m.severity, (m.demotion as { reason: string } | undefined)?.reason]))
        .flat()
        .sort();
    const expected = [
      ['assets/logo.svg', 'gcp-api-key', 'low', 'data-uri-binary-payload'],
      ['nb/plot.ipynb', 'gcp-api-key', 'low', 'base64-binary-run'],
    ];
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s', async mode => {
      const r = await runMode(mode, files);
      expect(shape(r.doc)).toEqual(expected);
    });
    it('a named target', async () => {
      const d = fresh();
      for (const [rel, data] of Object.entries(files)) write(d, rel, data);
      commitAll(d, 'init');
      process.chdir(d);
      const r = await capture(() => scanCommand(['assets/logo.svg', 'nb/plot.ipynb', 'src/ok.ts'], 'json'));
      expect(shape(JSON.parse(r.stdout) as Json)).toEqual(expected);
    });
  });

  describe('A24: an inline directive on a payload line tallies the rule severity', () => {
    it('inline_suppressed 1, inline_suppressed_critical_vendor 1', async () => {
      const svg = f17Svg(KEY, 64 * 1024).replace('</svg>\n', '</svg> <!-- vault-guard: ignore-line -->\n');
      const r = await runMode('plain', { 'assets/logo.svg': svg });
      expect(r.doc.run.inline_suppressed).toBe(1);
      expect(r.doc.run.inline_suppressed_critical_vendor).toBe(1);
      expect(matchesOf(r.doc)).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Grouping fixtures
  // -------------------------------------------------------------------------

  describe('A18: the data-file trigger is content, never the name', () => {
    const body = csv(30, (r, c) => (c === 6 ? jwt(r) : `v${r}x${c}`));
    const varied =
      Array.from({ length: 30 }, (_, i) => Array.from({ length: 2 + (i % 4) }, (_, c) => (c === 1 && i % 5 === 0 ? jwt(i) : `f${c}`)).join(',')).join('\n') + '\n';
    it('data.txt and data group, rows.csv does not', async () => {
      const r = await runMode('plain', { 'data.txt': body, data: body, 'rows.csv': varied });
      const by = (f: string) => r.doc.results.find(x => x.file === f);
      expect(by('data.txt')?.groups).toHaveLength(1);
      expect(by('data')?.groups).toHaveLength(1);
      expect(by('rows.csv')?.groups).toBeUndefined();
      expect(by('rows.csv')?.matches).toHaveLength(6);
    });
  });

  describe('A19: one 200 KB minified JSON line with 30 JWTs is one long-line group', () => {
    it('basis long-line, 30 members', async () => {
      const rows = Array.from({ length: 30 }, (_, i) => ({ t: jwt(i), pad: alnum(6000, 900 + i) }));
      const r = await runMode('plain', { 'dump.json': JSON.stringify({ rows }) + '\n' });
      const g = r.doc.results[0].groups ?? [];
      expect(g).toHaveLength(1);
      expect(g[0]).toMatchObject({ basis: 'long-line', members: 30 });
      expect(g[0]).not.toHaveProperty('column');
    });
  });

  describe('A20: quoted CSV fields with embedded commas and doubled quotes', () => {
    it('one group in column 3', async () => {
      const body = Array.from({ length: 30 }, (_, i) => `${i},"Smith, John","said ""hi"", ok",${jwt(i)},x`).join('\n') + '\n';
      const r = await runMode('plain', { 'people.csv': body });
      const g = r.doc.results[0].groups ?? [];
      expect(g).toHaveLength(1);
      expect(g[0]).toMatchObject({ column: 3, members: 30 });
    });
  });

  describe('A27: code that looks delimited is not a data file', () => {
    const ts = Array.from({ length: 100 }, (_, i) => (i % 16 === 3 && i < 90 ? `const t${i} = "${jwt(i)}";` : `const v${i} = ${i};`)).join('\n') + '\n';
    const mk =
      Array.from({ length: 100 }, (_, i) => (i % 10 === 0 ? `target${i}:` : i % 16 === 5 ? `\tcurl -H "Authorization: x" ${jwt(i)}` : `\techo step ${i}`)).join('\n') + '\n';
    it('a TypeScript file whose lines end in one ; and a tab-indented Makefile: six single findings each', async () => {
      const r = await runMode('plain', { 'src/tokens.ts': ts, Makefile: mk });
      for (const f of ['src/tokens.ts', 'Makefile']) {
        const e = r.doc.results.find(x => x.file === f);
        expect(e?.matches).toHaveLength(6);
        expect(e?.groups).toBeUndefined();
      }
      expect(r.doc.run.match_groups).toBe(0);
    });
  });

  describe('A29: an empty first field is ordinary data under the comma', () => {
    it('one group of 30 in column 2', async () => {
      const body = Array.from({ length: 30 }, (_, i) => `${i < 25 ? '' : `id${i}`},cat,${jwt(i)},x`).join('\n') + '\n';
      const r = await runMode('plain', { 'sparse.csv': body });
      const g = r.doc.results[0].groups ?? [];
      expect(g).toHaveLength(1);
      expect(g[0]).toMatchObject({ column: 2, members: 30 });
    });
  });

  describe('U6: group_id does not move with the display root', () => {
    it('scan data from the root and scan . from data/ give the same id', async () => {
      const d = fresh();
      write(d, 'data/users.csv', csv(30, (r, c) => (c === 6 ? jwt(r) : `v${r}x${c}`)));
      commitAll(d, 'init');
      process.chdir(d);
      const a = JSON.parse((await capture(() => scanCommand('data', 'json'))).stdout) as Json;
      process.chdir(path.join(d, 'data'));
      const b = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout) as Json;
      const ga = a.results[0].groups?.[0];
      const gb = b.results[0].groups?.[0];
      expect(ga?.group_id).toBeDefined();
      expect(gb?.group_id).toBe(ga?.group_id);
      expect(gb?.members_digest).toBe(ga?.members_digest);
    });
  });

  // -------------------------------------------------------------------------
  // Baseline interactions
  // -------------------------------------------------------------------------

  describe('A15: a baselined column reports a new value on its own', () => {
    const rows = (n: number): string => csv(n, (r, c) => (c === 6 ? jwt(r) : `v${r}x${c}`));

    async function baselined(): Promise<string> {
      const d = fresh();
      write(d, 'data/users.csv', rows(20));
      commitAll(d, 'init');
      process.chdir(d);
      const w = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
      expect(w.code).toBe(0);
      const doc = parseBaselineText(fs.readFileSync(path.join(d, '.vault-guard.baseline.json'), 'utf-8'));
      expect(doc.entries).toHaveLength(20);
      commitAll(d, 'baseline');
      git(d, ['tag', 'base']);
      write(d, 'data/users.csv', rows(21));
      commitAll(d, 'one more row');
      return d;
    }

    it.each(['plain', 'trust-base'] as const)('%s: exit 1, one match, not grouped, baseline_suppressed 20', async mode => {
      await baselined();
      const r = await capture(() => (mode === 'plain' ? scanCommand('.', 'json') : scanCommand('.', 'json', false, undefined, 'base')));
      const doc = JSON.parse(r.stdout) as Json;
      expect(r.code).toBe(1);
      expect(matchesOf(doc)).toHaveLength(1);
      expect(matchesOf(doc)[0].group_id).toBeUndefined();
      expect(doc.run.match_groups).toBe(0);
      expect(doc.run.baseline_suppressed).toBe(20);
    });

    it('A15b: a group_id hand-added to entries suppresses nothing', async () => {
      const d = fresh();
      write(d, 'data/users.csv', rows(21));
      commitAll(d, 'init');
      process.chdir(d);
      const first = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout) as Json;
      const gid = String(first.results[0].groups?.[0].group_id);
      write(
        d,
        '.vault-guard.baseline.json',
        JSON.stringify({ version: 1, fingerprints: [gid], entries: [{ fingerprint: gid, rule: 'jwt-token', file: 'data/users.csv', line: 2, severity: 'high', count: 21 }] }),
      );
      commitAll(d, 'baseline by group id');
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = JSON.parse(r.stdout) as Json;
      expect(r.code).toBe(1);
      expect(doc.run.baseline_suppressed ?? 0).toBe(0);
      expect(matchesOf(doc)).toHaveLength(21);
    });
  });

  describe('A16: a demotion cannot be laundered through the baseline', () => {
    /** A repository with a demoted critical key in logo.svg and fail_on low in its config. */
    function demotedRepo(): { d: string; svg: string } {
      const d = fresh();
      const svg = f17Svg(KEY, 64 * 1024);
      write(d, 'assets/logo.svg', svg);
      write(d, '.vault-guard.json', JSON.stringify({ fail_on: 'low' }) + '\n');
      commitAll(d, 'init');
      process.chdir(d);
      return { d, svg };
    }
    const baselineFile = (d: string) => parseBaselineText(fs.readFileSync(path.join(d, '.vault-guard.baseline.json'), 'utf-8'));

    it('(a) without --include-critical the demoted critical is refused and nothing is accepted', async () => {
      const { d } = demotedRepo();
      const w = await capture(() => baselineCommand('.', { write: true, includeCritical: false }));
      expect(w.code).toBe(1);
      expect(w.log).toMatch(/not accepted: critical.*assets\/logo\.svg:1 gcp-api-key/);
      const doc = baselineFile(d);
      expect(doc.entries).toEqual([]);
      expect(doc.fingerprints.size).toBe(0);
    });

    it('(b) with --include-critical: one entries record at low, absent from fingerprints; once C4 fails, no reader suppresses it', async () => {
      const { d, svg } = demotedRepo();
      const before = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout) as Json;
      const [demotedMatch] = matchesOf(before);
      expect(demotedMatch.severity).toBe('low');
      const w = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
      expect(w.code).toBe(0);
      const doc = baselineFile(d);
      expect(doc.entries).toHaveLength(1);
      expect(doc.entries?.[0]).toMatchObject({ rule: 'gcp-api-key', severity: 'low', count: 1 });
      expect(doc.fingerprints.has(String(demotedMatch.fingerprint))).toBe(false);
      expect(doc.fingerprints.size).toBe(0);

      // Replace the PNG header with other base64 of the same length: C4 fails,
      // every offset and the key bytes are unchanged.
      const at = svg.indexOf('base64,') + 'base64,'.length;
      const broken = svg.slice(0, at) + 'qZ8xT2mK9vB1' + svg.slice(at + 12);
      write(d, 'assets/logo.svg', broken);
      commitAll(d, 'baseline, then a broken header');

      // The 1.12.0 reader with entries.
      const r = await capture(() => scanCommand('.', 'json'));
      const after = JSON.parse(r.stdout) as Json;
      expect(r.code).toBe(1);
      const [m] = matchesOf(after);
      expect(m.severity).toBe('critical');
      expect(m.demotion).toBeUndefined();
      expect(m.offset).toBe(demotedMatch.offset);
      expect(after.run.baseline_suppressed ?? 0).toBe(0);

      // The legacy reader on the same file with entries removed (the 1.9.x path).
      const file = path.join(d, 'assets', 'logo.svg');
      const scanned: FileScanResult[] = [{ file, matches: new SecretScanner().scanContent(broken, { filePath: file }) }];
      expect(scanned[0].matches[0].severity).toBe('critical');
      expect(fingerprintForMatch(d, file, scanned[0].matches[0])).toBe(demotedMatch.fingerprint);
      const legacy = applyBaseline(scanned, { fingerprints: doc.fingerprints, entries: null }, { anchor: d, contentRoot: d, isValueBearing: () => true });
      expect(legacy.suppressed).toBe(0);
      expect(legacy.results[0].matches[0].severity).toBe('critical');

      // The published 1.9.1 CLI, when CI provides it.
      const old = process.env.VG_CLI_191;
      if (old && fs.existsSync(old)) {
        const { spawnSync } = await import('child_process');
        const res = spawnSync(process.execPath, [old, 'scan', '.', '--format', 'json'], { cwd: d, encoding: 'utf-8' });
        expect(res.status).toBe(1);
        const oldDoc = JSON.parse(res.stdout) as Json;
        expect(matchesOf(oldDoc).map(x => x.severity)).toEqual(['critical']);
      }
    });
  });

  // -------------------------------------------------------------------------
  // Merging copies (U14)
  // -------------------------------------------------------------------------

  describe('U14: the merge keeps the copy that holds the value at the higher severity', () => {
    itPosix('blob demoted, disk header replaced in an unstaged edit: critical from the worktree', async () => {
      const d = fresh();
      const svg = f17Svg(KEY, 64 * 1024);
      write(d, 'assets/logo.svg', svg);
      commitAll(d, 'init');
      const at = svg.indexOf('base64,') + 'base64,'.length;
      write(d, 'assets/logo.svg', svg.slice(0, at) + 'qZ8xT2mK9vB1' + svg.slice(at + 12));
      process.chdir(d);
      const doc = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout) as Json;
      const ms = matchesOf(doc);
      expect(ms.map(m => [m.severity, m.source])).toEqual([['critical', 'worktree']]);
    });

    itPosix('blob critical, disk demoted: critical from the index', async () => {
      const d = fresh();
      const svg = f17Svg(KEY, 64 * 1024);
      const at = svg.indexOf('base64,') + 'base64,'.length;
      write(d, 'assets/logo.svg', svg.slice(0, at) + 'qZ8xT2mK9vB1' + svg.slice(at + 12));
      commitAll(d, 'init');
      write(d, 'assets/logo.svg', svg);
      process.chdir(d);
      const doc = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout) as Json;
      expect(matchesOf(doc).map(m => [m.severity, m.source])).toEqual([['critical', 'index']]);
    });

    itPosix('equal severities keep the blob copy', async () => {
      const d = fresh();
      write(d, 'k.ts', `export const k = "${KEY}";\n`);
      commitAll(d, 'init');
      write(d, 'k.ts', `// moved\nexport const k = "${KEY}";\n`);
      process.chdir(d);
      const doc = JSON.parse((await capture(() => scanCommand('.', 'json'))).stdout) as Json;
      expect(matchesOf(doc).map(m => [m.severity, m.source])).toEqual([['critical', 'index']]);
    });
  });
});
