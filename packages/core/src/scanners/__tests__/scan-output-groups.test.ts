import { createHash } from 'crypto';
import path from 'path';

import { contentRunCounts, demotionText, formGroups, formatJson, formatSarif, type FileScanResult } from '../../scan-output';
import { contentFingerprint, rootPositionalFingerprint } from '../../match-fingerprint';
import type { SecretMatch } from '../../types';

/**
 * Grouping as presentation (design 2026-10-17 data files, sections 5 and 8):
 * formGroups is a pure function of the post-baseline results, every member
 * stays a match, and the output fields are stated even at zero.
 */

const ROOT = path.resolve('/repo');
const FILE = path.join(ROOT, 'data', 'users.csv');
const SLOT = { basis: 'column' as const, delimiter: ',', column: 6 };

function member(i: number, extra: Partial<SecretMatch> = {}): SecretMatch {
  return {
    type: 'jwt-token',
    value: 'eyJh(120c)',
    line: i + 2,
    column: 40,
    offset: 1000 + i * 200,
    matchLength: 120,
    severity: 'high',
    valueDigest: `digest${i}`,
    source: 'index',
    groupSlot: SLOT,
    ...extra,
  };
}

const sha = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex');

describe('formGroups', () => {
  it('five members with one key form a group; four do not', () => {
    const four: FileScanResult[] = [{ file: FILE, matches: [0, 1, 2, 3].map(i => member(i)) }];
    expect(formGroups(four, { contentRoot: ROOT }).byFile[0]).toEqual([]);
    const five: FileScanResult[] = [{ file: FILE, matches: [0, 1, 2, 3, 4].map(i => member(i)) }];
    const g = formGroups(five, { contentRoot: ROOT }).byFile[0];
    expect(g).toHaveLength(1);
    expect(g[0]).toMatchObject({
      rule: 'jwt-token',
      basis: 'column',
      delimiter: ',',
      column: 6,
      source: 'index',
      members: 5,
      distinct_values: 5,
      severity: 'high',
      demoted: false,
    });
    expect(g[0].first).toEqual([2, 3, 4, 5, 6].map(line => ({ line, column: 40 })));
  });

  it('a match with no slot is never a member', () => {
    const r: FileScanResult[] = [{ file: FILE, matches: [0, 1, 2, 3, 4].map(i => member(i, i === 0 ? { groupSlot: undefined } : {})) }];
    expect(formGroups(r, { contentRoot: ROOT }).byFile[0]).toEqual([]);
  });

  it('severity, demotion status, column, source and stage are all part of the key', () => {
    const variants: Array<Partial<SecretMatch>> = [
      { severity: 'critical' },
      { demotion: { from: 'high', reason: 'base64-binary-run', family: 'image', format: '.png', run_length: 2000 }, severity: 'low' },
      { groupSlot: { basis: 'column', delimiter: ',', column: 7 } },
      { groupSlot: { basis: 'long-line' } },
      { source: 'worktree' },
      { stage: 3 },
    ];
    for (const v of variants) {
      const ms = [0, 1, 2, 3, 4].map(i => member(i, i === 4 ? v : {}));
      expect(formGroups([{ file: FILE, matches: ms }], { contentRoot: ROOT }).byFile[0]).toEqual([]);
    }
  });

  it('distinct_values counts digests, and members with no digest count once each', () => {
    const same = [0, 1, 2, 3, 4, 5].map(i => member(i, { valueDigest: i < 3 ? 'a' : 'b' }));
    expect(formGroups([{ file: FILE, matches: same }], { contentRoot: ROOT }).byFile[0][0].distinct_values).toBe(2);
    const none = [0, 1, 2, 3, 4].map(i => member(i, { valueDigest: undefined }));
    expect(formGroups([{ file: FILE, matches: none }], { contentRoot: ROOT }).byFile[0][0].distinct_values).toBe(5);
  });

  it('U6: group_id and members_digest follow the formulas', () => {
    const ms = [0, 1, 2, 3, 4].map(i => member(i));
    const [g] = formGroups([{ file: FILE, matches: ms }], { contentRoot: ROOT }).byFile[0];
    expect(g.group_id).toBe(sha(['vg-group-v1', 'data/users.csv', 'jwt-token', 'high', 'false', 'column:,:6', 'index', ''].join('\0')));
    const keys = ms.map(m => contentFingerprint('data/users.csv', 'jwt-token', m.valueDigest!)).sort();
    expect(g.members_digest).toBe(sha(keys.join('\0')));
    // A header-only member is keyed by its root-relative positional fingerprint.
    const header = [0, 1, 2, 3, 4].map(i => member(i, { valueDigest: undefined, type: 'x-rule' }));
    const [h] = formGroups([{ file: FILE, matches: header }], { contentRoot: ROOT }).byFile[0];
    const hk = header.map(m => rootPositionalFingerprint(ROOT, FILE, m)).sort();
    expect(h.members_digest).toBe(sha(hk.join('\0')));
  });

  it('group_id does not move with the display root, and members_digest moves with any member', () => {
    const ms = [0, 1, 2, 3, 4].map(i => member(i));
    const a = formGroups([{ file: FILE, matches: ms }], { contentRoot: ROOT }).byFile[0][0];
    const rel = formGroups([{ file: FILE, matches: ms }], { contentRoot: ROOT }).byFile[0][0];
    expect(rel.group_id).toBe(a.group_id);
    const changed = formGroups([{ file: FILE, matches: [...ms.slice(0, 4), member(4, { valueDigest: 'other' })] }], { contentRoot: ROOT }).byFile[0][0];
    expect(changed.group_id).toBe(a.group_id);
    expect(changed.members_digest).not.toBe(a.members_digest);
  });
});

describe('JSON and SARIF fields', () => {
  const run = { duration_ms: 1, files_scanned: 1, bytes_scanned: 1, patterns_active: 1 };
  const demotion = { from: 'critical' as const, reason: 'data-uri-binary-payload' as const, family: 'image', format: '.png', media_type: 'image/png', run_length: 4096 };
  const results = (): FileScanResult[] => [
    { file: FILE, matches: [0, 1, 2, 3, 4].map(i => member(i)) },
    { file: path.join(ROOT, 'logo.svg'), matches: [{ ...member(9, { type: 'gcp-api-key', severity: 'low', groupSlot: undefined }), demotion }] },
  ];

  it('U8: the four run fields are present at zero on a tree with no demotion and no group', () => {
    const doc = JSON.parse(formatJson([], { cwd: ROOT, run }));
    expect(doc.run).toMatchObject({
      demoted_matches: 0,
      demoted_by_reason: { 'data-uri-binary-payload': 0, 'base64-binary-run': 0 },
      match_groups: 0,
      grouped_matches: 0,
    });
    const sarif = JSON.parse(formatSarif([], { cwd: ROOT, run }));
    expect(sarif.runs[0].properties.vault_guard_run).toMatchObject({
      demoted_matches: 0,
      demoted_by_reason: { 'data-uri-binary-payload': 0, 'base64-binary-run': 0 },
      match_groups: 0,
      grouped_matches: 0,
    });
  });

  it('JSON carries demotion and group_id per match, groups per file, and the counts', () => {
    const doc = JSON.parse(formatJson(results(), { cwd: ROOT, contentRoot: ROOT, run }));
    expect(doc.summary.secrets).toBe(6);
    expect(doc.results[0].matches).toHaveLength(5);
    const gid = doc.results[0].groups[0].group_id;
    for (const m of doc.results[0].matches) expect(m.group_id).toBe(gid);
    expect(doc.results[1].groups).toBeUndefined();
    expect(doc.results[1].matches[0].demotion).toEqual(demotion);
    expect(doc.results[1].matches[0].group_id).toBeUndefined();
    expect(doc.run).toMatchObject({
      demoted_matches: 1,
      demoted_by_reason: { 'data-uri-binary-payload': 1, 'base64-binary-run': 0 },
      match_groups: 1,
      grouped_matches: 5,
    });
  });

  it('SARIF keeps one result per match, with group and demotion properties, and equal run counts', () => {
    const json = JSON.parse(formatJson(results(), { cwd: ROOT, contentRoot: ROOT, run }));
    const sarif = JSON.parse(formatSarif(results(), { cwd: ROOT, contentRoot: ROOT, run }));
    const res = sarif.runs[0].results;
    expect(res).toHaveLength(6);
    expect(res[0].properties).toMatchObject({ 'vault-guard/group': json.results[0].groups[0].group_id, 'vault-guard/group_size': 5 });
    expect(res[5].properties).toMatchObject({ 'vault-guard/demoted_from': 'critical', 'vault-guard/demotion_reason': 'data-uri-binary-payload' });
    expect(res[5].level).toBe('note');
    const props = sarif.runs[0].properties.vault_guard_run;
    for (const k of ['demoted_matches', 'demoted_by_reason', 'match_groups', 'grouped_matches']) expect(props[k]).toEqual(json.run[k]);
  });

  it('contentRunCounts sums demotions by reason', () => {
    const c = contentRunCounts(results(), formGroups(results(), { contentRoot: ROOT }));
    expect(c).toEqual({
      demoted_matches: 1,
      demoted_by_reason: { 'data-uri-binary-payload': 1, 'base64-binary-run': 0 },
      match_groups: 1,
      grouped_matches: 5,
    });
  });

  it('demotionText names the payload, its length and what it decodes to', () => {
    expect(demotionText({ ...demotion, run_length: 812004 })).toBe(
      'demoted from critical: inside an 812004-character data:image/png;base64 payload that decodes to a png image',
    );
    expect(demotionText({ from: 'high', reason: 'base64-binary-run', family: 'image', format: '.jpg', run_length: 2048 })).toBe(
      'demoted from high: inside a 2048-character base64 run that decodes to a jpg image',
    );
  });
});
