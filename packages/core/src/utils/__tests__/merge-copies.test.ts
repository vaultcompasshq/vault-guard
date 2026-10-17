import { mergeCopies } from '../content-source';
import type { SecretMatch } from '../../types';

/**
 * Section 6.5 of the 2026-10-17 data-file design: of two copies of one value
 * the merge keeps the one with the higher severity; a tie keeps the blob's.
 */

function m(sev: SecretMatch['severity'], source: SecretMatch['source'], extra: Partial<SecretMatch> = {}): SecretMatch {
  return {
    type: 'gcp-api-key',
    value: 'AIza(39c)',
    line: 1,
    column: 10,
    offset: 10,
    matchLength: 39,
    severity: sev,
    valueDigest: 'd1',
    source,
    ...extra,
  };
}

const demoted = { from: 'critical' as const, reason: 'data-uri-binary-payload' as const, family: 'image', format: '.png', media_type: 'image/png', run_length: 4096 };

describe('U14: mergeCopies keeps the higher-severity copy', () => {
  it('blob demoted, disk critical: the disk copy is reported', () => {
    const out = mergeCopies([[m('low', 'index', { demotion: demoted })]], [m('critical', 'worktree')]);
    expect(out.map(x => [x.severity, x.source])).toEqual([['critical', 'worktree']]);
  });

  it('blob critical, disk demoted: the blob copy is reported', () => {
    const out = mergeCopies([[m('critical', 'index')]], [m('low', 'worktree', { demotion: demoted })]);
    expect(out.map(x => [x.severity, x.source])).toEqual([['critical', 'index']]);
  });

  it('equal severities keep the blob copy, as before', () => {
    const out = mergeCopies([[m('critical', 'index')]], [m('critical', 'worktree', { line: 2, offset: 50 })]);
    expect(out.map(x => [x.source, x.line])).toEqual([['index', 1]]);
  });

  it('a value only on disk is still reported beside the blob one', () => {
    const out = mergeCopies([[m('critical', 'index')]], [m('critical', 'worktree', { valueDigest: 'd2' })]);
    expect(out.map(x => x.source)).toEqual(['index', 'worktree']);
  });

  it('two blob copies and one disk copy pair as a multiset, lowest blob severity first', () => {
    const out = mergeCopies(
      [[m('critical', 'index', { line: 1 }), m('low', 'index', { line: 2, demotion: demoted })]],
      [m('critical', 'worktree', { line: 3 })],
    );
    expect(out.map(x => [x.severity, x.source, x.line])).toEqual([
      ['critical', 'index', 1],
      ['critical', 'worktree', 3],
    ]);
  });

  it('conflict stages: a stage 3 copy at a higher severity replaces the stage 2 copy', () => {
    const out = mergeCopies(
      [[m('low', 'index', { stage: 2, demotion: demoted })], [m('critical', 'index', { stage: 3 })]],
      [],
    );
    expect(out.map(x => [x.severity, x.stage])).toEqual([['critical', 3]]);
  });

  it('conflict stages: an equal stage 3 copy is dropped, as before', () => {
    const out = mergeCopies([[m('critical', 'index', { stage: 2 })], [m('critical', 'index', { stage: 3 })]], []);
    expect(out.map(x => x.stage)).toEqual([2]);
  });
});
