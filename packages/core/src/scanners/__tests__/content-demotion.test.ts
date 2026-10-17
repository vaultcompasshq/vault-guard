import { SecretScanner } from '../secret-scanner';
import { internals } from '../../utils/data-shape';
import { JPEG_HEAD, PNG_HEAD, alnum, gcpKey, payload, runWithKey, seeded } from '../../utils/__tests__/media-fixtures';

/**
 * The encoded-payload demotion inside SecretScanner.scanContent (design
 * 2026-10-17 data files, sections 3, 4.2 and 4.4), and the slot it sets for
 * grouping (section 5.2).
 */

const scanner = new SecretScanner();
const key = gcpKey(3);

function only(text: string, s = scanner): ReturnType<SecretScanner['scanContent']> {
  return s.scanContent(text);
}

describe('demotion in scanContent', () => {
  it('a key inside a PNG data: payload is low with a record from critical', () => {
    const text = `<img src="data:image/png;base64,${runWithKey(PNG_HEAD, 4096, key)}">\n`;
    const [m, ...rest] = only(text);
    expect(rest).toHaveLength(0);
    expect(m.type).toBe('gcp-api-key');
    expect(m.severity).toBe('low');
    expect(m.demotion).toEqual({
      from: 'critical',
      reason: 'data-uri-binary-payload',
      family: 'image',
      format: '.png',
      media_type: 'image/png',
      run_length: 4096,
    });
    expect(m.valueDigest).toBeDefined();
  });

  it('the same key standing alone keeps critical and carries no record', () => {
    const [m] = only(`const k = "${key}";\n`);
    expect(m.severity).toBe('critical');
    expect(m.demotion).toBeUndefined();
  });

  it('a severity override to low is a no-op: no record', () => {
    const s = new SecretScanner({ severity_overrides: { 'gcp-api-key': 'low' } });
    const [m] = s.scanContent(`"data:image/png;base64,${runWithKey(PNG_HEAD, 4096, key)}"\n`);
    expect(m.severity).toBe('low');
    expect(m.demotion).toBeUndefined();
  });

  it('a severity override to high is demoted from high', () => {
    const s = new SecretScanner({ severity_overrides: { 'gcp-api-key': 'high' } });
    const [m] = s.scanContent(`"data:image/png;base64,${runWithKey(PNG_HEAD, 4096, key)}"\n`);
    expect(m.severity).toBe('low');
    expect(m.demotion?.from).toBe('high');
  });

  it('a JWT is never demoted (its dots fail C1), whatever surrounds it', () => {
    const jwt = ['eyJhbGciOiJIUzI1NiJ9', alnum(40, 5), alnum(43, 6)].join('.');
    const text = `"data:image/png;base64,${payload(PNG_HEAD, 2048)}" ${jwt}\n`;
    const m = only(text).find(x => x.type === 'jwt-token');
    expect(m?.severity).toBe('high');
    expect(m?.demotion).toBeUndefined();
  });

  it('an ignore-line directive tallies the rule severity, not the demoted one (A24 at the scanner)', () => {
    const hits = { count: 0, lines: [] as number[], criticalVendorAnchored: 0 };
    const text = `"data:image/png;base64,${runWithKey(PNG_HEAD, 4096, key)}" // vault-guard: ignore-line\n`;
    expect(scanner.scanContent(text, { ignoreHits: hits })).toHaveLength(0);
    expect(hits.count).toBe(1);
    expect(hits.criticalVendorAnchored).toBe(1);
  });
});

describe('U12: dedupe then demote restores a displaced match that would not be demoted', () => {
  it('a bearer match displaced by a demoted gcp slice is restored at high', () => {
    // URL-safe payload, so the bearer rule runs over the whole run.
    const body = Buffer.concat([PNG_HEAD, seeded(1600, 21)]).toString('base64url');
    const run = body.slice(0, 40) + key + body.slice(40);
    const text = `Authorization: Bearer ${run}\n`;
    const ms = only(text);
    const bearer = ms.find(m => m.type === 'bearer-token');
    const gcp = ms.find(m => m.type === 'gcp-api-key');
    expect(gcp?.severity).toBe('low');
    expect(gcp?.demotion?.reason).toBe('base64-binary-run');
    expect(bearer?.severity).toBe('high');
    expect(bearer?.demotion).toBeUndefined();
    expect(ms).toHaveLength(2);
  });

  it('a displaced match that would itself be demoted stays dropped', () => {
    // A github-token shape overlapping the gcp slice, both inside the run.
    const ghp = ['gh', 'p_'].join('') + alnum(36, 9);
    const body = Buffer.concat([PNG_HEAD, seeded(1600, 22)]).toString('base64url');
    const inner = key.slice(0, 14) + ghp;
    const run = body.slice(0, 40) + inner + body.slice(40);
    const text = `"${run}"\n`;
    const ms = only(text);
    expect(ms.map(m => [m.type, m.severity])).toEqual([['gcp-api-key', 'low']]);
  });

  it('a restored match never displaces a kept match: the kept one wins, as in 1.11.0', () => {
    // A bearer header over a base64url PNG run holding a gcp slice in its
    // middle and a github-token shape flush at its end. Dedupe keeps the gcp
    // slice (it beats the bearer match) and the github-token match (no overlap
    // with the slice). The slice is demoted, so the bearer match is restored;
    // it overlaps the kept github-token match and must not replace it.
    const s = new SecretScanner({ severity_overrides: { 'github-token': 'high' } });
    const ghp = ['gh', 'p_'].join('') + alnum(36, 11);
    const body = Buffer.concat([PNG_HEAD, seeded(1600, 23)]).toString('base64url');
    const run = body.slice(0, 40) + key + body.slice(40) + ghp;
    const ms = s.scanContent(`Authorization: Bearer ${run}\n`);
    expect(ms.map(m => [m.type, m.severity, m.demotion !== undefined])).toEqual([
      ['gcp-api-key', 'low', true],
      ['github-token', 'high', false],
    ]);
  });

  it('nothing is restored when the winner is not demoted', () => {
    const text = `Authorization: Bearer ${key}x${alnum(20, 4)}\n`;
    const ms = only(text);
    expect(ms.map(m => [m.type, m.severity])).toEqual([['gcp-api-key', 'critical']]);
  });
});

describe('U13: run starts are found by one lazy linear sweep per copy', () => {
  /** A PNG payload run of at least `chars` characters with `slices` gcp slices spread through it. */
  function packed(chars: number, slices: number): string {
    const body = payload(PNG_HEAD, chars, 31);
    const step = Math.floor(body.length / (slices + 1));
    const parts: string[] = [];
    for (let i = 0; i < slices; i++) parts.push(body.slice(i * step, (i + 1) * step), gcpKey(1000 + i));
    parts.push(body.slice(slices * step));
    return `"data:image/png;base64,${parts.join('')}"\n`;
  }

  afterEach(() => jest.restoreAllMocks());

  it('the sweep runs once per copy, however many matches it judges', () => {
    const spy = jest.spyOn(internals, 'sweepRuns');
    const ms = only(packed(64 * 1024, 200));
    expect(ms.filter(m => m.demotion !== undefined).length).toBe(200);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('a clean copy and a copy whose matches are delimited never sweep', () => {
    const spy = jest.spyOn(internals, 'sweepRuns');
    only('nothing here\n');
    only(`a,${key},b\n`);
    expect(spy).not.toHaveBeenCalled();
  });

  it('10,000 slices take at most 20 times the time of 1,000 (linear, not quadratic)', () => {
    const big = 8 * 1024 * 1024;
    const t1 = packed(big, 1000);
    const t10 = packed(big, 10000);
    const time = (t: string): number => {
      let best = Infinity;
      for (let i = 0; i < 2; i++) {
        const t0 = process.hrtime.bigint();
        const ms = only(t);
        best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6);
        expect(ms.every(m => m.severity === 'low')).toBe(true);
      }
      return best;
    };
    // The demotion step is measured inside scanContent: the regex pass is the
    // same for both texts up to the extra matches, so the ratio bounds the step.
    const a = time(t1);
    const b = time(t10);
    expect(b / a).toBeLessThanOrEqual(20);
  }, 120000);
});

describe('U11: the data-file classifier costs a clean copy nothing', () => {
  afterEach(() => jest.restoreAllMocks());

  it('a 30 MB delimited CSV with no matches never runs dataShape', () => {
    const spy = jest.spyOn(internals, 'classify');
    const row = 'alpha,bravo,charlie,delta,echo,foxtrot,golf,hotel\n';
    const big = row.repeat(Math.ceil((30 * 1024 * 1024) / row.length));
    expect(only(big)).toHaveLength(0);
    expect(spy).not.toHaveBeenCalled();
  }, 120000);

  // The design's bound is 5 percent on the CI machine; measured 3.4 percent
  // here. Timing on shared runners moves with GC and JIT, so the assertion
  // allows 15 percent: it still catches a classifier that costs as much as
  // the scan, and the deterministic contract is the spy test above.
  it("A2's CSV: the classification is a small share of the scan", () => {
    const enc = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
    const jwt = (i: number): string => [enc({ alg: 'HS256', typ: 'JWT' }), enc({ sub: `row-${i}` }), alnum(43, 5000 + i)].join('.');
    const text =
      ['c0,c1,c2,c3,c4,c5,c6,c7', ...Array.from({ length: 500 }, (_, r) => Array.from({ length: 8 }, (_, c) => (c === 6 ? jwt(r) : `v${r}x${c}`)).join(','))].join('\n') +
      '\n';
    const original = internals.classify;
    const spy = jest.spyOn(internals, 'classify');
    let classifyMs = 0;
    spy.mockImplementation((t: string) => {
      const t0 = process.hrtime.bigint();
      const out = original(t);
      classifyMs += Number(process.hrtime.bigint() - t0) / 1e6;
      return out;
    });
    // Steady state: the fastest of five scans against the fastest of five
    // classifications, so JIT warm-up and a busy machine do not decide it.
    let best = Infinity;
    let bestClassify = Infinity;
    for (let i = 0; i < 5; i++) {
      classifyMs = 0;
      const t0 = process.hrtime.bigint();
      const ms = only(text);
      const total = Number(process.hrtime.bigint() - t0) / 1e6;
      expect(ms.every(m => m.groupSlot !== undefined)).toBe(true);
      best = Math.min(best, total);
      bestClassify = Math.min(bestClassify, classifyMs);
    }
    expect(spy).toHaveBeenCalled();
    expect(bestClassify / best).toBeLessThan(0.15);
  });
});

describe('slots for grouping', () => {
  it('matches in one column of a delimited copy carry the column slot', () => {
    const rows = Array.from({ length: 30 }, (_, i) => `${i},user${i},${gcpKey(200 + i)},x`).join('\n') + '\n';
    const ms = only(rows);
    expect(ms).toHaveLength(30);
    for (const m of ms) expect(m.groupSlot).toEqual({ basis: 'column', delimiter: ',', column: 2 });
  });

  it('fewer than five matches of any rule never classify the copy', () => {
    const spy = jest.spyOn(internals, 'classify');
    const rows = Array.from({ length: 30 }, (_, i) => `${i},user${i},${i < 4 ? gcpKey(300 + i) : 'none'},x`).join('\n');
    const ms = only(rows);
    expect(ms).toHaveLength(4);
    expect(ms.every(m => m.groupSlot === undefined)).toBe(true);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('a bare JPEG run demotes, a bare run of random bytes does not', () => {
    const jpeg = only(`{"thumb":"${runWithKey(JPEG_HEAD, 4096, key)}"}\n`);
    expect(jpeg[0].demotion?.format).toBe('.jpg');
    const random = only(`{"blob":"${runWithKey(Buffer.from([0x13, 0x37, 0x00, 0x01]), 4096, key)}"}\n`);
    expect(random[0].severity).toBe('critical');
  });
});
