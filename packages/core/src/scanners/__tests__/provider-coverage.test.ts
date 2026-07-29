import { SecretScanner } from '../secret-scanner';

/**
 * Recall guard for the credential formats added in 1.4.0.
 *
 * Every value here is assembled from fragments so no contiguous secret-shaped
 * literal lives in git history (same policy as `bench/generate-fixtures.cjs`);
 * the strings are synthetic and match only the documented public key *shape*.
 */
/**
 * Deterministic pseudo-random string. Uses mulberry32 and draws from the top
 * bits: a plain LCG mod 2^31 has a period of at most 16 in its low bits, which
 * yields a low-variety string that the scanner's entropy guard correctly drops.
 */
function makeRng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function fromAlphabet(chars: string, n: number, seed: number): string {
  const rng = makeRng(seed);
  let out = '';
  for (let i = 0; i < n; i++) out += chars[Math.floor(rng() * chars.length)];
  return out;
}

function alnum(n: number, seed = 7): string {
  return fromAlphabet('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', n, seed);
}

function hex(n: number, seed = 11): string {
  return fromAlphabet('abcdef0123456789', n, seed);
}

describe('1.4.0 provider coverage', () => {
  const scanner = new SecretScanner();

  const cases: Array<[string, string, string]> = [
    ['groq', `${'gsk'}_${alnum(52)}`, 'critical'],
    ['openrouter', `${'sk-or'}-v1-${hex(64)}`, 'critical'],
    ['xai', `${'xai'}-${alnum(80)}`, 'critical'],
    ['perplexity', `${'pplx'}-${alnum(48)}`, 'critical'],
    ['langsmith', `${'lsv2'}_pt_${hex(32)}_${hex(10)}`, 'critical'],
    ['fireworks-ai', `${'fw'}_${alnum(30)}`, 'critical'],
    ['supabase-token', `${'sbp'}_${hex(40)}`, 'critical'],
    ['supabase-secret', `${'sb'}_secret_${alnum(40)}`, 'critical'],
    ['vercel-blob', `${'vercel'}_blob_rw_${alnum(26)}_${alnum(32)}`, 'critical'],
    ['planetscale', `${'pscale'}_tkn_${alnum(43)}`, 'critical'],
    ['doppler-token', `${'dp'}.pt.${alnum(43)}`, 'critical'],
    ['databricks-token', `${'dapi'}${hex(32)}`, 'critical'],
    ['notion-token', `${'ntn'}_${alnum(46)}`, 'critical'],
    ['airtable-pat', `${'pat'}${alnum(14)}.${hex(64)}`, 'critical'],
    ['figma-token', `${'figd'}_${alnum(40)}`, 'critical'],
  ];

  it.each(cases)('detects %s at %s severity', (type, value, severity) => {
    const matches = scanner.scanContent(`const k = "${value}";`);
    const hit = matches.find(m => m.type === type);
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe(severity);
  });

  const contextAnchored: Array<[string, string]> = [
    ['mistral', `MISTRAL_API_KEY=${alnum(32)}`],
    ['together-ai', `TOGETHER_API_KEY=${hex(64)}`],
    ['deepseek', `DEEPSEEK_API_KEY=sk-${hex(32)}`],
    ['cloudflare-token', `CLOUDFLARE_API_TOKEN=${alnum(40)}`],
  ];

  it.each(contextAnchored)('detects %s from its canonical env-var name', (type, line) => {
    const matches = scanner.scanContent(line);
    expect(matches.map(m => m.type)).toContain(type);
  });

  it('reports a Sentry DSN at low severity (public by design, like gcp-oauth)', () => {
    const dsn = `https://${hex(32)}@o123456.ingest.sentry.io/1234567`;
    const matches = scanner.scanContent(`Sentry.init({ dsn: "${dsn}" });`);
    const hit = matches.find(m => m.type === 'sentry-dsn');
    expect(hit).toBeDefined();
    expect(hit!.severity).toBe('low');
  });

  it('does not fire the new prefixes on identifiers that merely contain them', () => {
    const benign = [
      'const gsk_total = computeTotal();',
      'const dapifoo = 1;',
      'export function patchUserRecord() {}',
      'const figure = renderFigure();',
    ].join('\n');
    const newRules = new Set([
      'groq', 'databricks-token', 'airtable-pat', 'figma-token',
    ]);
    const matches = scanner.scanContent(benign).filter(m => newRules.has(m.type));
    expect(matches).toEqual([]);
  });
});
