import { seeded } from './binary-fixtures';

/**
 * Fixtures for the 2026-10-17 data-file design (section 10). Encoded media
 * is synthetic: the minimal valid header of a format followed by seeded
 * pseudo-random bytes, base64-encoded here. Planted keys and tokens are built
 * at run time from a seeded generator; none is a real credential and none is
 * a documentation example key.
 */

export const PNG_HEAD = Buffer.from([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10,
]);
export const JPEG_HEAD = Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01]);

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** `n` seeded alphanumeric characters. */
export function alnum(n: number, seed = 7): string {
  const bytes = seeded(n * 2, seed);
  let s = '';
  for (let i = 0; i < n; i++) s += ALNUM[bytes[i * 2] % ALNUM.length];
  return s;
}

/** A gcp-api-key shaped value built at run time: the prefix and 35 seeded alphanumerics. */
export function gcpKey(seed = 7): string {
  return ['AI', 'za'].join('') + alnum(35, seed);
}

/** A JWT-shaped token with a distinct subject per `i`. Synthetic, never the jwt.io sample. */
export function jwt(i: number): string {
  const enc = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString('base64url');
  return [enc({ alg: 'HS256', typ: 'JWT' }), enc({ sub: `row-${i}`, iat: 1700000000 + i, scope: 'scrape' }), alnum(43, 5000 + i)].join('.');
}

/** Exactly `chars` characters of standard base64 (no `=`) of `head` followed by seeded bytes. */
export function payload(head: Buffer, chars: number, seed = 12): string {
  const bytes = Math.ceil((chars * 3) / 4) + 3;
  const b64 = Buffer.concat([head, seeded(Math.max(0, bytes - head.length), seed)]).toString('base64').replace(/[=]/g, '');
  if (b64.length < chars) throw new Error('payload too short');
  return b64.slice(0, chars);
}

/** A run of exactly `chars` characters whose head decodes to `head`, with `key` spliced in at `at` (default the middle). */
export function runWithKey(head: Buffer, chars: number, key: string, at?: number, seed = 12): string {
  const body = payload(head, chars - key.length, seed);
  const pos = at ?? Math.floor(body.length / 2);
  return body.slice(0, pos) + key + body.slice(pos);
}

/** The F17 shape: a one-line SVG of about `bytes` bytes whose data:image/png payload holds `key` in its middle. */
export function f17Svg(key: string, bytes = 800 * 1024, mediaPrefix = 'data:image/png;base64,'): string {
  const head = `<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><image href="${mediaPrefix}`;
  const tail = '"/></svg>\n';
  return head + runWithKey(PNG_HEAD, bytes - head.length - tail.length, key) + tail;
}

/** An 8-column CSV of `rows` rows, the header first; `cell(r, c)` gives row r's column c. */
export function csv(rows: number, cell: (r: number, c: number) => string, cols = 8): string {
  const header = Array.from({ length: cols }, (_, c) => `col${c}`).join(',');
  const body = Array.from({ length: rows }, (_, r) => Array.from({ length: cols }, (_, c) => cell(r, c)).join(','));
  return [header, ...body].join('\n') + '\n';
}

/** A distinct 40-character standard-base64 token per cell, from a fixed seed (no rule matches any of them). */
export function token40(r: number, c: number): string {
  return seeded(30, 100000 + r * 16 + c).toString('base64');
}
