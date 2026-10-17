/**
 * Synthetic encoded-media fixtures for the 2026-10-17 data-file design
 * (section 10): the minimal valid header of a format followed by seeded
 * pseudo-random bytes, base64-encoded in the test. No third-party media and
 * no real key: planted keys are built at run time from a seeded generator.
 */

/** Seeded pseudo-random bytes (xorshift32). */
export function seeded(n: number, seed = 0x2545f491): Buffer {
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

/** A gcp-api-key shaped value: the prefix and 35 seeded alphanumerics. Synthetic. */
export function gcpKey(seed = 7): string {
  return ['AI', 'za'].join('') + alnum(35, seed);
}

/** The base64 (standard alphabet, no padding characters) of `head` plus seeded bytes, exactly `chars` long. */
export function payload(head: Buffer, chars: number, seed = 12): string {
  const bytes = Math.ceil((chars * 3) / 4) + 3;
  const b64 = Buffer.concat([head, seeded(Math.max(0, bytes - head.length), seed)]).toString('base64').replace(/[=]/g, '');
  return b64.slice(0, chars);
}

/**
 * A run of exactly `chars` characters whose head decodes to `head`, with
 * `key` spliced in at `at` (default the middle). Padding never appears.
 */
export function runWithKey(head: Buffer, chars: number, key: string, at?: number, seed = 12): string {
  const body = payload(head, chars - key.length, seed);
  const pos = at ?? Math.floor(body.length / 2);
  return body.slice(0, pos) + key + body.slice(pos);
}
