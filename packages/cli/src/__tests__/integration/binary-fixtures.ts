/**
 * Synthetic binary fixtures for the 2026-10-17 design (section 11): the
 * minimal valid header of a format followed by pseudo-random bytes from a
 * fixed seed, so no third-party media is committed. Built in memory.
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

/** An ISO base media header (`ftyp` box) and seeded bytes, `size` bytes in all. */
export function realMp4(size = 8192, seed = 11): Buffer {
  const head = Buffer.from([0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, 0x00, 0x00, 0x02, 0x00]);
  return Buffer.concat([head, seeded(Math.max(0, size - head.length), seed)]);
}

/** A PNG signature and IHDR chunk, then seeded bytes. */
export function realPng(size = 4096, seed = 12): Buffer {
  const head = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10,
  ]);
  return Buffer.concat([head, seeded(Math.max(0, size - head.length), seed)]);
}

/** A WOFF2 header (`wOF2`, flavor, length), then seeded bytes. */
export function realWoff2(size = 2048, seed = 13): Buffer {
  const head = Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00]);
  return Buffer.concat([head, seeded(Math.max(0, size - head.length), seed)]);
}

/** A WebM (EBML) header with its size and version elements, then seeded bytes. */
export function realWebm(size = 4096, seed = 14): Buffer {
  const head = Buffer.from([0x1a, 0x45, 0xdf, 0xa3, 0x9f, 0x42, 0x86, 0x81, 0x01, 0x42, 0xf7, 0x81, 0x01]);
  return Buffer.concat([head, seeded(Math.max(0, size - head.length), seed)]);
}

/** A POSIX (ustar) tar holding one file, stored uncompressed. */
export function posixTar(name: string, body: Buffer): Buffer {
  const header = Buffer.alloc(512, 0);
  const put = (s: string, off: number): void => {
    Buffer.from(s, 'latin1').copy(header, off);
  };
  put(name, 0);
  put('0000644\0', 100);
  put('0000000\0', 108);
  put('0000000\0', 116);
  put(`${body.length.toString(8).padStart(11, '0')}\0`, 124);
  put('00000000000\0', 136);
  put('        ', 148);
  put('0', 156);
  put('ustar\0', 257);
  put('00', 263);
  let sum = 0;
  for (const x of header) sum += x;
  put(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  const pad = (512 - (body.length % 512)) % 512;
  return Buffer.concat([header, body, Buffer.alloc(pad), Buffer.alloc(1024)]);
}

/**
 * The first non-empty stderr line after the cleaning the umbrella applies:
 * control characters and non-ASCII replaced, whitespace collapsed, trimmed.
 */
export function firstStderrLine(stderr: string): string {
  for (const raw of stderr.split('\n')) {
    // eslint-disable-next-line no-control-regex
    const clean = raw.replace(/[\u0000-\u001f\u007f-￿]/g, ' ').replace(/\s+/g, ' ').trim();
    if (clean.length > 0) return clean;
  }
  return '';
}

/** Index of the first stderr line matching `re`, or -1. */
export function lineIndex(stderr: string, re: RegExp): number {
  return stderr.split('\n').findIndex(l => re.test(l));
}
