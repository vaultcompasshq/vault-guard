import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { BlobBatchReader } from '../blob-reader';
import { GitContentSource, scanFileContent, type TrackedEntry } from '../content-source';
import { SecretScanner } from '../../scanners/secret-scanner';

/**
 * U5 of the 2026-10-17 design: `BlobBatchReader.readHead` keeps the first n
 * bytes of a blob, consumes the rest of the body without holding it, and its
 * entries are released through the same path as a full read.
 */

function git(cwd: string, args: string[], input?: Buffer): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf-8',
    ...(input !== undefined ? { input } : {}),
    stdio: [input !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
    maxBuffer: 1 << 28,
  });
}

/** Seeded pseudo-random bytes (xorshift32), so no third-party media is committed. */
function seeded(n: number, seed = 0x2545f491): Buffer {
  const out = Buffer.alloc(n);
  let x = seed >>> 0;
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

const PNG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d]);

describe('U5: BlobBatchReader.readHead', () => {
  let repo: string;

  beforeEach(() => {
    repo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-head-read-')));
    git(repo, ['init', '-q', '-b', 'main']);
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  function blob(bytes: Buffer): string {
    return git(repo, ['hash-object', '-w', '--stdin'], bytes).trim();
  }

  it('returns min(size, 4096) identical bytes, and a full read queued right after stays in sync', async () => {
    const sizes = [0, 3, 4096, 4097, 40 * 1024 * 1024];
    const reader = new BlobBatchReader(repo, process.env, 2);
    try {
      for (const [i, n] of sizes.entries()) {
        const body = seeded(n, 7 + i);
        const next = Buffer.from(`next object ${i}\n${'z'.repeat(5000 + i)}\n`);
        const [oid, nextOid] = [blob(body), blob(next)];
        const [head, full] = await Promise.all([reader.readHead(oid, 4096), reader.read(nextOid)]);
        expect(head.length).toBe(Math.min(n, 4096));
        expect(head.equals(body.subarray(0, 4096))).toBe(true);
        expect(full.equals(next)).toBe(true);
      }
    } finally {
      await reader.closeAndWait();
    }
  }, 120_000);

  it('the largest buffer held during a 40 MiB head read stays under 1 MiB', async () => {
    const oid = blob(seeded(40 * 1024 * 1024, 99));
    const reader = new BlobBatchReader(repo, process.env, 2);
    try {
      const head = await reader.readHead(oid, 4096);
      expect(head.length).toBe(4096);
      expect(reader.maxBuffered).toBeLessThan(1024 * 1024);
      expect(reader.headReadBytes).toBe(40 * 1024 * 1024);
    } finally {
      await reader.closeAndWait();
    }
  }, 120_000);

  it('head and full reads of one object are separate shared entries, both released by release()', async () => {
    const body = Buffer.concat([PNG, seeded(10000)]);
    const oid = blob(body);
    const reader = new BlobBatchReader(repo, process.env, 2);
    try {
      const [h1, h2, f] = await Promise.all([reader.readHead(oid, 4096), reader.readHead(oid, 4096), reader.read(oid)]);
      expect(h1).toBe(h2);
      expect(f.equals(body)).toBe(true);
      expect(reader.requested).toBe(2);
      expect(reader.held).toBe(2);
      reader.release(oid);
      expect(reader.held).toBe(0);
    } finally {
      await reader.closeAndWait();
    }
  });

  it('after a scan of 50 image blobs no blob is held', async () => {
    const entries = new Map<string, TrackedEntry>();
    for (let i = 0; i < 50; i++) {
      const oid = blob(Buffer.concat([PNG, seeded(6000, i + 1)]));
      entries.set(path.join(repo, `img/logo${i}.png`), {
        repoTop: repo,
        mode: '100644',
        oid,
        worktreeAlso: false,
        filtered: false,
      });
    }
    const source = new GitContentSource('index', process.env, entries);
    const scanner = new SecretScanner();
    try {
      source.prepare(entries.keys());
      const outcomes = await Promise.all(
        [...entries].map(([file, entry]) => scanFileContent(scanner, file, entry, source, { classify: true })),
      );
      for (const o of outcomes) expect(o.skippedByType).toEqual({ family: 'image' });
      expect(source.blobsHeld).toBe(0);
      expect(source.headReadBytes).toBe(50 * (PNG.length + 6000));
    } finally {
      await source.closeAndWait();
    }
  });
});
