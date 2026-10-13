import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { BlobBatchReader, batchCheckBlobs } from '../blob-reader';
import { GitContentSource, scanFileContent } from '../content-source';
import { SecretScanner } from '../../scanners/secret-scanner';

/**
 * The batch blob reader (design 2026-10-12, 2.3). Each test names the unit
 * row of section 7.2 it implements and the mutation it kills.
 */

function git(cwd: string, args: string[], input?: Buffer): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf-8',
    ...(input !== undefined ? { input } : {}),
    stdio: [input !== undefined ? 'pipe' : 'ignore', 'pipe', 'pipe'],
  });
}

describe('blob reader', () => {
  let repo: string;

  beforeEach(() => {
    repo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-blob-reader-')));
    git(repo, ['init', '-q', '-b', 'main']);
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  /** Write a blob straight into the object store and return its id. */
  function blob(bytes: Buffer): string {
    return git(repo, ['hash-object', '-w', '--stdin'], bytes).trim();
  }

  it('U2: blobs of 0 bytes, 1 byte, a header-shaped body and exactly 32 MiB come back byte-identical', async () => {
    const empty = Buffer.alloc(0);
    const one = Buffer.from('x');
    const decoyOid = blob(Buffer.from('decoy'));
    // A body that looks like the next object's header, to catch a parser that
    // reads headers out of content instead of counting bytes.
    const tricky = Buffer.from(`first\n${decoyOid} blob 5\nsecond\n`);
    const big = Buffer.alloc(32 * 1024 * 1024, 0x41);
    big[big.length - 1] = 0x0a;
    const inputs = [empty, one, tricky, big, one];
    const oids = inputs.map(blob);
    const reader = new BlobBatchReader(repo, process.env, 2);
    try {
      const out = await Promise.all(oids.map(o => reader.read(o)));
      out.forEach((b, i) => {
        expect(b.length).toBe(inputs[i].length);
        expect(b.equals(inputs[i])).toBe(true);
      });
      expect(reader.spawned).toBe(1);
    } finally {
      reader.close();
    }
  }, 60_000);

  /** Wait until the reader has no live git child, or give up after `ms`. */
  async function settled(reader: BlobBatchReader, ms = 5000): Promise<number> {
    const end = Date.now() + ms;
    while (reader.liveChildren > 0 && Date.now() < end) await new Promise(r => setTimeout(r, 20));
    return reader.liveChildren;
  }

  it('closing with reads still queued starts no new git process and settles every read', async () => {
    const oids = Array.from({ length: 6 }, (_, i) => blob(Buffer.from(`blob ${i}\n${'y'.repeat(65536)}\n`)));
    const reader = new BlobBatchReader(repo, process.env, 1);
    const reads = oids.map(o => reader.read(o));
    // What a scan does when another file's git error ends the run while
    // reads beyond the window are still queued.
    reader.close();
    const outcomes = await Promise.allSettled(reads);
    expect(outcomes.length).toBe(6);
    expect(reader.spawned).toBe(1);
    expect(await settled(reader)).toBe(0);
  });

  it('a failure in the middle of the reads leaves no live git process', async () => {
    const good = blob(Buffer.from('fine\n'));
    const reader = new BlobBatchReader(repo, process.env, 2);
    const reads = [reader.read(good), reader.read('0123456789abcdef0123456789abcdef01234567'), reader.read(good)];
    const outcomes = await Promise.allSettled(reads);
    expect(outcomes.some(o => o.status === 'rejected')).toBe(true);
    reader.close();
    expect(await settled(reader)).toBe(0);
  });

  it('a closed content source refuses a read for a repository it has no reader for yet', async () => {
    // A sibling file in the same batch can still reach read() after a git
    // error closed the source; it must not start a git process nothing closes.
    const other = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-blob-other-')));
    try {
      git(other, ['init', '-q', '-b', 'main']);
      const oid = git(other, ['hash-object', '-w', '--stdin'], Buffer.from('other repo blob\n')).trim();
      const source = new GitContentSource('index', process.env);
      source.close();
      await expect(source.read(other, oid)).rejects.toThrow('closed');
      expect(source.batchReads).toBe(0);
    } finally {
      fs.rmSync(other, { recursive: true, force: true });
    }
  });

  it('U2: --batch-check reports sizes and missing objects before any content moves', () => {
    const a = blob(Buffer.from('hello\n'));
    const missing = '0123456789abcdef0123456789abcdef01234567';
    const checks = batchCheckBlobs(repo, [a, missing, a], process.env);
    expect(checks.get(a)).toEqual({ kind: 'blob', size: 6 });
    expect(checks.get(missing)).toEqual({ kind: 'missing' });
  });

  it('U4: one object id at two paths is read once and scanned at each path', async () => {
    const key = ['AKIA', 'Q7MZR2XVB9', 'NTD4WH'].join('');
    const oid = blob(Buffer.from(`export const k = "${key}";\n`));
    const entry = { repoTop: repo, mode: '100644', oid, worktreeAlso: false, filtered: false };
    const a = path.join(repo, 'a', 'k.ts');
    const b = path.join(repo, 'b', 'k.ts');
    const source = new GitContentSource('index', process.env, new Map([[a, entry], [b, entry]]));
    const scanner = new SecretScanner();
    try {
      source.prepare([a, b]);
      const results = await Promise.all([a, b].map(f => scanFileContent(scanner, f, entry, source)));
      // Two scans, two findings: path context can change severity.
      expect(results.map(r => r.matches.length)).toEqual([1, 1]);
    } finally {
      source.close();
    }
    // One object id written to git, one process.
    expect(source.blobsRequested).toBe(1);
    expect(source.batchReads).toBe(1);
    // Released once the last path that needed it was scanned.
    expect(source.blobsHeld).toBe(0);
  });

  it('holds no more blobs than the read window at once, and none after the run', async () => {
    // 200 distinct blobs, scanned the way the CLI does: ten at a time.
    const entries = new Map<string, { repoTop: string; mode: string; oid: string; worktreeAlso: boolean; filtered: boolean }>();
    for (let i = 0; i < 200; i++) {
      const oid = blob(Buffer.from(`export const v${i} = ${i};\n${'x'.repeat(4096)}\n`));
      entries.set(path.join(repo, `f${i}.ts`), { repoTop: repo, mode: '100644', oid, worktreeAlso: false, filtered: false });
    }
    const source = new GitContentSource('index', process.env, new Map(entries));
    const scanner = new SecretScanner();
    const files = [...entries.keys()];
    try {
      source.prepare(files);
      for (let i = 0; i < files.length; i += 10) {
        await Promise.all(files.slice(i, i + 10).map(f => scanFileContent(scanner, f, entries.get(f), source)));
      }
    } finally {
      source.close();
    }
    expect(source.blobsRequested).toBe(200);
    expect(source.maxBlobsHeld).toBeLessThanOrEqual(10);
    expect(source.blobsHeld).toBe(0);
  }, 60_000);
});
