import fs from 'fs';
import os from 'os';
import path from 'path';

import { HEAD_TREE_LISTING_MAX_BYTES, TrustBaseError, listHeadTreeBlobs } from '../trust-base';

/**
 * The HEAD tree listing under --trust-base (design 2026-10-12, 2.6): a failure
 * is a TrustBaseError, never `[]`, and the buffer is the 512 MiB the plain file
 * set allows, not the old 64 MiB.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

/** A `git` stub that answers `ls-tree` with `bytes` of output, generated. */
function stub(dir: string, bytes: number, valid: boolean): string {
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin, { recursive: true });
  const script = [
    `#!${process.execPath}`,
    "const fs = require('fs');",
    'const args = process.argv.slice(2);',
    "if (!args.includes('ls-tree')) process.exit(1);",
    `const total = ${bytes};`,
    `const valid = ${valid ? 'true' : 'false'};`,
    'const pad = "p".repeat(200);',
    'let written = 0;',
    'let i = 0;',
    'const chunk = [];',
    'let chunkLen = 0;',
    'while (written < total) {',
    '  const rec = valid',
    '    ? `100644 blob ${"0".repeat(40)}\\tdir/${pad}/f${i++}.txt\\0`',
    '    : "x".repeat(1 << 20);',
    '  chunk.push(rec); chunkLen += rec.length; written += rec.length;',
    '  if (chunkLen > (1 << 22)) { fs.writeSync(1, chunk.join("")); chunk.length = 0; chunkLen = 0; }',
    '}',
    'if (chunk.length) fs.writeSync(1, chunk.join(""));',
    '',
  ].join('\n');
  fs.writeFileSync(path.join(bin, 'git'), script, { mode: 0o755 });
  return bin;
}

describe('HEAD tree listing (U23)', () => {
  const originalPath = process.env.PATH;
  let dir: string;

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-tree-listing-')));
  });

  afterEach(() => {
    process.env.PATH = originalPath;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  // The limit is injected so these cases move a few MiB, not half a gigabyte:
  // a listing is judged against the limit the same way at any size.
  const SMALL = 1024 * 1024;

  itPosix('U23: the listing buffer is 512 MiB, not the old 64 MiB', () => {
    expect(HEAD_TREE_LISTING_MAX_BYTES).toBe(512 * 1024 * 1024);
    // With no option the default applies: a listing over the small limit reads.
    process.env.PATH = `${stub(dir, 3 * SMALL, true)}${path.delimiter}${originalPath ?? ''}`;
    expect(listHeadTreeBlobs(dir).size).toBeGreaterThan(10_000);
  }, 60_000);

  itPosix('U23: a listing under the limit succeeds', () => {
    process.env.PATH = `${stub(dir, SMALL - 64 * 1024, true)}${path.delimiter}${originalPath ?? ''}`;
    expect(listHeadTreeBlobs(dir, { maxBytes: SMALL }).size).toBeGreaterThan(3_000);
  }, 60_000);

  itPosix('U23: a listing over the limit is exit 2 saying the tree listing was too large', () => {
    process.env.PATH = `${stub(dir, 3 * SMALL, false)}${path.delimiter}${originalPath ?? ''}`;
    let caught: unknown;
    try {
      listHeadTreeBlobs(dir, { maxBytes: SMALL });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TrustBaseError);
    expect(String((caught as Error).message)).toContain('the HEAD tree listing (git ls-tree -r HEAD) was too large');
    expect(String((caught as Error).message)).not.toContain('ENOBUFS');
  }, 60_000);

  itPosix('U12: a failing listing is a TrustBaseError, not an empty file set', () => {
    // Not a git repository at all: ls-tree fails.
    let caught: unknown;
    try {
      listHeadTreeBlobs(dir);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(TrustBaseError);
  });
});
