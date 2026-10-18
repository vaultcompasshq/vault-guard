import * as fs from 'fs';
import * as path from 'path';

import { checkCommand } from '../../commands/check';
import { scanCommand } from '../../commands/scan';
import { AWS_KEY, AWS_KEY_2, capture, commitAll, git, initRepo, parse, sources, tmpDir, write } from './git-fixture';

/**
 * Audit 2026-10-18, N1. A file the head tree records as a regular blob, whose
 * working copy was replaced by a symlink AFTER checkout (an earlier CI step,
 * not anything the head commit can carry), used to be dropped from a
 * `--trust-base` run without being counted anywhere: the file set asked the
 * disk entry's type and `continue`d on a non-file. The tree says what the file
 * is and the blob says what it holds, so the blob is scanned; the link is
 * never followed, neither to read content nor to key the finding, and the run
 * says so with a warning. The same holds for a file named on the command line.
 *
 * Plain mode is pinned unchanged here on purpose: its drop of the same file is
 * a documented known limit (CHANGELOG), and changing it is a separate decision
 * that has to change that text with it.
 *
 * The case with no head blob to read is in trust-base-disk-swap-no-blob.test.ts,
 * which needs a module mock of its own.
 */
const itPosix = process.platform === 'win32' ? it.skip : it;

interface ContentFp {
  file: string;
  content_fingerprint?: string;
  fingerprint: string;
}

function fingerprintsOf(stdout: string, file: string): ContentFp[] {
  return parse(stdout)
    .results.filter(r => r.file === file)
    .flatMap(r => r.matches.map(m => ({ file: r.file, content_fingerprint: m.content_fingerprint, fingerprint: m.fingerprint })));
}

describe('trust-base: a tracked regular file whose working copy became a symlink', () => {
  const originalCwd = process.cwd();
  let dir: string;
  let outside: string;

  beforeEach(() => {
    dir = tmpDir('vg-disk-swap-');
    outside = tmpDir('vg-disk-swap-outside-');
    process.chdir(dir);
    initRepo(dir);
    write(dir, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    write(dir, 'src/app.ts', 'export const greeting = "hello";\n');
    write(dir, 'src/harmless.ts', 'export const nothing = 0;\n');
    write(dir, 'docs/notes.md', 'notes\n');
    commitAll(dir, 'base');
    git(dir, ['branch', 'base-snapshot']);
    git(dir, ['checkout', '-q', '-b', 'feature']);
    write(dir, 'src/swapped.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'head');
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });

  function swapForLink(target: string, rel = 'src/swapped.ts'): void {
    const p = path.join(dir, rel);
    fs.rmSync(p);
    fs.symlinkSync(target, p);
  }

  itPosix('the precondition holds: HEAD records a regular blob and the disk entry is a link', () => {
    swapForLink('harmless.ts');
    expect(git(dir, ['ls-tree', 'HEAD', 'src/swapped.ts'])).toMatch(/^100644 blob /);
    expect(fs.lstatSync(path.join(dir, 'src', 'swapped.ts')).isSymbolicLink()).toBe(true);
  });

  itPosix('still blocks on the key in the head blob, and never exits 0', async () => {
    swapForLink('harmless.ts');
    const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    expect(r.code).not.toBe(0);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual(['src/swapped.ts|aws-access|head']);
    // The link is named, not silently accepted.
    expect(
      doc.diagnostics?.some(
        d => d.code === 'symlink.not_followed' && String(d.ctx.file).endsWith(path.join('src', 'swapped.ts')),
      ),
    ).toBe(true);
  });

  itPosix('never reads through the link: a key in the link target outside the repository is not reported', async () => {
    write(outside, 'target.ts', `export const other = "${AWS_KEY_2}";\n`);
    swapForLink(path.join(outside, 'target.ts'));
    const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    expect(r.code).toBe(1);
    // Exactly the head blob's one match: nothing from the link target.
    expect(sources(parse(r.stdout))).toEqual(['src/swapped.ts|aws-access|head']);
  });

  itPosix('text output blocks too and never prints the all-clear', async () => {
    swapForLink('harmless.ts');
    const r = await capture(() => scanCommand('.', 'text', false, undefined, 'base-snapshot'));
    expect(r.code).toBe(1);
    expect(`${r.log}\n${r.err}`).not.toMatch(/No secrets found/);
  });

  itPosix('A9: the swap moves neither fingerprint of the head blob\'s finding', async () => {
    const before = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    const unswapped = fingerprintsOf(before.stdout, path.join('src', 'swapped.ts'));
    expect(unswapped).toHaveLength(1);
    expect(unswapped[0].content_fingerprint).toBeDefined();
    swapForLink('harmless.ts');
    const after = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    expect(fingerprintsOf(after.stdout, path.join('src', 'swapped.ts'))).toEqual(unswapped);
  });

  itPosix('two named targets, one swapped for a link to a directory in the repository: blocks on the head blob', async () => {
    swapForLink('../docs');
    const r = await capture(() =>
      scanCommand(['src/app.ts', 'src/swapped.ts'], 'json', false, undefined, 'base-snapshot'),
    );
    expect(r.code).toBe(1);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual(['src/swapped.ts|aws-access|head']);
    expect(doc.diagnostics?.some(d => d.code === 'symlink.not_followed')).toBe(true);
  });

  itPosix('check --trust-base with the same two named targets blocks too', async () => {
    swapForLink('../docs');
    const r = await capture(() => checkCommand(['src/app.ts', 'src/swapped.ts'], undefined, 'base-snapshot'));
    expect(r.code).toBe(1);
  });

  itPosix('a single named target swapped for a link to a file blocks on the head blob, not the target', async () => {
    write(outside, 'target.ts', `export const other = "${AWS_KEY_2}";\n`);
    swapForLink(path.join(outside, 'target.ts'));
    const r = await capture(() => scanCommand(['src/swapped.ts'], 'json', false, undefined, 'base-snapshot'));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['src/swapped.ts|aws-access|head']);
  });

  itPosix('plain mode keeps its documented known limit: the swapped file is dropped', async () => {
    swapForLink('harmless.ts');
    const r = await capture(() => scanCommand('.', 'json'));
    expect(r.code).toBe(0);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual([]);
  });
});

describe('trust-base: a swapped link cannot borrow another file\'s baseline entry', () => {
  const originalCwd = process.cwd();
  let dir: string;

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  /**
   * The base accepts a key in src/accepted.ts. The head rotates accepted.ts
   * and adds the same key in a new src/new.ts. A copy into another file is a
   * new key, so the head blocks; swapping new.ts's working copy for a link to
   * accepted.ts must not change that.
   */
  async function seed(): Promise<void> {
    dir = tmpDir('vg-disk-swap-baseline-');
    process.chdir(dir);
    initRepo(dir);
    write(dir, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    write(dir, 'src/accepted.ts', `export const k = "${AWS_KEY}";\n`);
    const first = await capture(() => scanCommand('.', 'json'));
    const entries = parse(first.stdout).results.flatMap(r =>
      r.matches.map(m => ({
        fingerprint: m.content_fingerprint,
        rule: m.type,
        file: r.file,
        line: m.line,
        severity: m.severity,
        count: 1,
      })),
    );
    expect(entries).toHaveLength(1);
    write(dir, '.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: [], entries }, null, 2));
    commitAll(dir, 'base with baseline');
    git(dir, ['branch', 'base-snapshot']);
    git(dir, ['checkout', '-q', '-b', 'feature']);
    write(dir, 'src/accepted.ts', 'export const k = process.env.K;\n');
    write(dir, 'src/new.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'head rotates and copies');
  }

  itPosix('A13 control: without a swap the copied key blocks', async () => {
    await seed();
    const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['src/new.ts|aws-access|head']);
  });

  itPosix('A13: after swapping new.ts for a link to accepted.ts the key still blocks, reported on src/new.ts', async () => {
    await seed();
    const p = path.join(dir, 'src', 'new.ts');
    fs.rmSync(p);
    fs.symlinkSync('accepted.ts', p);
    const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    expect(r.code).toBe(1);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual(['src/new.ts|aws-access|head']);
    expect(doc.run.baseline_suppressed ?? 0).toBe(0);
  });
});
