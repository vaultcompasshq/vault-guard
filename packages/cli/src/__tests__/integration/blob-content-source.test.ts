import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';
import { baselineCommand } from '../../commands/baseline';
import {
  AWS_KEY,
  AWS_KEY_2,
  capture,
  commitAll,
  git,
  gitStub,
  initRepo,
  parse,
  pemKey,
  runCli,
  sources,
  stubCalls,
  subcommand,
  tmpDir,
  write,
} from './git-fixture';

/**
 * Tracked content is read from git, not from the checkout (design
 * 2026-10-12, section 2). Each test names the fixture or unit row of the
 * design's section 7 it implements and the mutation it kills.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

function utf16le(text: string, bom = false): Buffer {
  const body = Buffer.from(text, 'utf16le');
  return bom ? Buffer.concat([Buffer.from([0xff, 0xfe]), body]) : body;
}

function utf16be(text: string): Buffer {
  const le = Buffer.from(text, 'utf16le');
  return Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(le).swap16()]);
}

/** Child processes of this test process, as `pgrep -P` lists them (pgrep excludes itself). */
function childrenOfThisProcess(): string {
  const p = spawnSync('pgrep', ['-P', String(process.pid)], { encoding: 'utf-8' });
  return (p.stdout ?? '').trim();
}

function sha256(b: Buffer): string {
  return createHash('sha256').update(b).digest('hex');
}

describe('tracked content comes from git blobs', () => {
  const originalCwd = process.cwd();
  const originalPath = process.env.PATH;
  const dirs: string[] = [];

  function fresh(prefix = 'vg-blob-'): string {
    const d = tmpDir(prefix);
    dirs.push(d);
    return d;
  }

  afterEach(() => {
    process.chdir(originalCwd);
    process.env.PATH = originalPath;
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  /**
   * F1's repository: a base commit, a head commit adding src/leak.ts with a
   * key, and a head commit adding a .gitattributes that re-encodes it as
   * BOM-less UTF-16LE on checkout. Returned as a fresh clone, so the checkout
   * applies the attribute.
   */
  function attributeClone(attrPath = '.gitattributes', attrLine = 'src/leak.ts working-tree-encoding=UTF-16LE'): string {
    const src = fresh('vg-blob-src-');
    initRepo(src);
    write(src, 'app.ts', 'export const a = 1;\n');
    commitAll(src, 'base');
    git(src, ['branch', 'base']);
    write(src, 'src/leak.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(src, 'add leak');
    write(src, attrPath, `${attrLine}\n`);
    // Only the attributes file: re-adding leak.ts under the new attribute
    // would make git try to read its UTF-8 bytes as UTF-16LE.
    git(src, ['add', attrPath]);
    git(src, ['commit', '-q', '-m', 'add attributes']);
    const parent = fresh('vg-blob-clone-');
    const clone = path.join(parent, 'c');
    git(parent, ['clone', '-q', src, 'c']);
    git(clone, ['config', 'user.email', 'test@example.invalid']);
    git(clone, ['config', 'user.name', 'Test']);
    return clone;
  }

  itPosix('F1: a head-side working-tree-encoding does not hide a key under --trust-base', async () => {
    const clone = attributeClone();
    const disk = fs.readFileSync(path.join(clone, 'src/leak.ts'));
    // The checkout really did write BOM-less UTF-16LE: the case is real.
    expect(disk[0]).not.toBe(0xff);
    expect(disk[1]).toBe(0);
    process.chdir(clone);
    const r = await capture(() => scanCommand('.', 'json', false, undefined, 'origin/base'));
    expect(r.code).toBe(1);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual(['src/leak.ts|aws-access|head']);
    expect(doc.results[0].matches[0].severity).toBe('critical');
    expect(doc.run.content_source).toBe('git');
  });

  itPosix('F2: the same attribute does not hide a key in a plain scan', async () => {
    const clone = attributeClone();
    process.chdir(clone);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual(['src/leak.ts|aws-access|index']);
    expect(doc.run.worktree_copies_scanned).toBe(0);
  });

  itPosix('F4: --staged still reads the staged blob of a re-encoded file', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, '.gitattributes', 'src/leak.ts working-tree-encoding=UTF-16LE\n');
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    write(dir, 'src/leak.ts', utf16le(`export const k = "${AWS_KEY}";\n`));
    git(dir, ['add', 'src/leak.ts']);
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', true));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['src/leak.ts|aws-access|index']);
  });

  it('F5: an unstaged edit that adds a key is found and labelled worktree', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    write(dir, 'app.ts', `export const a = 1;\nexport const k = "${AWS_KEY}";\n`);
    process.chdir(dir);
    const json = await capture(() => scanCommand('.', 'json', false));
    expect(json.code).toBe(1);
    const doc = parse(json.stdout);
    expect(sources(doc)).toEqual(['app.ts|aws-access|worktree']);
    expect(doc.run.worktree_copies_scanned).toBe(1);
    const text = await capture(() => scanCommand('.', 'text', false));
    expect(text.code).toBe(1);
    expect(text.log).toContain('(working tree, not in the index)');
    expect(text.log).toContain('Tracked files whose working-tree copy differs, both scanned: 1');
  });

  it('F5: under --trust-base a disk copy edited after checkout is scanned and labelled worktree', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    git(dir, ['branch', 'base']);
    write(dir, 'lib.ts', 'export const b = 2;\n');
    commitAll(dir, 'head');
    // Not committed: the disk copy differs from the HEAD blob.
    write(dir, 'lib.ts', `export const b = 2;\nexport const k = "${AWS_KEY}";\n`);
    process.chdir(dir);
    const json = await capture(() => scanCommand('.', 'json', false, undefined, 'base'));
    expect(json.code).toBe(1);
    const doc = parse(json.stdout);
    expect(sources(doc)).toEqual(['lib.ts|aws-access|worktree']);
    expect(doc.run.worktree_copies_scanned).toBe(1);
    const text = await capture(() => scanCommand('.', 'text', false, undefined, 'base'));
    expect(text.log).toContain('(working tree, not committed)');
  });

  it('F5: a clean tree prints no copy labels and no differs line', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'base');
    process.chdir(dir);
    const text = await capture(() => scanCommand('.', 'text', false));
    expect(text.code).toBe(1);
    expect(text.log).not.toContain('(index)');
    expect(text.log).not.toContain('both scanned');
  });

  it('F6: a staged key whose working copy was reverted is found by a plain scan', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    write(dir, 'app.ts', `export const k = "${AWS_KEY}";\n`);
    git(dir, ['add', 'app.ts']);
    write(dir, 'app.ts', 'export const a = 1;\n');
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['app.ts|aws-access|index']);
  });

  itPosix('F7: a key behind a filter driver is found from the working-tree copy', async () => {
    const dir = fresh();
    initRepo(dir);
    const rot = 'tr A-Za-z N-ZA-Mn-za-m';
    git(dir, ['config', 'filter.rot.clean', rot]);
    git(dir, ['config', 'filter.rot.smudge', rot]);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    git(dir, ['branch', 'base']);
    write(dir, '.gitattributes', 'secret.txt filter=rot\n');
    write(dir, 'secret.txt', `key = ${AWS_KEY}\n`);
    commitAll(dir, 'filtered');
    // The blob is the rotated form; the disk holds the key.
    expect(git(dir, ['cat-file', 'blob', 'HEAD:secret.txt'])).not.toContain(AWS_KEY);
    expect(fs.readFileSync(path.join(dir, 'secret.txt'), 'utf-8')).toContain(AWS_KEY);
    process.chdir(dir);
    const plain = await capture(() => scanCommand('.', 'json', false));
    expect(plain.code).toBe(1);
    expect(sources(parse(plain.stdout))).toEqual(['secret.txt|aws-access|worktree']);
    const pr = await capture(() => scanCommand('.', 'json', false, undefined, 'base'));
    expect(pr.code).toBe(1);
    expect(sources(parse(pr.stdout))).toEqual(['secret.txt|aws-access|worktree']);
  });

  it('F8: a missing blob is exit 2 naming the file', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    write(dir, 'gone.ts', 'export const gone = "only in the object store";\n');
    commitAll(dir, 'base');
    const oid = git(dir, ['rev-parse', 'HEAD:gone.ts']).trim();
    fs.rmSync(path.join(dir, '.git', 'objects', oid.slice(0, 2), oid.slice(2)));
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(2);
    const doc = parse(r.stdout);
    expect(doc.run.unscannable).toEqual([{ file: 'gone.ts', kind: 'read_error', exclude: '/gone.ts' }]);
    expect(r.err).toContain('gone.ts');
    expect(r.err).toContain('not in the local object store');
  });

  itPosix('F9: a failing cat-file is exit 2 quoting git', () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'base');
    const log = path.join(fresh('vg-blob-log-'), 'git.log');
    const bin = gitStub(path.dirname(log), log, {
      fail: 'cat-file',
      failMessage: 'fatal: stubbed cat-file failure',
    });
    const r = runCli(['scan', '.'], dir, { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}` });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('fatal: stubbed cat-file failure');
    expect(r.stderr).toContain('could not read committed content for tracked files');
  });

  describe('F18: files git has been told not to look at', () => {
    function template(): string {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'config/local.json', '{ "aws_access_key_id": "" }\n');
      commitAll(dir, 'template');
      return dir;
    }

    it('F18: a key in a skip-worktree or assume-unchanged file is found from disk', async () => {
      for (const flag of ['--skip-worktree', '--assume-unchanged']) {
        const dir = template();
        git(dir, ['update-index', flag, 'config/local.json']);
        write(dir, 'config/local.json', `{ "aws_access_key_id": "${AWS_KEY}" }\n`);
        // status is silent about the edit: the blob-only read would pass.
        expect(git(dir, ['status', '--porcelain'])).toBe('');
        process.chdir(dir);
        const r = await capture(() => scanCommand('.', 'json', false));
        expect({ flag, code: r.code }).toEqual({ flag, code: 1 });
        expect(sources(parse(r.stdout))).toEqual(['config/local.json|aws-access|worktree']);
        process.chdir(originalCwd);
      }
    });

    it('F18: an entry added while core.ignoreStat is true is read from disk too', async () => {
      const dir = template();
      git(dir, ['config', 'core.ignoreStat', 'true']);
      git(dir, ['rm', '-q', '--cached', 'config/local.json']);
      git(dir, ['add', 'config/local.json']);
      write(dir, 'config/local.json', `{ "aws_access_key_id": "${AWS_KEY}" }\n`);
      process.chdir(dir);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      expect(sources(parse(r.stdout))).toEqual(['config/local.json|aws-access|worktree']);
    });
  });

  itPosix('F21: an unsupported working-tree encoding is a coverage line, not exit 2', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'a.txt', 'clean a\n');
    write(dir, 'b.txt', 'clean b\n');
    commitAll(dir, 'base');
    write(dir, '.gitattributes', 'a.txt working-tree-encoding=UTF-32\nb.txt working-tree-encoding=UTF-16\n');
    git(dir, ['add', '.gitattributes']);
    git(dir, ['commit', '-q', '-m', 'attributes']);
    write(dir, 'a.txt', `clean a\nkey = ${AWS_KEY}\n`);
    write(dir, 'b.txt', utf16be(`clean b\nkey = ${AWS_KEY_2}\n`));
    process.chdir(dir);
    const json = await capture(() => scanCommand('.', 'json', false));
    expect(json.code).toBe(1);
    const doc = parse(json.stdout);
    expect(sources(doc)).toEqual(['a.txt|aws-access|worktree', 'b.txt|aws-access|worktree']);
    expect(doc.run.worktree_undecodable).toEqual([{ file: 'a.txt', encoding: 'UTF-32' }]);
    expect(doc.diagnostics?.some(d => d.code === 'encoding.unsupported')).toBe(true);
    const text = await capture(() => scanCommand('.', 'text', false));
    expect(text.code).toBe(1);
    expect(text.log).toContain(
      'Working-tree copies in an encoding vault-guard cannot decode, scanned as UTF-8: 1 (a.txt: UTF-32)',
    );
  });

  itPosix("U21: a BOM decides a disk copy's encoding before its declared label", async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'w.txt', 'clean\n');
    commitAll(dir, 'base');
    write(dir, '.gitattributes', 'w.txt working-tree-encoding=UTF-16LE\n');
    git(dir, ['add', '.gitattributes']);
    git(dir, ['commit', '-q', '-m', 'attributes']);
    // The label says little-endian; the BOM says big-endian, and wins.
    write(dir, 'w.txt', utf16be(`clean\nkey = ${AWS_KEY}\n`));
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['w.txt|aws-access|worktree']);
  });

  it('F22a: a staged key in a file deleted from disk is scanned from the index and counted missing', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    write(dir, 'new.ts', `export const k = "${AWS_KEY}";\n`);
    git(dir, ['add', 'new.ts']);
    fs.rmSync(path.join(dir, 'new.ts'));
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    const doc = parse(r.stdout);
    expect(sources(doc)).toEqual(['new.ts|aws-access|index']);
    expect(doc.run.tracked_files_missing).toBe(1);
  });

  it('F22b: a committed file removed with plain rm is counted, not scanned', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    write(dir, 'old.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'base');
    fs.rmSync(path.join(dir, 'old.ts'));
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(0);
    expect(parse(r.stdout).run.tracked_files_missing).toBe(1);
  });

  describe('F23: tracked symlinks named on the command line', () => {
    function linkRepo(): { dir: string; outside: string } {
      const dir = fresh();
      const outside = fresh('vg-blob-outside-');
      initRepo(dir);
      write(dir, 'secrets/k.txt', `key = ${AWS_KEY}\n`);
      write(outside, 'k.txt', `key = ${AWS_KEY_2}\n`);
      fs.symlinkSync('secrets/k.txt', path.join(dir, 'in.txt'));
      fs.symlinkSync(path.join(outside, 'k.txt'), path.join(dir, 'out.txt'));
      fs.symlinkSync('nowhere.txt', path.join(dir, 'dead.txt'));
      fs.symlinkSync('loop2.txt', path.join(dir, 'loop.txt'));
      fs.symlinkSync('loop.txt', path.join(dir, 'loop2.txt'));
      fs.symlinkSync('secrets', path.join(dir, 'dir.txt'));
      commitAll(dir, 'links');
      git(dir, ['branch', 'base', 'HEAD']);
      write(dir, 'touch.ts', 'export const t = 1;\n');
      commitAll(dir, 'head');
      return { dir, outside };
    }

    for (const mode of ['plain', 'trust-base'] as const) {
      const trust = mode === 'trust-base' ? 'base' : undefined;
      itPosix(`F23 (${mode}): a link inside the repository is followed and reported under its own name`, async () => {
        const { dir } = linkRepo();
        process.chdir(dir);
        const r = await capture(() => scanCommand('in.txt', 'json', false, undefined, trust));
        expect(r.code).toBe(1);
        expect(sources(parse(r.stdout))).toEqual(['in.txt|aws-access|worktree']);
      });

      itPosix(`F23 (${mode}): links outside, dangling, looping or to a directory are not followed`, async () => {
        const { dir } = linkRepo();
        process.chdir(dir);
        const cases: Array<[string, string]> = [
          ['out.txt', 'out.txt: symlink target is outside the repository, not followed'],
          ['dead.txt', 'dead.txt: symlink target does not exist, not followed'],
          ['loop.txt', 'loop.txt: symlink target cannot be resolved (a loop), not followed'],
          ['dir.txt', 'dir.txt: symlink target is not a regular file, not followed'],
        ];
        for (const [name, warning] of cases) {
          const text = await capture(() => scanCommand(name, 'text', false, undefined, trust));
          expect({ name, code: text.code }).toEqual({ name, code: 0 });
          expect(text.err).toContain(warning);
          const json = await capture(() => scanCommand(name, 'json', false, undefined, trust));
          const doc = parse(json.stdout);
          expect(doc.run.files_scanned).toBe(1);
          expect(doc.diagnostics?.some(d => d.code === 'symlink.not_followed')).toBe(true);
        }
      });
    }

    itPosix('F23d: a directory scan of the same tree still skips every link', async () => {
      const { dir } = linkRepo();
      process.chdir(dir);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      expect(parse(r.stdout).results.map(x => x.file)).toEqual(['secrets/k.txt']);
    });
  });

  it('U3: a blob over 32 MiB is too_large on its raw size, and its disk copy is not read', async () => {
    const dir = fresh();
    initRepo(dir);
    // Sizes are the smallest that still decide each case: just over the
    // 32 MiB limit for the over-limit files, just under it for the scanned one.
    const OVER = 32 * 1024 * 1024 + 64 * 1024;
    write(dir, 'big.txt', Buffer.alloc(OVER, 0x61));
    // UTF-16LE with a BOM, ASCII text, just over 32 MiB raw: about 16 MiB once
    // decoded, so only a limit judged on raw bytes refuses it.
    const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.alloc(OVER, 0)]);
    for (let i = 2; i < utf16.length; i += 2) utf16[i] = 0x62;
    write(dir, 'wide.txt', utf16);
    // Just under the limit, raw.
    const under = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.alloc(32 * 1024 * 1024 - 64, 0)]);
    for (let i = 2; i < under.length; i += 2) under[i] = 0x63;
    write(dir, 'under.txt', under);
    commitAll(dir, 'base');
    // An unstaged edit, so the disk copy of big.txt would be read if anything was.
    write(dir, 'big.txt', Buffer.alloc(OVER, 0x62));
    process.chdir(dir);
    const readFile = jest.spyOn(fs.promises, 'readFile');
    try {
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(2);
      const doc = parse(r.stdout);
      expect(doc.run.unscannable).toEqual(
        expect.arrayContaining([
          { file: 'big.txt', kind: 'too_large', exclude: '/big.txt' },
          { file: 'wide.txt', kind: 'too_large', exclude: '/wide.txt' },
        ]),
      );
      expect((doc.run.unscannable as unknown[]).length).toBe(2);
      expect(doc.run.files_scanned).toBe(1);
      expect(readFile.mock.calls.some(c => String(c[0]).endsWith('big.txt'))).toBe(false);
    } finally {
      readFile.mockRestore();
    }
  }, 60_000);

  it('U4: one object id at two paths is scanned at each path', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'a/k.ts', `export const k = "${AWS_KEY}";\n`);
    write(dir, 'b/k.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'base');
    expect(git(dir, ['rev-parse', 'HEAD:a/k.ts'])).toBe(git(dir, ['rev-parse', 'HEAD:b/k.ts']));
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['a/k.ts|aws-access|index', 'b/k.ts|aws-access|index']);
  });

  describe('U5: one report per distinct finding', () => {
    it('U5: the same key in blob and disk is reported once, from the blob', async () => {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'app.ts', `export const k = "${AWS_KEY}";\n`);
      commitAll(dir, 'base');
      write(dir, 'app.ts', `export const k = "${AWS_KEY}";\nexport const other = 2;\n`);
      process.chdir(dir);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(sources(parse(r.stdout))).toEqual(['app.ts|aws-access|index']);
    });

    it('U5: a second copy pasted only on disk is still reported', async () => {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'app.ts', `export const k = "${AWS_KEY}";\n`);
      commitAll(dir, 'base');
      write(dir, 'app.ts', `export const k = "${AWS_KEY}";\nexport const again = "${AWS_KEY}";\n`);
      process.chdir(dir);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(sources(parse(r.stdout))).toEqual(['app.ts|aws-access|index', 'app.ts|aws-access|worktree']);
    });

    it('U5: a baseline with count 1 spends its count on the blob, so the extra disk copy is the one reported', async () => {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'app.ts', `export const k = "${AWS_KEY}";\n`);
      commitAll(dir, 'base');
      process.chdir(dir);
      const w = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
      expect(w.code).toBe(0);
      commitAll(dir, 'baseline');
      write(dir, 'app.ts', `export const k = "${AWS_KEY}";\nexport const again = "${AWS_KEY}";\n`);
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      const doc = parse(r.stdout);
      expect(doc.run.baseline_suppressed).toBe(1);
      expect(sources(doc)).toEqual(['app.ts|aws-access|worktree']);
    });
  });

  describe('U6: header-only findings on both copies', () => {
    it('U6: a baselined PEM with an unstaged edit elsewhere reports the worktree copy and suppresses the index one', async () => {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'keys/id.pem', pemKey());
      commitAll(dir, 'base');
      process.chdir(dir);
      expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
      commitAll(dir, 'baseline');
      expect((await capture(() => scanCommand('.', 'json', false))).code).toBe(0);
      write(dir, 'keys/id.pem', `${pemKey()}# edited\n`);
      const r = await capture(() => scanCommand('.', 'json', false));
      const doc = parse(r.stdout);
      expect(doc.run.baseline_suppressed).toBe(1);
      expect(sources(doc)).toEqual(['keys/id.pem|ssh-private-key|worktree']);
    });

    it('U6: a key-body swap in an unstaged edit is reported', async () => {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'keys/id.pem', pemKey(0));
      commitAll(dir, 'base');
      process.chdir(dir);
      expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
      commitAll(dir, 'baseline');
      write(dir, 'keys/id.pem', pemKey(1));
      const r = await capture(() => scanCommand('.', 'json', false));
      expect(r.code).toBe(1);
      expect(sources(parse(r.stdout))).toEqual(['keys/id.pem|ssh-private-key|worktree']);
    });
  });

  describe('U7: conflicted paths', () => {
    function conflict(ours: string, theirs: string): string {
      const dir = fresh();
      initRepo(dir);
      write(dir, 'f.ts', 'export const base = 0;\n');
      commitAll(dir, 'base');
      git(dir, ['checkout', '-q', '-b', 'theirs']);
      write(dir, 'f.ts', theirs);
      commitAll(dir, 'theirs');
      git(dir, ['checkout', '-q', 'main']);
      write(dir, 'f.ts', ours);
      commitAll(dir, 'ours');
      try {
        git(dir, ['merge', '-q', 'theirs']);
      } catch {
        // The conflict is the point.
      }
      expect(git(dir, ['ls-files', '-s', 'f.ts']).split('\n').filter(Boolean).length).toBe(3);
      return dir;
    }

    it('U7: a key only in stage 3 is found once and labelled (index, theirs)', async () => {
      const dir = conflict('export const ours = 1;\n', `export const k = "${AWS_KEY}";\n`);
      process.chdir(dir);
      const json = await capture(() => scanCommand('.', 'json', false));
      expect(json.code).toBe(1);
      expect(sources(parse(json.stdout))).toEqual(['f.ts|aws-access|index']);
      const text = await capture(() => scanCommand('.', 'text', false));
      expect(text.log).toContain('(index, theirs)');
    });

    it('U7: the same key in stages 2 and 3 is found once, from stage 2', async () => {
      const dir = conflict(
        `export const k = "${AWS_KEY}";\nexport const ours = 1;\n`,
        `export const k = "${AWS_KEY}";\nexport const theirs = 2;\n`,
      );
      process.chdir(dir);
      const json = await capture(() => scanCommand('.', 'json', false));
      expect(sources(parse(json.stdout))).toEqual(['f.ts|aws-access|index']);
      const text = await capture(() => scanCommand('.', 'text', false));
      expect(text.log).toContain('(index, ours)');
      expect(text.log).not.toContain('(index, theirs)');
    });
  });

  it('U8: an intent-to-add file holding a key is found from the working tree', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    write(dir, 'new.ts', `export const k = "${AWS_KEY}";\n`);
    git(dir, ['add', '-N', 'new.ts']);
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(1);
    expect(sources(parse(r.stdout))).toEqual(['new.ts|aws-access|worktree']);
  });

  it('U9: fingerprints from the blob equal fingerprints from disk for an untransformed tree', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'crlf.ts', Buffer.from(`// line one\r\n// line two\r\nexport const k = "${AWS_KEY}";\r\n`));
    write(dir, 'bom8.ts', Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(`export const k = "${AWS_KEY_2}";\n`)]));
    write(dir, 'wide.txt', utf16le(`one\ntwo\nkey = ${AWS_KEY}\n`, true));
    // Non-ASCII text before the finding, built from code points so this
    // source file stays ASCII.
    const accents = String.fromCodePoint(0x63, 0x61, 0x66, 0xe9, 0x20, 0xfc, 0x62, 0x65, 0x72, 0x20, 0x4e2d, 0x6587);
    write(dir, 'accents.ts', `// ${accents}\nexport const k = "${AWS_KEY_2}";\n`);
    write(dir, 'keys/id.pem', pemKey());
    commitAll(dir, 'base');
    // The same files, outside git: read from disk.
    const copy = fresh('vg-blob-copy-');
    for (const f of ['crlf.ts', 'bom8.ts', 'wide.txt', 'accents.ts', 'keys/id.pem']) {
      write(copy, f, fs.readFileSync(path.join(dir, f)));
    }
    process.chdir(dir);
    const fromBlob = parse((await capture(() => scanCommand('.', 'json', false))).stdout);
    expect(fromBlob.run.content_source).toBe('git');
    process.chdir(copy);
    const fromDisk = parse((await capture(() => scanCommand('.', 'json', false))).stdout);
    expect(fromDisk.run.content_source).toBe('disk');
    const keys = (d: typeof fromBlob): string[] =>
      d.results
        .flatMap(r => r.matches.map(m => `${r.file}|${m.type}|${m.line}|${m.offset}|${m.fingerprint}|${m.content_fingerprint ?? ''}`))
        .sort();
    expect(keys(fromBlob).length).toBe(5);
    expect(keys(fromBlob)).toEqual(keys(fromDisk));
    process.chdir(dir);
    expect((await capture(() => baselineCommand('.', { write: true, includeCritical: true }))).code).toBe(0);
    const doc = JSON.parse(fs.readFileSync(path.join(dir, '.vault-guard.baseline.json'), 'utf-8')) as {
      entries: Array<{ rule: string; file_digest?: string }>;
    };
    const pem = doc.entries.find(e => e.rule === 'ssh-private-key');
    expect(pem?.file_digest).toBe(sha256(fs.readFileSync(path.join(dir, 'keys/id.pem'))));
  });

  itPosix('U10: a header-only entry written on a CRLF checkout matches on the next scan', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, '.gitattributes', '*.ts text eol=crlf\n');
    write(dir, 'keys.ts', `export const k = "${AWS_KEY}";\nexport const pem = \`\n${pemKey()}\`;\n`);
    commitAll(dir, 'base');
    fs.rmSync(path.join(dir, 'keys.ts'));
    git(dir, ['checkout', '--', 'keys.ts']);
    const disk = fs.readFileSync(path.join(dir, 'keys.ts'));
    const blob = Buffer.from(git(dir, ['cat-file', 'blob', 'HEAD:keys.ts']), 'utf-8');
    // The case is real: CRLF on disk, LF in the blob.
    expect(disk.includes(Buffer.from('\r\n'))).toBe(true);
    expect(blob.includes(Buffer.from('\r\n'))).toBe(false);
    expect(disk.equals(blob)).toBe(false);
    process.chdir(dir);
    const w = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
    expect(w.code).toBe(0);
    const doc = JSON.parse(fs.readFileSync(path.join(dir, '.vault-guard.baseline.json'), 'utf-8')) as {
      entries: Array<{ rule: string; file_digest?: string }>;
    };
    const pem = doc.entries.find(e => e.rule === 'ssh-private-key');
    expect(pem?.file_digest).toBe(sha256(blob));
    expect(pem?.file_digest).not.toBe(sha256(disk));
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(0);
    expect(parse(r.stdout).run.baseline_suppressed).toBe(2);
  });

  it('U11: baseline --write does not accept a finding that exists only in an uncommitted edit', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    write(dir, 'app.ts', `export const a = 1;\nexport const k = "${AWS_KEY}";\n`);
    process.chdir(dir);
    const w = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
    expect(w.code).toBe(0);
    expect(w.log).toContain('uncommitted working-tree edits with findings: 1 (not accepted; stage or revert them)');
    const doc = JSON.parse(fs.readFileSync(path.join(dir, '.vault-guard.baseline.json'), 'utf-8')) as {
      entries: unknown[];
    };
    expect(doc.entries).toEqual([]);
  });

  itPosix('U12: a failing HEAD tree listing is exit 2 even beside a file target that scans', async () => {
    const dir = fresh();
    initRepo(dir);
    write(dir, 'app.ts', 'export const a = 1;\n');
    commitAll(dir, 'base');
    git(dir, ['branch', 'base']);
    write(dir, 'b.ts', 'export const b = 2;\n');
    commitAll(dir, 'head');
    const log = path.join(fresh('vg-blob-log-'), 'git.log');
    const bin = gitStub(path.dirname(log), log, { fail: 'ls-tree', failMessage: 'fatal: stubbed ls-tree failure' });
    process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ''}`;
    process.chdir(dir);
    const r = await capture(() => scanCommand(['.', 'app.ts'], 'json', false, undefined, 'base'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('Cannot establish the trust base');
  });

  describe('U18: tracked files named on the command line', () => {
    itPosix('U18: a named file under --trust-base is read from the HEAD blob', async () => {
      const clone = attributeClone();
      process.chdir(clone);
      const r = await capture(() => scanCommand('src/leak.ts', 'json', false, undefined, 'origin/base'));
      expect(r.code).toBe(1);
      expect(sources(parse(r.stdout))).toEqual(['src/leak.ts|aws-access|head']);
    });

    itPosix('U18: three named files across a repository and a submodule: one listing per repository', async () => {
      const sub = fresh('vg-blob-sub-');
      initRepo(sub);
      write(sub, 'lib/key.ts', `export const k = "${AWS_KEY}";\n`);
      write(sub, 'lib/other.ts', 'export const o = 1;\n');
      commitAll(sub, 'sub');
      const dir = fresh();
      initRepo(dir);
      write(dir, 'a.ts', 'export const a = 1;\n');
      write(dir, 'b.ts', `export const b = "${AWS_KEY_2}";\n`);
      commitAll(dir, 'base');
      git(dir, ['-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', sub, 'sub']);
      commitAll(dir, 'submodule');
      // The submodule's working copy is UTF-16 on disk; only its own object
      // store holds the UTF-8 blob the key is found in.
      write(dir, 'sub/lib/key.ts', utf16le(`export const k = "${AWS_KEY}";\n`));
      git(path.join(dir, 'sub'), ['update-index', '--assume-unchanged', 'lib/key.ts']);
      const log = path.join(fresh('vg-blob-log-'), 'git.log');
      const bin = gitStub(path.dirname(log), log);
      process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ''}`;
      process.chdir(dir);
      const r = await capture(() => scanCommand(['a.ts', 'b.ts', 'sub/lib/key.ts'], 'json', false));
      expect(r.code).toBe(1);
      expect(sources(parse(r.stdout))).toEqual(['b.ts|aws-access|index', 'sub/lib/key.ts|aws-access|index']);
      const calls = stubCalls(log);
      const listings = calls.filter(c => subcommand(c.args) === 'ls-files' && c.args.includes('-v'));
      expect(listings.map(c => fs.realpathSync(c.cwd)).sort()).toEqual(
        [fs.realpathSync(dir), fs.realpathSync(path.join(dir, 'sub'))].sort(),
      );
      const batches = calls.filter(c => subcommand(c.args) === 'cat-file' && c.args.includes('--batch'));
      expect(batches.map(c => fs.realpathSync(c.cwd)).sort()).toEqual(
        [fs.realpathSync(dir), fs.realpathSync(path.join(dir, 'sub'))].sort(),
      );
    });
  });

  itPosix('a scan that fails while reading blobs leaves no git process running', async () => {
    // A submodule whose cat-file --batch fails, beside outer files whose
    // reads are in flight at the same moment: the run exits 2, and every
    // reader it started is closed, so nothing it spawned outlives it.
    const sub = fresh('vg-blob-sub-');
    initRepo(sub);
    for (let i = 0; i < 5; i++) write(sub, `lib/s${i}.ts`, `export const s${i} = ${i};\n`);
    commitAll(sub, 'sub');
    const dir = fresh();
    initRepo(dir);
    for (let i = 0; i < 40; i++) write(dir, `z/f${i}.ts`, `export const f${i} = ${i};\n`);
    commitAll(dir, 'base');
    git(dir, ['-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', sub, 'a-sub']);
    commitAll(dir, 'submodule');
    const log = path.join(fresh('vg-blob-log-'), 'git.log');
    const bin = gitStub(path.dirname(log), log, {
      fail: 'cat-file',
      failArg: '--batch',
      failCwdSuffix: `${path.sep}a-sub`,
      failMessage: 'fatal: stubbed cat-file failure in the submodule',
    });
    process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ''}`;
    process.chdir(dir);
    const r = await capture(() => scanCommand('.', 'json', false));
    expect(r.code).toBe(2);
    expect(r.err).toContain('stubbed cat-file failure in the submodule');
    // Every child of this process (the git stubs and their git) has already
    // exited when the scan returns: the scan waits for them, no polling here.
    expect(childrenOfThisProcess()).toBe('');
  }, 60_000);

  itPosix('no git process is alive when a plain, pull-request or staged scan returns', async () => {
    const dir = fresh();
    initRepo(dir);
    for (let i = 0; i < 25; i++) write(dir, `src/f${i}.ts`, `export const f${i} = ${i};\n`);
    commitAll(dir, 'base');
    git(dir, ['branch', 'base']);
    write(dir, 'src/leak.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'head');
    write(dir, 'src/staged.ts', `export const s = "${AWS_KEY_2}";\n`);
    git(dir, ['add', 'src/staged.ts']);
    process.chdir(dir);
    const runs: Array<[string, () => Promise<number>]> = [
      ['plain', () => scanCommand('.', 'json', false)],
      ['trust-base', () => scanCommand('.', 'json', false, undefined, 'base')],
      ['staged', () => scanCommand('.', 'json', true)],
    ];
    for (const [mode, run] of runs) {
      const r = await capture(run);
      expect({ mode, code: r.code }).toEqual({ mode, code: 1 });
      expect({ mode, children: childrenOfThisProcess() }).toEqual({ mode, children: '' });
    }
  }, 60_000);

  itPosix('U1: blob reads use at most two cat-file processes per repository', () => {
    const dir = fresh();
    initRepo(dir);
    for (let i = 0; i < 200; i++) write(dir, `src/f${i}.ts`, `export const v${i} = ${i};\n`);
    write(dir, 'src/leak.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'base');
    const log = path.join(fresh('vg-blob-log-'), 'git.log');
    const bin = gitStub(path.dirname(log), log);
    const r = runCli(['scan', '.', '--format', 'json'], dir, {
      ...process.env,
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
    });
    expect(r.code).toBe(1);
    const calls = stubCalls(log);
    const isRootLookup = (c: { args: string[] }): boolean =>
      subcommand(c.args) === 'rev-parse' &&
      c.args.includes('--show-toplevel') &&
      !(c.args.length === 4 && c.args[0] === '-c' && c.args[1] === 'core.quotePath=false');
    const roots = calls.filter(isRootLookup);
    const fileSet = calls.filter(c => !isRootLookup(c));
    expect(roots.length).toBe(2);
    expect(fileSet.map(c => subcommand(c.args))).toEqual([
      'rev-parse', 'ls-files', 'status', 'check-attr', 'ls-files', 'ls-files', 'ls-files', 'cat-file', 'cat-file',
    ]);
    expect(fileSet.filter(c => subcommand(c.args) === 'cat-file').length).toBeLessThanOrEqual(2);
    expect(calls.some(c => subcommand(c.args) === 'show')).toBe(false);
  }, 60_000);
});
