import * as fs from 'fs';
import * as path from 'path';

import { ATTRIBUTES_PROPOSAL_LINE } from '@vaultcompass/vault-guard-core';
import { scanCommand } from '../../commands/scan';
import { AWS_KEY, capture, commitAll, git, initRepo, parse, tmpDir, write, type JsonDoc } from './git-fixture';
import { firstStderrLine, posixTar, realMp4, realPng, seeded } from './binary-fixtures';

/**
 * Binary skips by content agreement (design 2026-10-17, section 11.1). Every
 * fixture whose subject may be skipped also holds a clean src/ok.ts, so a run
 * whose subject is skipped does not exit 2 through "nothing was scanned".
 */

const itPosix = process.platform === 'win32' ? it.skip : it;
const KEY_LINE = `aws_access_key_id = ${AWS_KEY}\n`;

type Mode = 'plain' | 'trust-base' | 'staged';

describe('binary skips need the name and the bytes to agree', () => {
  const originalCwd = process.cwd();
  const dirs: string[] = [];

  afterEach(() => {
    process.chdir(originalCwd);
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function fresh(): string {
    const d = tmpDir('vg-bin-');
    dirs.push(d);
    initRepo(d);
    write(d, 'src/ok.ts', 'export const ok = 1;\n');
    return d;
  }

  /**
   * One subject file in a mode: plain and trust-base commit it on top of a
   * base commit tagged `base`; staged only stages it.
   */
  async function runMode(mode: Mode, files: Record<string, Buffer | string>, format: 'json' | 'text' = 'json') {
    const d = fresh();
    commitAll(d, 'base');
    git(d, ['tag', 'base']);
    for (const [rel, data] of Object.entries(files)) write(d, rel, data);
    if (mode === 'staged') {
      git(d, ['add', '-A', '-f']);
    } else {
      commitAll(d, 'head');
    }
    process.chdir(d);
    const r = await capture(() =>
      mode === 'staged'
        ? scanCommand('.', format, true)
        : mode === 'trust-base'
          ? scanCommand('.', format, false, undefined, 'base')
          : scanCommand('.', format),
    );
    return { ...r, dir: d, doc: format === 'json' ? parse(r.stdout) : (undefined as unknown as JsonDoc) };
  }

  const run = (doc: JsonDoc): Record<string, unknown> => doc.run;
  const mismatch = (doc: JsonDoc): unknown => run(doc).binary_type_mismatch;

  describe('A1: config/credentials.mov holding a key is scanned in every mode', () => {
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s: exit 1, a video mismatch, a warning', async mode => {
      const r = await runMode(mode, { 'config/credentials.mov': KEY_LINE });
      expect(r.code).toBe(1);
      expect(run(r.doc).binary_type_mismatch_scanned).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'config/credentials.mov', family: 'video' }]);
      expect(r.doc.diagnostics).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ code: 'file.type_mismatch', severity: 'warning', ctx: { file: 'config/credentials.mov', family: 'video' } }),
        ]),
      );
    });
  });

  describe('A2: credentials.png holding a key is scanned', () => {
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s: exit 1, an image mismatch', async mode => {
      const r = await runMode(mode, { 'config/credentials.png': KEY_LINE });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'config/credentials.png', family: 'image' }]);
      expect(run(r.doc).binary_files_skipped).toBe(0);
    });
  });

  describe('A3: the extension is compared case-insensitively', () => {
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s: credentials.PNG holding a key exits 1', async mode => {
      const r = await runMode(mode, { 'config/credentials.PNG': KEY_LINE });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'config/credentials.PNG', family: 'image' }]);
    });

    it('named on the command line beside src/ok.ts: exit 1', async () => {
      const d = fresh();
      write(d, 'config/credentials.PNG', KEY_LINE);
      commitAll(d, 'head');
      process.chdir(d);
      const r = await capture(() => scanCommand(['config/credentials.PNG', 'src/ok.ts'], 'json'));
      expect(r.code).toBe(1);
      expect(parse(r.stdout).run.binary_type_mismatch_scanned).toBe(1);
    });
  });

  describe('A4: dump.bin of UTF-8 text with no NUL is scanned', () => {
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s: exit 1, family other', async mode => {
      const r = await runMode(mode, { 'dump.bin': `HOME=/home/a\n${KEY_LINE}` });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'dump.bin', family: 'other' }]);
    });
  });

  describe('A21: dump.bin of NUL-separated records (the env -0 shape) is scanned', () => {
    const body = Buffer.from(['HOME=/home/a', 'SHELL=/bin/zsh', `AWS_ACCESS_KEY_ID=${AWS_KEY}`, 'LANG=C', ''].join('\0'));
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s: exit 1, family other', async mode => {
      const r = await runMode(mode, { 'dump.bin': body });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'dump.bin', family: 'other' }]);
    });
  });

  describe('A24: dump.bin in Windows-1252 (the set > dump.bin shape) is scanned', () => {
    const body = Buffer.concat([
      Buffer.from('HOMEDRIVE=C:\r\nUSERNAME=Ren', 'latin1'),
      Buffer.from([0xe9]),
      Buffer.from(`\r\nAWS_ACCESS_KEY_ID=${AWS_KEY}\r\nOS=Windows_NT\r\n`, 'latin1'),
    ]);
    it.each(['plain', 'trust-base', 'staged'] as Mode[])('%s: exit 1, family other', async mode => {
      const r = await runMode(mode, { 'dump.bin': body });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'dump.bin', family: 'other' }]);
    });
  });

  describe('A25: a printable signature with only invalid UTF-8 after it is scanned', () => {
    const body = Buffer.concat([
      Buffer.from('abcdfree caf', 'latin1'),
      Buffer.from([0xe9]),
      Buffer.from(` notes\n${KEY_LINE}`, 'latin1'),
    ]);
    it.each(['plain', 'trust-base'] as Mode[])('%s: intro.mov exits 1, a video mismatch', async mode => {
      const r = await runMode(mode, { 'intro.mov': body });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'intro.mov', family: 'video' }]);
    });
  });

  describe('A6: song.ogg of OggS followed by ASCII text is scanned', () => {
    it('plain: exit 1, mismatch counted', async () => {
      const r = await runMode('plain', { 'song.ogg': `OggS ${KEY_LINE}` });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'song.ogg', family: 'audio' }]);
    });
  });

  describe('A5: a UTF-16LE notes.bin with a BOM is scanned', () => {
    it('plain: exit 1, the finding at line 2', async () => {
      const text = `first \u0101 line\n${KEY_LINE}`;
      const r = await runMode('plain', { 'notes.bin': Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]) });
      expect(r.code).toBe(1);
      const m = r.doc.results.find(x => x.file === 'notes.bin');
      expect(m?.matches[0].line).toBe(2);
    });
  });

  describe('A7: the documented boundaries, pinned', () => {
    it('a valid ftyp header followed by text is skipped', async () => {
      const body = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70]), Buffer.from(KEY_LINE)]);
      const r = await runMode('plain', { 'clip.mp4': body });
      expect(r.code).toBe(0);
      expect(run(r.doc).binary_files_skipped).toBe(1);
    });

    it('a POSIX tar holding a .env with a key is skipped', async () => {
      const r = await runMode('plain', { 'bundle.tar': posixTar('.env', Buffer.from(KEY_LINE)) });
      expect(r.code).toBe(0);
      expect(run(r.doc).binary_files_skipped).toBe(1);
      expect((run(r.doc).binary_files_skipped_by_family as Record<string, number>).archive).toBe(1);
    });
  });

  describe('A8: a 40 MiB real-header .mp4 is skipped at any size', () => {
    const big = realMp4(40 * 1024 * 1024, 21);
    it.each(['plain', 'trust-base', 'staged'] as Mode[])(
      '%s: exit 0, family video, files_scanned 1',
      async mode => {
        const r = await runMode(mode, { 'media/clip.mp4': big });
        expect(r.err).not.toMatch(/INCOMPLETE/);
        expect(r.code).toBe(0);
        expect(run(r.doc).binary_files_skipped).toBe(1);
        expect((run(r.doc).binary_files_skipped_by_family as Record<string, number>).video).toBe(1);
        if (mode !== 'staged') expect(run(r.doc).files_scanned).toBe(1);
      },
      120_000,
    );
  });

  describe('A9: anything scanned as text over 32 MiB is exit 2, and the first stderr line names it', () => {
    it('a 33 MiB credentials.mov that is text', async () => {
      const body = Buffer.alloc(33 * 1024 * 1024, 0x61);
      Buffer.from(KEY_LINE).copy(body, 0);
      const r = await runMode('plain', { 'credentials.mov': body });
      expect(r.code).toBe(2);
      expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: credentials\.mov\. /);
    }, 120_000);

    it('a 32.1 MiB data/export.json', async () => {
      const body = Buffer.alloc(Math.ceil(32.1 * 1024 * 1024), 0x20);
      body[0] = 0x5b;
      body[body.length - 1] = 0x5d;
      const r = await runMode('plain', { 'data/export.json': body });
      expect(r.code).toBe(2);
      expect(firstStderrLine(r.err)).toMatch(/^INCOMPLETE: First: data\/export\.json\. 1 file/);
    }, 120_000);
  });

  describe('A11: copies are classified per copy', () => {
    it('a real logo.png blob with a text disk copy: the key is found in the working tree', async () => {
      const d = fresh();
      write(d, 'logo.png', realPng());
      commitAll(d, 'head');
      write(d, 'logo.png', KEY_LINE);
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(1);
      expect(doc.results.find(x => x.file === 'logo.png')?.matches[0].source).toBe('worktree');
      expect(doc.run.binary_type_mismatch).toEqual([{ file: 'logo.png', family: 'image' }]);
    });
  });

  describe('A12: no attribute is consulted by the classifier', () => {
    it('a head .gitattributes marking credentials.mov binary changes nothing but adds the proposal', async () => {
      const r = await runMode('trust-base', {
        'config/credentials.mov': KEY_LINE,
        '.gitattributes': 'config/credentials.mov binary -diff -text\n',
      });
      expect(r.code).toBe(1);
      expect(mismatch(r.doc)).toEqual([{ file: 'config/credentials.mov', family: 'video' }]);
      expect(r.doc.trustBase?.proposals.some(p => p.startsWith(ATTRIBUTES_PROPOSAL_LINE))).toBe(true);
    });
  });

  describe('A10: the LFS shape, with a local filter driver', () => {
    itPosix('the pointer blob is scanned and not a mismatch; the real disk copy is skipped', async () => {
      const d = fresh();
      const clean = path.join(d, '..', `${path.basename(d)}-clean.cjs`);
      dirs.push(clean);
      fs.writeFileSync(
        clean,
        [
          "process.stdin.resume();",
          "process.stdin.on('data', () => {});",
          "process.stdin.on('end', () => {",
          "  process.stdout.write('version https://git-lfs.github.com/spec/v1\\noid sha256:" + 'a'.repeat(64) + "\\nsize 8192\\n');",
          '});',
          '',
        ].join('\n'),
      );
      git(d, ['config', 'filter.vgtest.clean', `"${process.execPath}" "${clean}"`]);
      git(d, ['config', 'filter.vgtest.smudge', 'cat']);
      write(d, '.gitattributes', '*.mp4 filter=vgtest\n');
      write(d, 'media/clip.mp4', realMp4());
      commitAll(d, 'head');
      expect(git(d, ['cat-file', '-p', 'HEAD:media/clip.mp4'])).toMatch(/^version https:\/\/git-lfs/);
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(0);
      expect(doc.run.binary_type_mismatch_scanned).toBe(0);
      expect(doc.run.binary_worktree_copies_skipped).toBe(1);
      expect(doc.run.binary_files_skipped).toBe(0);
      // src/ok.ts, .gitattributes and the pointer.
      expect(doc.run.files_scanned).toBe(3);
    });
  });

  describe('A22: a declared working-tree-encoding that decodes means text', () => {
    function encodedClone(diskText: string): string {
      const d = fresh();
      write(d, '.gitattributes', 'clip.mp4 working-tree-encoding=UTF-16LE\n');
      write(d, 'clip.mp4', Buffer.from('plain caption text\n', 'utf16le'));
      commitAll(d, 'head');
      // An unstaged edit: the disk copy is BOM-less UTF-16LE.
      write(d, 'clip.mp4', Buffer.from(diskText, 'utf16le'));
      return d;
    }

    it('ftyp at offset 4 and NULs at 1 and 3 in a UTF-16LE disk copy: the key is found', async () => {
      const d = encodedClone(`ab\u7466\u7079\n${KEY_LINE}`);
      const disk = fs.readFileSync(path.join(d, 'clip.mp4'));
      expect(disk.subarray(4, 8).toString('latin1')).toBe('ftyp');
      expect([disk[1], disk[3]]).toEqual([0, 0]);
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(1);
      expect(doc.results.find(x => x.file === 'clip.mp4')?.matches[0].source).toBe('worktree');
      expect(doc.run.binary_type_mismatch).toEqual([{ file: 'clip.mp4', family: 'video' }]);
    });

    it('A22b: with U+00E9 and U+0101 before the key, the key is still found', async () => {
      const d = encodedClone(`ab\u7466\u7079 caf\u00e9 \u0101\u0101\n${KEY_LINE}`);
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(1);
      expect(doc.results.find(x => x.file === 'clip.mp4')?.matches[0].source).toBe('worktree');
    });
  });

  describe('U3: the window edge in the declared-label decode', () => {
    it('(a) a UTF-16LE .bin with a surrogate pair split by the 4096-byte window', async () => {
      const d = fresh();
      write(d, '.gitattributes', 'dump.bin working-tree-encoding=UTF-16LE\n');
      write(d, 'dump.bin', Buffer.from('placeholder\n', 'utf16le'));
      commitAll(d, 'head');
      const prefix = '\u0101' + 'a'.repeat(2046);
      const disk = Buffer.from(`${prefix}\u{1F600}\n${KEY_LINE}`, 'utf16le');
      expect(Buffer.from(prefix, 'utf16le').length).toBe(4094);
      write(d, 'dump.bin', disk);
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(1);
      expect(doc.results.find(x => x.file === 'dump.bin')?.matches[0].source).toBe('worktree');
    });

    it('(b) a SHIFT_JIS .bin whose window ends on a lead byte', async () => {
      const d = fresh();
      write(d, '.gitattributes', 'dump.bin working-tree-encoding=SHIFT_JIS\n');
      write(d, 'dump.bin', 'placeholder\n');
      commitAll(d, 'head');
      // 0x01, ASCII up to offset 4094, then the two-byte character 0x83 0x65
      // whose lead byte is offset 4095 and trail byte offset 4096.
      const disk = Buffer.concat([
        Buffer.from([0x01]),
        Buffer.alloc(4094, 0x61),
        Buffer.from([0x83, 0x65]),
        Buffer.from(`\n${KEY_LINE}`),
      ]);
      expect(disk[4095]).toBe(0x83);
      write(d, 'dump.bin', disk);
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(1);
      expect(doc.results.find(x => x.file === 'dump.bin')?.matches[0].source).toBe('worktree');
    });
  });

  describe('U12: a tracked image missing from the working tree', () => {
    it('plain: counted in tracked_files_missing; --trust-base: exit 2 naming it', async () => {
      const d = fresh();
      commitAll(d, 'base');
      git(d, ['tag', 'base']);
      write(d, 'img/logo.png', realPng());
      commitAll(d, 'head');
      fs.rmSync(path.join(d, 'img/logo.png'));
      process.chdir(d);
      const plain = await capture(() => scanCommand('.', 'json'));
      expect(plain.code).toBe(0);
      expect(parse(plain.stdout).run.tracked_files_missing).toBe(1);
      const pr = await capture(() => scanCommand('.', 'json', false, undefined, 'base'));
      expect(pr.code).toBe(2);
      expect(firstStderrLine(pr.err)).toMatch(/^INCOMPLETE: First: img\/logo\.png\./);
    });
  });

  describe('U18: named tracked symlinks, each copy judged by the name of the bytes it holds', () => {
    itPosix('notes.txt to a real clip.mp4: link text scanned, the video skipped as a worktree copy', async () => {
      const d = fresh();
      write(d, 'clip.mp4', realMp4());
      fs.symlinkSync('clip.mp4', path.join(d, 'notes.txt'));
      commitAll(d, 'head');
      process.chdir(d);
      const r = await capture(() => scanCommand(['notes.txt', 'src/ok.ts'], 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(0);
      expect(doc.run.binary_worktree_copies_skipped).toBe(1);
      expect(doc.run.binary_type_mismatch_scanned).toBe(0);
    });

    itPosix('clip.mp4 to notes.txt holding a key: the link text is a mismatch, the key found in the target', async () => {
      const d = fresh();
      write(d, 'notes.txt', KEY_LINE);
      fs.symlinkSync('notes.txt', path.join(d, 'clip.mp4'));
      commitAll(d, 'head');
      process.chdir(d);
      const r = await capture(() => scanCommand(['clip.mp4', 'src/ok.ts'], 'json'));
      const doc = parse(r.stdout);
      expect(r.code).toBe(1);
      expect(doc.run.binary_type_mismatch).toEqual([{ file: 'clip.mp4', family: 'video' }]);
      expect(doc.results.find(x => x.file === 'clip.mp4')?.matches[0].source).toBe('worktree');
    });
  });

  describe('U7: the new JSON fields are always present, and SARIF carries the same values', () => {
    it('a tree with no binary files: every field at zero', async () => {
      const d = fresh();
      commitAll(d, 'head');
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'json'));
      const run = parse(r.stdout).run;
      expect(run.binary_files_skipped).toBe(0);
      expect(run.binary_files_skipped_by_family).toEqual({
        image: 0, document: 0, video: 0, audio: 0, font: 0, archive: 0, executable: 0, other: 0,
      });
      expect(run.binary_worktree_copies_skipped).toBe(0);
      expect(run.binary_type_mismatch_scanned).toBe(0);
      expect(run.binary_type_mismatch).toEqual([]);
      expect(run.scan_budget_retimed).toBe(0);
    });

    it('family counts sum to binary_files_skipped, and SARIF equals JSON for each field', async () => {
      const d = fresh();
      write(d, 'a.png', realPng());
      write(d, 'b.mp4', realMp4());
      write(d, 'c.mp4', realMp4(4096, 3));
      write(d, 'config/credentials.mov', KEY_LINE);
      commitAll(d, 'head');
      process.chdir(d);
      const j = parse((await capture(() => scanCommand('.', 'json'))).stdout).run;
      const fam = j.binary_files_skipped_by_family as Record<string, number>;
      expect(Object.values(fam).reduce((a, b) => a + b, 0)).toBe(j.binary_files_skipped);
      expect(j.binary_files_skipped).toBe(3);
      const s = JSON.parse((await capture(() => scanCommand('.', 'sarif'))).stdout) as {
        runs: Array<{ properties: { vault_guard_run: Record<string, unknown> } }>;
      };
      const props = s.runs[0].properties.vault_guard_run;
      for (const k of [
        'binary_files_skipped',
        'binary_files_skipped_by_family',
        'binary_worktree_copies_skipped',
        'binary_type_mismatch_scanned',
        'binary_type_mismatch',
        'scan_budget_retimed',
      ]) {
        expect(props[k]).toEqual(j[k]);
      }
    });
  });

  describe('U8: the text lines', () => {
    it('the three binary lines appear with their wording, and the mismatch line names three then "and 2 more"', async () => {
      const d = fresh();
      write(d, 'a.png', realPng());
      write(d, 'b.mp4', realMp4());
      for (const n of ['a', 'b', 'c', 'd']) write(d, `t/${n}.mov`, 'just text\n');
      // A text blob whose disk copy is replaced by a real video: the blob is
      // a mismatch and scanned, the disk copy is skipped.
      write(d, 'clip.mp4', 'a caption\n');
      commitAll(d, 'head');
      write(d, 'clip.mp4', realMp4());
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.log).toContain('Binary files skipped: 2 (content matched the extension: image 1, video 1)');
      expect(r.log).toContain('Working-tree copies skipped as binary, blob scanned: 1');
      expect(r.log).toContain(
        'Files named as binary but holding text, scanned as text: 5 (clip.mp4, t/a.mov, t/b.mov and 2 more)',
      );
    });

    it('none of the lines appear at zero', async () => {
      const d = fresh();
      commitAll(d, 'head');
      process.chdir(d);
      const r = await capture(() => scanCommand('.', 'text'));
      expect(r.log).not.toMatch(/Binary files skipped|Working-tree copies skipped as binary|Files named as binary|re-timed/);
    });
  });

  describe('U17: skipBinary false scans every file as text, with no classification', () => {
    it('a real .png, a text credentials.png and a .ts are all scanned', async () => {
      const { scanFilesAsync, newRunSkipCounts } = await import('../../utils/scan-utils');
      const d = fresh();
      write(d, 'real.png', realPng());
      write(d, 'config/credentials.png', KEY_LINE);
      commitAll(d, 'head');
      process.chdir(d);
      const { SecretScanner } = await import('@vaultcompass/vault-guard-core');
      const skips = newRunSkipCounts();
      const stats = { filesScanned: 0, bytesScanned: 0 };
      const results = await scanFilesAsync(['.'], new SecretScanner(), { skipBinary: false, skips, stats });
      expect(stats.filesScanned).toBe(3);
      expect(skips.binary).toBe(0);
      expect(skips.typeMismatch).toEqual([]);
      expect(results.some(x => x.file.endsWith('credentials.png'))).toBe(true);
    });
  });

  describe('seeded fixtures are deterministic', () => {
    it('the same seed gives the same bytes', () => {
      expect(seeded(64, 5).equals(seeded(64, 5))).toBe(true);
    });
  });
});
