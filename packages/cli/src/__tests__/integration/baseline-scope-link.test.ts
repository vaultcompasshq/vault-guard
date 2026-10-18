import * as fs from 'fs';
import * as path from 'path';

import { baselineCommand } from '../../commands/baseline';
import { scanCommand } from '../../commands/scan';
import { AWS_KEY, AWS_KEY_2, capture, commitAll, git, initRepo, tmpDir, write } from './git-fixture';

/**
 * Review of audit 2026-10-18, N1, final round. `baseline <link> --write`
 * scopes the write to the path it was given, resolved the way an entry's
 * file label is (`contentRelPath`: parent directories resolved, the leaf
 * never). When the scope resolved the leaf, naming a committed link to a
 * baselined file scoped the write to the TARGET, and the target's accepted
 * entry was dropped, so the next scan blocked on a file nobody touched.
 */
const itPosix = process.platform === 'win32' ? it.skip : it;

interface BaselineDoc {
  entries?: Array<{ file?: string; rule?: string }>;
}

describe('baseline --write scoped to a committed link', () => {
  const originalCwd = process.cwd();
  let dir: string;

  beforeEach(() => {
    dir = tmpDir('vg-baseline-scope-link-');
    process.chdir(dir);
    initRepo(dir);
    write(dir, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    write(dir, 'src/real.ts', `export const k = "${AWS_KEY}";\n`);
    fs.symlinkSync('real.ts', path.join(dir, 'src', 'link.ts'));
    commitAll(dir, 'real file and a link to it');
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function readBaseline(): BaselineDoc {
    return JSON.parse(fs.readFileSync(path.join(dir, '.vault-guard.baseline.json'), 'utf-8')) as BaselineDoc;
  }

  itPosix('keeps the target\'s entry, accepts nothing for the link, and the next scan still passes', async () => {
    const whole = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
    expect(whole.code).toBe(0);
    expect(readBaseline().entries?.map(e => e.file)).toEqual(['src/real.ts']);
    commitAll(dir, 'baseline');
    git(dir, ['checkout', '-q', '-b', 'feature']);

    const scoped = await capture(() => baselineCommand('src/link.ts', { write: true, includeCritical: true }));
    expect(scoped.code).not.toBe(2);
    // The link's finding comes from its target's content on disk, which a
    // baseline cannot accept under the link's name: it is reported, not taken.
    expect(`${scoped.log}\n${scoped.err}`).toMatch(/working-tree edits with findings: 1 \(not accepted/);
    const files = readBaseline().entries?.map(e => e.file) ?? [];
    // The target's entry survives the write scoped to the link...
    expect(files).toContain('src/real.ts');
    // ...and nothing is accepted under the link's name.
    expect(files).not.toContain('src/link.ts');

    const after = await capture(() => scanCommand('.', 'json'));
    expect(after.code).toBe(0);
  });
});

describe('baseline --write scoped to a link to a directory', () => {
  const originalCwd = process.cwd();
  let dir: string;

  beforeEach(() => {
    dir = tmpDir('vg-baseline-scope-dirlink-');
    process.chdir(dir);
    initRepo(dir);
    write(dir, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    write(dir, 'pkg/real/leak.ts', `export const k = "${AWS_KEY}";\n`);
    write(dir, 'other/keep.ts', `export const k = "${AWS_KEY_2}";\n`);
    fs.symlinkSync(path.join('pkg', 'real'), path.join(dir, 'alias'));
    commitAll(dir, 'two keyed files and a link to one directory');
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function entryFiles(): string[] {
    const doc = JSON.parse(fs.readFileSync(path.join(dir, '.vault-guard.baseline.json'), 'utf-8')) as {
      entries?: Array<{ file?: string }>;
    };
    return (doc.entries ?? []).map(e => e.file ?? '').sort();
  }

  itPosix('leaves every entry in place, and the next scan still passes', async () => {
    const whole = await capture(() => baselineCommand('.', { write: true, includeCritical: true }));
    expect(whole.code).toBe(0);
    const before = entryFiles();
    expect(before).toEqual(['other/keep.ts', 'pkg/real/leak.ts']);
    commitAll(dir, 'baseline');

    await capture(() => baselineCommand('alias', { write: true, includeCritical: true }));
    expect(entryFiles()).toEqual(before);

    const after = await capture(() => scanCommand('.', 'json'));
    expect(after.code).toBe(0);
  });
});
