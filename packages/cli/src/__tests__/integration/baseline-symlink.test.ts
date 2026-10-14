import * as fs from 'fs';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';
import * as fx from './git-fixture';

/**
 * The baseline and config are never read through a link, and a parse error
 * never echoes file content (design 2026-10-12, 4.1 and 4.2).
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

/** Text that must never reach the output when it sits in a linked file. */
const VICTIM_TEXT = 'aws_secret = victim-file-marker-7731';

describe('control files are never read through a link', () => {
  const originalCwd = process.cwd();
  const dirs: string[] = [];

  afterEach(() => {
    process.chdir(originalCwd);
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function setup(link: (repo: string, parent: string) => void): string {
    const parent = fx.tmpDir('vg-link-read-');
    dirs.push(parent);
    const repo = path.join(parent, 'repo');
    fs.mkdirSync(repo);
    fx.initRepo(repo);
    fx.write(repo, 'app.ts', `export const k = "${fx.AWS_KEY}";\n`);
    link(repo, parent);
    fx.commitAll(repo, 'base');
    return repo;
  }

  itPosix('F11: scan refuses a symlinked baseline with exit 2 and prints none of the target', async () => {
    const repo = setup((r, p) => {
      fs.writeFileSync(path.join(p, 'victim.txt'), `${VICTIM_TEXT}\n`);
      fs.symlinkSync('../victim.txt', path.join(r, '.vault-guard.baseline.json'));
    });
    process.chdir(repo);
    for (const format of ['text', 'json', 'sarif'] as const) {
      const r = await fx.capture(() => scanCommand('.', format, false));
      expect({ format, code: r.code }).toEqual({ format, code: 2 });
      const all = `${r.log}\n${r.err}\n${r.stdout}`;
      expect(all).toContain('Cannot read the baseline: .vault-guard.baseline.json at');
      expect(all).toContain('is a symlink, not a regular file');
      expect(all).toContain('Nothing was scanned.');
      expect(all).not.toContain('victim-file-marker');
      expect(all).not.toContain('Scanning');
    }
  });

  itPosix('F13: scan refuses a symlinked config with exit 2', async () => {
    const repo = setup((r, p) => {
      fs.writeFileSync(path.join(p, 'outside.json'), '{"fail_on":"none"}\n');
      fs.symlinkSync('../outside.json', path.join(r, '.vault-guard.json'));
    });
    process.chdir(repo);
    const r = await fx.capture(() => scanCommand('.', 'text', false));
    expect(r.code).toBe(2);
    expect(r.err).toContain('Config error');
    expect(r.err).toContain('.vault-guard.json');
    expect(r.err).toContain('is a symlink, not a regular file');
  });

  it('F14: a baseline parse error never echoes file content', async () => {
    const repo = setup(r => fx.write(r, '.vault-guard.baseline.json', `{"version":1, ${VICTIM_TEXT}`));
    process.chdir(repo);
    const json = await fx.capture(() => scanCommand('.', 'json', false));
    expect(json.code).toBe(1);
    const doc = fx.parse(json.stdout);
    const d = doc.diagnostics?.find(x => x.code === 'baseline.invalid');
    expect(d?.ctx.detail).toBe('could not be parsed as JSON');
    expect(json.stdout).not.toContain('victim-file-marker');
    expect(json.stdout).not.toContain('aws_secret');
    const sarif = await fx.capture(() => scanCommand('.', 'sarif', false));
    expect(sarif.stdout).toContain('could not be parsed as JSON');
    expect(sarif.stdout).not.toContain('victim-file-marker');
    const text = await fx.capture(() => scanCommand('.', 'text', false));
    expect(`${text.log}\n${text.err}`).not.toContain('victim-file-marker');
  });

  it('F14: a baseline whose engine message would quote its content echoes none of it', async () => {
    // Node 22 quotes the start of the input for this shape of error.
    const repo = setup(r => fx.write(r, '.vault-guard.baseline.json', '{"a": victim-file-marker-7731}'));
    process.chdir(repo);
    const json = await fx.capture(() => scanCommand('.', 'json', false));
    expect(json.stdout).toContain('could not be parsed as JSON');
    expect(`${json.stdout}\n${json.err}`).not.toContain('victim-fil');
  });

  itPosix('F19: a dangling config or baseline link is refused, not treated as absent', async () => {
    for (const name of ['.vault-guard.json', '.vault-guard.baseline.json']) {
      const repo = setup(r => {
        if (name === '.vault-guard.json') {
          fx.write(r, '.vault-guard.json', '{"fail_on":"none"}\n');
        } else {
          // A baseline that would suppress the finding, at the parent.
          fx.write(r, '.vault-guard.baseline.json', '{"version":1,"fingerprints":[],"entries":[]}\n');
        }
        fs.mkdirSync(path.join(r, 'sub'));
        fx.write(r, 'sub/k.ts', `export const k = "${fx.AWS_KEY_2}";\n`);
        fs.symlinkSync('../nowhere.json', path.join(r, 'sub', name));
      });
      process.chdir(path.join(repo, 'sub'));
      const r = await fx.capture(() => scanCommand('.', 'text', false));
      expect({ name, code: r.code }).toEqual({ name, code: 2 });
      expect(r.err).toContain(path.join('sub', name));
      expect(r.err).toContain('is a symlink, not a regular file');
      process.chdir(originalCwd);
    }
  });
});
