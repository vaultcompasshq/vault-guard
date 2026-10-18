import * as fs from 'fs';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';
import { AWS_KEY, capture, commitAll, git, initRepo, tmpDir, write } from './git-fixture';

/**
 * Audit 2026-10-18, N1, the fail-closed half. When the run has no HEAD blob
 * for a head-tree file whose working copy is not a regular file, the file is
 * recorded as unscannable and the run exits 2; it is never dropped
 * uncounted. `scanCommand` always has the blobs, so this file strips them
 * from the trusted controls to reach that branch.
 */
jest.mock('@vaultcompass/vault-guard-core', () => {
  const actual = jest.requireActual('@vaultcompass/vault-guard-core');
  return {
    ...actual,
    loadTrustedControls: (...args: unknown[]) => {
      const controls = actual.loadTrustedControls(...args);
      return { ...controls, headBlobs: undefined };
    },
  };
});

const itPosix = process.platform === 'win32' ? it.skip : it;

describe('trust-base without head blobs: a swapped working copy fails closed', () => {
  const originalCwd = process.cwd();
  let dir: string;

  beforeEach(() => {
    dir = tmpDir('vg-disk-swap-noblob-');
    process.chdir(dir);
    initRepo(dir);
    write(dir, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    write(dir, 'src/app.ts', 'export const greeting = "hello";\n');
    write(dir, 'src/harmless.ts', 'export const nothing = 0;\n');
    commitAll(dir, 'base');
    git(dir, ['branch', 'base-snapshot']);
    git(dir, ['checkout', '-q', '-b', 'feature']);
    write(dir, 'src/swapped.ts', `export const k = "${AWS_KEY}";\n`);
    commitAll(dir, 'head');
    const p = path.join(dir, 'src', 'swapped.ts');
    fs.rmSync(p);
    fs.symlinkSync('harmless.ts', p);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  itPosix('records the file as unscannable with the reason, and exits 2', async () => {
    const r = await capture(() => scanCommand('.', 'json', false, undefined, 'base-snapshot'));
    expect(r.code).toBe(2);
    const doc = JSON.parse(r.stdout) as {
      run: { unscannable?: Array<{ file: string }> };
      diagnostics?: Array<{ code: string; ctx: Record<string, unknown> }>;
    };
    expect(doc.run.unscannable?.map(u => u.file)).toContain(path.join('src', 'swapped.ts'));
    const diag = doc.diagnostics?.find(
      d => d.code === 'file.read_error' && d.ctx.file === path.join('src', 'swapped.ts'),
    );
    expect(String(diag?.ctx.detail)).toMatch(/working-tree entry is a symlink, not a regular file/);
  });
});
