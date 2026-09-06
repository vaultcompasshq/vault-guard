import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  TrustBaseError,
  loadTrustedControls,
  CONFIG_PROPOSAL_LINE,
  BASELINE_PROPOSAL_LINE,
  CONFIG_ADDED_LINE,
  BASELINE_ADDED_LINE,
} from '../trust-base';
import { ConfigError } from '../errors';

/**
 * Symlinks, file modes and `..`-shaped path handling behave differently on
 * Windows, where the CI job is not a required check. Those cases are gated;
 * everything else here is portable.
 */
const itPosix = process.platform === 'win32' ? it.skip : it;

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/**
 * A scratch repository, its path canonicalised with `realpathSync.native`.
 *
 * `.native` rather than plain `realpathSync`, because the two differ on
 * Windows: `os.tmpdir()` comes back in 8.3 short form there
 * (`C:\Users\RUNNER~1\...`) and plain `realpathSync` keeps it, while git
 * reports the long form (`C:\Users\runneradmin\...`). An absolute expectation
 * built from the short root then never matches a listing built from git's
 * root, and the failure reads as a wrong file set rather than as two spellings
 * of one path. macOS has the same shape for a different reason (`/var` is a
 * link to `/private/var`), which is why the helper was already here.
 */
function makeRepo(): string {
  const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-trust-base-')));
  git(dir, ['init', '-q', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.invalid']);
  git(dir, ['config', 'user.name', 'test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  return dir;
}

function write(root: string, rel: string, text: string): void {
  const abs = path.join(root, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, text);
}

function commit(root: string, message: string): void {
  git(root, ['add', '-A']);
  git(root, ['commit', '-q', '-m', message]);
}

/** Base branch with a config and a baseline, then a feature branch on top. */
function seed(root: string, config: unknown = { fail_on: 'medium' }): void {
  write(root, '.vault-guard.json', JSON.stringify(config));
  write(root, '.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: ['aaa'] }));
  write(root, 'src/app.ts', 'export const x = 1;\n');
  commit(root, 'base');
  git(root, ['branch', 'base-snapshot']);
  git(root, ['checkout', '-q', '-b', 'feature']);
}

describe('loadTrustedControls', () => {
  let root: string;

  beforeEach(() => {
    root = makeRepo();
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  describe('the ref itself', () => {
    it('fails closed when the ref does not resolve, naming the ref and the fetch', () => {
      seed(root);
      write(root, 'src/other.ts', 'export const y = 2;\n');
      commit(root, 'feature');
      let err: unknown;
      try {
        loadTrustedControls(root, 'origin/nope');
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(TrustBaseError);
      expect((err as Error).message).toContain('origin/nope');
      expect((err as Error).message).toContain('fetch-depth: 0');
      expect((err as Error).message).toContain('Nothing was scanned.');
    });

    it('refuses a ref that begins with a dash, which git would read as an option', () => {
      seed(root);
      write(root, 'src/other.ts', 'export const y = 2;\n');
      commit(root, 'feature');
      expect(() => loadTrustedControls(root, '--upload-pack=x')).toThrow(TrustBaseError);
      expect(() => loadTrustedControls(root, '--upload-pack=x')).toThrow(/may not begin with a dash/);
    });

    it('refuses a ref that resolves to the same commit as HEAD', () => {
      seed(root);
      write(root, 'src/other.ts', 'export const y = 2;\n');
      commit(root, 'feature');
      expect(() => loadTrustedControls(root, 'HEAD')).toThrow(TrustBaseError);
      expect(() => loadTrustedControls(root, 'HEAD')).toThrow(/the same commit as HEAD/);
    });

    it('refuses a different commit that carries an identical tree', () => {
      seed(root);
      write(root, 'src/other.ts', 'export const y = 2;\n');
      commit(root, 'feature');
      // An empty commit is a new commit with the head's exact tree, which is
      // what a pull request's merge ref looks like when the base has not moved.
      git(root, ['branch', 'twin']);
      git(root, ['checkout', '-q', 'twin']);
      git(root, ['commit', '-q', '--allow-empty', '-m', 'merge ref shape']);
      git(root, ['checkout', '-q', 'feature']);
      expect(() => loadTrustedControls(root, 'twin')).toThrow(/identical tree/);
    });

    it('accepts a base that differs only in a file that is not a control input', () => {
      seed(root);
      write(root, 'src/other.ts', 'export const y = 2;\n');
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.proposals).toEqual([]);
      expect(controls.configChanged).toBe(false);
      expect(controls.baselineChanged).toBe(false);
      expect(controls.config.fail_on).toBe('medium');
    });
  });

  describe('config', () => {
    it('uses the base config and reports a head-side change as a proposal', () => {
      seed(root);
      write(root, '.vault-guard.json', JSON.stringify({ fail_on: 'none', ignore: { paths: ['**'] } }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config.fail_on).toBe('medium');
      expect(controls.config.ignore).toBeUndefined();
      expect(controls.configChanged).toBe(true);
      expect(controls.proposals[0]).toContain(CONFIG_PROPOSAL_LINE);
    });

    it('summarises what the head config proposed, when it is cheap to compute', () => {
      seed(root);
      write(
        root,
        '.vault-guard.json',
        JSON.stringify({ fail_on: 'none', ignore: { paths: ['a/**', 'b/**'] } }),
      );
      commit(root, 'feature');
      const line = loadTrustedControls(root, 'base-snapshot').proposals[0];
      expect(line).toContain('2 patterns added to ignore');
      expect(line).toContain('fail_on lowered');
    });

    it('ignores a config that exists only at the head and reports it as added', () => {
      write(root, 'src/app.ts', 'export const x = 1;\n');
      commit(root, 'base');
      git(root, ['branch', 'base-snapshot']);
      git(root, ['checkout', '-q', '-b', 'feature']);
      write(root, '.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config).toEqual({});
      expect(controls.configChanged).toBe(true);
      expect(controls.proposals).toContain(CONFIG_ADDED_LINE);
    });

    it('reports a config the head removed and still uses the base one', () => {
      seed(root);
      fs.rmSync(path.join(root, '.vault-guard.json'));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config.fail_on).toBe('medium');
      expect(controls.configShapeChange).toBe('removed');
      expect(controls.proposals).toContain('config removed in this pull request');
    });

    it('does not let a head-added .vault-guard.local.json take effect', () => {
      seed(root);
      fs.rmSync(path.join(root, '.vault-guard.json'));
      write(root, '.vault-guard.local.json', JSON.stringify({ fail_on: 'none' }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config.fail_on).toBe('medium');
      expect(controls.configChanged).toBe(true);
    });

    it('refuses a base config that fails schema validation', () => {
      seed(root, { fail_on: 'medium', unknown_key: true });
      write(root, 'src/other.ts', 'export const y = 2;\n');
      commit(root, 'feature');
      expect(() => loadTrustedControls(root, 'base-snapshot')).toThrow(ConfigError);
      expect(() => loadTrustedControls(root, 'base-snapshot')).toThrow(/unknown top-level key/);
    });

    itPosix('reports a config the head turned into a symlink, and ignores it', () => {
      seed(root);
      write(root, 'decoy.json', JSON.stringify({ fail_on: 'none' }));
      fs.rmSync(path.join(root, '.vault-guard.json'));
      fs.symlinkSync('decoy.json', path.join(root, '.vault-guard.json'));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config.fail_on).toBe('medium');
      expect(controls.configShapeChange).toBe('symlink');
      expect(controls.proposals).toContain(
        'config is a symlink at the head commit, not a regular file',
      );
    });

    itPosix('reports a config whose file mode the head changed', () => {
      seed(root);
      fs.chmodSync(path.join(root, '.vault-guard.json'), 0o755);
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.configShapeChange).toBe('mode');
      expect(controls.proposals).toContain('config file mode changed in this pull request');
    });
  });

  describe('baseline', () => {
    it('uses the base baseline and reports a head-side rewrite', () => {
      seed(root);
      write(
        root,
        '.vault-guard.baseline.json',
        JSON.stringify({ version: 1, fingerprints: ['aaa', 'bbb'] }),
      );
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect([...controls.baseline]).toEqual(['aaa']);
      expect(controls.baselineChanged).toBe(true);
      expect(controls.proposals.some(p => p.startsWith(BASELINE_PROPOSAL_LINE))).toBe(true);
      expect(controls.proposals.some(p => p.includes('1 baseline entry added'))).toBe(true);
    });

    it('reports a baseline that exists only at the head and uses none', () => {
      write(root, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
      commit(root, 'base');
      git(root, ['branch', 'base-snapshot']);
      git(root, ['checkout', '-q', '-b', 'feature']);
      write(root, '.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: ['x'] }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.baseline.size).toBe(0);
      expect(controls.proposals).toContain(BASELINE_ADDED_LINE);
    });
  });

  describe('the head tree file set', () => {
    it('lists the head tree as absolute paths and excludes untracked ones', () => {
      seed(root);
      write(root, 'src/tracked.ts', 'export const t = 1;\n');
      commit(root, 'feature');
      write(root, 'src/untracked.ts', 'export const u = 1;\n');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.headTreeFiles).toContain(path.join(root, 'src', 'tracked.ts'));
      expect(controls.headTreeFiles).not.toContain(path.join(root, 'src', 'untracked.ts'));
    });

    itPosix('drops a symlink from the listing itself, by its git mode', () => {
      seed(root);
      write(root, 'src/real.ts', 'export const t = 1;\n');
      fs.symlinkSync('real.ts', path.join(root, 'src', 'link.ts'));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.headTreeFiles).toContain(path.join(root, 'src', 'real.ts'));
      expect(controls.headTreeFiles).not.toContain(path.join(root, 'src', 'link.ts'));
    });
  });
});
