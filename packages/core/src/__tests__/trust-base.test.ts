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
  OTHER_CONTROL_FILES_LINE,
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

    describe('naming the repository it consulted', () => {
      const startCwd = process.cwd();
      afterEach(() => process.chdir(startCwd));

      function messageFor(startDir: string, ref: string): string {
        try {
          loadTrustedControls(startDir, ref);
        } catch (e) {
          return (e as Error).message;
        }
        throw new Error('expected loadTrustedControls to throw');
      }

      it('an unresolvable ref names the repository relative to the cwd, never its absolute path', () => {
        seed(root);
        write(root, 'src/other.ts', 'export const y = 2;\n');
        commit(root, 'feature');
        process.chdir(path.join(root, 'src'));
        const message = messageFor(process.cwd(), 'origin/nope');
        expect(message).toContain('origin/nope');
        expect(message).toContain('the repository at ".."');
        expect(message).not.toContain(root);
      });

      it('names the repository as "." when the cwd is its root', () => {
        seed(root);
        write(root, 'src/other.ts', 'export const y = 2;\n');
        commit(root, 'feature');
        process.chdir(root);
        const message = messageFor(root, 'origin/nope');
        expect(message).toContain('the repository at "." (the current directory)');
      });

      it('a start directory outside any worktree is named relative to the cwd', () => {
        const bare = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-not-git-')));
        try {
          process.chdir(bare);
          const message = messageFor(bare, 'main');
          expect(message).toContain('"." (the current directory) is not inside a git worktree');
          expect(message).not.toContain(bare);
        } finally {
          process.chdir(startCwd);
          fs.rmSync(bare, { recursive: true, force: true });
        }
      });

      it('prints the repository path and none of its content', () => {
        // A repository with no commits and one untracked file: pins that no
        // file name or config text from the repository rides along with the path.
        write(root, 'secret-name-xyz.ts', 'export const y = 2;\n');
        process.chdir(root);
        const message = messageFor(root, 'main');
        expect(message).toContain('the repository at "."');
        expect(message).not.toContain('secret-name-xyz');
      });
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

  /**
   * Audit 2026-10-27 NB2: the summary named four levers and was silent on the
   * rest, so a head that raised entropy_threshold, or added a local or nested
   * config the base run never reads, printed a proposal line that a reviewer
   * would read as complete. Every top-level setting that differs is now named,
   * and every other control file the head touched is listed by path.
   */
  describe('the proposal summary names every head change the run ignores', () => {
    function configLine(head: unknown, base: unknown = { fail_on: 'medium' }): string {
      seed(root, base);
      write(root, '.vault-guard.json', JSON.stringify(head));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config).toEqual(base);
      const line = controls.proposals.find(p => p.startsWith(CONFIG_PROPOSAL_LINE));
      expect(line).toBeDefined();
      return line as string;
    }

    it('names a raised entropy_threshold with both values', () => {
      expect(configLine({ fail_on: 'medium', entropy_threshold: 7.9 })).toContain(
        'entropy_threshold raised from 3.5 to 7.9',
      );
    });

    it('names a lowered entropy_threshold too', () => {
      expect(
        configLine({ fail_on: 'medium', entropy_threshold: 2 }, { fail_on: 'medium', entropy_threshold: 4 }),
      ).toContain('entropy_threshold lowered from 4 to 2');
    });

    it('names extra_patterns_unsafe being turned on', () => {
      expect(configLine({ fail_on: 'medium', extra_patterns_unsafe: true })).toContain(
        'extra_patterns_unsafe turned on',
      );
    });

    it('names removals, not only additions', () => {
      const line = configLine(
        { fail_on: 'medium' },
        {
          fail_on: 'medium',
          ignore: { paths: ['a/**'] },
          severity_overrides: { anthropic: 'critical' },
          extra_patterns: [{ id: 'x', regex: 'xyz[0-9]{8}', severity: 'high' }],
        },
      );
      expect(line).toContain('1 pattern removed from ignore');
      expect(line).toContain('1 severity override removed');
      expect(line).toContain('1 extra pattern removed');
    });

    it('counts an ignore entry moved between paths and patterns as added', () => {
      expect(
        configLine(
          { fail_on: 'medium', ignore: { patterns: ['a/**'] } },
          { fail_on: 'medium', ignore: { paths: ['a/**'] } },
        ),
      ).toContain('1 pattern added to ignore');
    });

    it('names fail_on raised, so a changed fail_on is never silent', () => {
      expect(configLine({ fail_on: 'low' })).toContain('fail_on raised');
    });

    it('names a changed extra pattern whose count did not move', () => {
      expect(
        configLine(
          { fail_on: 'medium', extra_patterns: [{ id: 'x', regex: 'abc[0-9]{8}', severity: 'high' }] },
          { fail_on: 'medium', extra_patterns: [{ id: 'x', regex: 'xyz[0-9]{8}', severity: 'high' }] },
        ),
      ).toContain('extra_patterns changed');
    });

    it('says which way a changed severity override moved', () => {
      const lowered = configLine(
        { fail_on: 'medium', severity_overrides: { anthropic: 'off', github: 'low' } },
        { fail_on: 'medium', severity_overrides: { anthropic: 'critical', github: 'high' } },
      );
      expect(lowered).toContain('2 severity overrides lowered');
      expect(lowered).not.toContain('added');
    });

    it('says raised for a stricter severity override', () => {
      const raised = configLine(
        { fail_on: 'medium', severity_overrides: { anthropic: 'critical' } },
        { fail_on: 'medium', severity_overrides: { anthropic: 'off' } },
      );
      expect(raised).toContain('1 severity override raised');
      expect(raised).not.toContain('added');
    });

    it('says an entropy_threshold that is not a number is not a number, not a move to the default', () => {
      const line = configLine(
        { fail_on: 'medium', entropy_threshold: '4.5' },
        { fail_on: 'medium', entropy_threshold: 4.5 },
      );
      expect(line).toContain(
        'entropy_threshold changed (not a number at the head; the base rules use 4.5)',
      );
      expect(line).not.toContain('lowered');
    });

    it('escapes C1 control and bidi characters in an echoed path', () => {
      seed(root);
      const bidi = 'a‮b/.vault-guard.json';
      const c1 = 'c\u0085d/.vault-guard.local.json';
      write(root, bidi, JSON.stringify({ fail_on: 'none' }));
      write(root, c1, JSON.stringify({ fail_on: 'none' }));
      commit(root, 'feature');
      const line = loadTrustedControls(root, 'base-snapshot').proposals[0];
      expect(line).toBe(
        `${OTHER_CONTROL_FILES_LINE} (2 files: "a\\u202eb/.vault-guard.json", "c\\u0085d/.vault-guard.local.json")`,
      );
      expect(line).not.toMatch(/[\u0080-\u009f‪-‮⁦-⁩]/);
    });

    it('counts unrecognised top-level keys without echoing their names', () => {
      const line = configLine({ fail_on: 'medium', 'evil\nkey': 1 });
      expect(line).toContain('1 unrecognised top-level key changed');
      expect(line).not.toContain('evil');
    });

    it('says so when the head config is not a JSON object', () => {
      seed(root);
      write(root, '.vault-guard.json', '{ not json');
      commit(root, 'feature');
      const line = loadTrustedControls(root, 'base-snapshot').proposals.find(p =>
        p.startsWith(CONFIG_PROPOSAL_LINE),
      );
      expect(line).toContain('not a JSON object at the head');
    });

    it('names the path when the head config is a different file from the base one', () => {
      seed(root);
      write(root, 'src/.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
      commit(root, 'feature');
      const controls = loadTrustedControls(path.join(root, 'src'), 'base-snapshot');
      expect(controls.config).toEqual({ fail_on: 'medium' });
      const line = controls.proposals.find(p => p.startsWith(CONFIG_PROPOSAL_LINE));
      expect(line).toBe(
        `${CONFIG_PROPOSAL_LINE} (read from src/.vault-guard.json at the head instead of .vault-guard.json)`,
      );
    });

    it('lists a head-added .vault-guard.local.json that the committed config shadows', () => {
      seed(root);
      write(root, '.vault-guard.local.json', JSON.stringify({ ignore: { paths: ['**'] } }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.configChanged).toBe(false);
      expect(controls.proposals).toEqual([
        `${OTHER_CONTROL_FILES_LINE} (1 file: .vault-guard.local.json)`,
      ]);
    });

    it('lists a head-added nested config and a nested baseline by path', () => {
      seed(root);
      write(root, 'src/.vault-guard.json', JSON.stringify({ ignore: { paths: ['**'] } }));
      write(root, 'lib/.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: ['z'] }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.proposals).toEqual([
        `${OTHER_CONTROL_FILES_LINE} (2 files: lib/.vault-guard.baseline.json, src/.vault-guard.json)`,
      ]);
    });

    it('lists a nested config the head modified or removed, not only added', () => {
      write(root, 'a/.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
      write(root, 'b/.vault-guard.local.json', JSON.stringify({ fail_on: 'medium' }));
      seed(root);
      write(root, 'a/.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      fs.rmSync(path.join(root, 'b/.vault-guard.local.json'));
      commit(root, 'feature');
      expect(loadTrustedControls(root, 'base-snapshot').proposals).toEqual([
        `${OTHER_CONTROL_FILES_LINE} (2 files: a/.vault-guard.json, b/.vault-guard.local.json)`,
      ]);
    });

    it('names the first three and counts the rest', () => {
      seed(root);
      for (const d of ['a', 'b', 'c', 'd', 'e']) {
        write(root, `${d}/.vault-guard.json`, JSON.stringify({ fail_on: 'none' }));
      }
      commit(root, 'feature');
      expect(loadTrustedControls(root, 'base-snapshot').proposals).toEqual([
        `${OTHER_CONTROL_FILES_LINE} (5 files: a/.vault-guard.json, b/.vault-guard.json, c/.vault-guard.json, and 2 more)`,
      ]);
    });

    it('does not list the config or baseline that already has its own line', () => {
      seed(root);
      write(root, '.vault-guard.json', JSON.stringify({ fail_on: 'none' }));
      write(root, '.vault-guard.baseline.json', JSON.stringify({ version: 1, fingerprints: ['aaa', 'b'] }));
      commit(root, 'feature');
      const proposals = loadTrustedControls(root, 'base-snapshot').proposals;
      expect(proposals.some(p => p.startsWith(OTHER_CONTROL_FILES_LINE))).toBe(false);
    });

    it('reproduces the audit case: every lever named, none applied', () => {
      seed(root);
      write(
        root,
        '.vault-guard.json',
        JSON.stringify({
          fail_on: 'none',
          ignore: { paths: ['src/**'] },
          severity_overrides: { anthropic: 'off' },
          entropy_threshold: 7.9,
        }),
      );
      write(root, '.vault-guard.local.json', JSON.stringify({ ignore: { paths: ['**'] } }));
      write(root, 'src/.vault-guard.json', JSON.stringify({ ignore: { paths: ['**'] } }));
      commit(root, 'feature');
      const controls = loadTrustedControls(root, 'base-snapshot');
      expect(controls.config).toEqual({ fail_on: 'medium' });
      expect(controls.proposals).toEqual([
        `${CONFIG_PROPOSAL_LINE} (1 pattern added to ignore, fail_on lowered, ` +
          '1 severity override added, entropy_threshold raised from 3.5 to 7.9)',
        `${OTHER_CONTROL_FILES_LINE} (2 files: .vault-guard.local.json, src/.vault-guard.json)`,
      ]);
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
