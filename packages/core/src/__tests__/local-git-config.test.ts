import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  LOCAL_GIT_CONFIG_ALLOWED_KEYS,
  checkLocalGitConfig,
  isAllowedLocalGitConfigKey,
  localGitConfigRefusal,
} from '../utils/local-git-config';
import { presentRepoControls } from '../no-repo-controls';

/**
 * The allowlist of design 2026-10-28, section 3.2 (DECISION 3, with the keys
 * left off it in N4). It is pinned here whole, so widening it is a visible
 * change to this test, not a side effect.
 */
describe('local git config allowlist', () => {
  it('is exactly the keys a fresh clone writes', () => {
    expect([...LOCAL_GIT_CONFIG_ALLOWED_KEYS].sort()).toEqual(
      [
        'core.bare',
        'core.filemode',
        'core.ignorecase',
        'core.logallrefupdates',
        'core.precomposeunicode',
        'core.repositoryformatversion',
        'core.symlinks',
        'extensions.objectformat',
      ].sort(),
    );
    for (const key of [
      'remote.origin.url',
      'remote.origin.fetch',
      'remote.origin.tagopt',
      'remote.my.dotted.name.url',
      'branch.main.remote',
      'branch.main.merge',
      'branch.feature/x.rebase',
      'Core.FileMode',
    ]) {
      expect([key, isAllowedLocalGitConfigKey(key)]).toEqual([key, true]);
    }
  });

  it('refuses every other key, including the ones left off on purpose', () => {
    for (const key of [
      'core.fsmonitor',
      'core.hookspath',
      'core.pager',
      'core.sshcommand',
      'core.editor',
      'core.worktree',
      'core.excludesfile',
      'core.attributesfile',
      'diff.external',
      'diff.x.textconv',
      'diff.x.command',
      'filter.x.clean',
      'filter.x.process',
      'merge.x.driver',
      'credential.helper',
      'gpg.program',
      'include.path',
      'includeif.gitdir:/x/.path',
      'remote.origin.promisor',
      'remote.origin.partialclonefilter',
      'remote.origin.pushurl',
      'remote.origin.uploadpack',
      'extensions.worktreeconfig',
      'submodule.lib.url',
      'user.name',
      'remote..url',
      'remote.url',
      'branch.remote',
      '',
    ]) {
      expect([key, isAllowedLocalGitConfigKey(key)]).toEqual([key, false]);
    }
  });

  it('checks a real repository: git init passes, an added key is named', () => {
    const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-lgc-')));
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: dir });
    expect(checkLocalGitConfig(dir, process.env).ok).toBe(true);
    execFileSync('git', ['config', '--local', 'filter.x.clean', 'cat'], { cwd: dir });
    const v = checkLocalGitConfig(dir, process.env);
    expect(v).toEqual({ ok: false, reason: 'key', key: 'filter.x.clean' });
    if (v.ok) throw new Error('unreachable');
    const message = localGitConfigRefusal(v, 'vault-guard');
    expect(message).toContain('filter.x.clean');
    expect(message).toContain('Clone the repository fresh and assess the clone.');
  });

  it('fails closed outside a repository', () => {
    const dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-lgc-none-')));
    const v = checkLocalGitConfig(dir, { ...process.env, GIT_CEILING_DIRECTORIES: path.dirname(dir) });
    expect(v.ok).toBe(false);
    expect(v.ok === false && v.reason).toBe('git');
  });
});

describe('presentRepoControls', () => {
  it('names every control file at any depth, case-insensitively, any entry kind but a directory', () => {
    const e = (p: string, type = 'blob', mode = '100644') => ({ mode, type, oid: '0'.repeat(40), path: p });
    expect(
      presentRepoControls([
        e('src/app.ts'),
        e('.vault-guard.json'),
        e('a/.vault-guard.local.json'),
        e('.vault-guard.baseline.json', 'blob', '120000'),
        e('x/.GITIGNORE'),
        e('y/.gitattributes'),
        e('z/.gitignore', 'tree', '040000'),
        e('not.gitignore'),
      ]),
    ).toEqual(['.vault-guard.baseline.json', '.vault-guard.json', 'a/.vault-guard.local.json', 'x/.GITIGNORE', 'y/.gitattributes']);
  });
});
