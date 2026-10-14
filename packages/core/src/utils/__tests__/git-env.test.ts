import { execFileSync } from 'child_process';

import { CLEAN_GIT_ENV_STRIPPED, cleanGitEnv } from '../git-env';

/**
 * File-set git calls run with git's local-repository variables removed
 * (design 2026-10-12, section 6).
 */
describe('cleanGitEnv', () => {
  const KEPT = ['GIT_CONFIG_PARAMETERS', 'GIT_CONFIG_COUNT'];

  it('U16: the stripped list covers git rev-parse --local-env-vars except the two config variables', () => {
    const local = execFileSync('git', ['rev-parse', '--local-env-vars'], { encoding: 'utf-8' })
      .split('\n')
      .map(l => l.trim())
      .filter(Boolean);
    expect(local.length).toBeGreaterThan(5);
    for (const name of local) {
      expect({ name, covered: CLEAN_GIT_ENV_STRIPPED.includes(name) || KEPT.includes(name) }).toEqual({
        name,
        covered: true,
      });
    }
  });

  it('U16: strips every listed variable, keeps the two config variables, and sets GIT_OPTIONAL_LOCKS=0 and GIT_NO_REPLACE_OBJECTS=1', () => {
    const saved = { ...process.env };
    try {
      for (const name of [...CLEAN_GIT_ENV_STRIPPED, ...KEPT]) process.env[name] = `set-${name}`;
      process.env.GIT_OPTIONAL_LOCKS = '1';
      const env = cleanGitEnv();
      // Stripped, except GIT_NO_REPLACE_OBJECTS, which is then set to 1.
      for (const name of CLEAN_GIT_ENV_STRIPPED.filter(n => n !== 'GIT_NO_REPLACE_OBJECTS')) {
        expect({ name, v: env[name] }).toEqual({ name, v: undefined });
      }
      expect(env.GIT_NO_REPLACE_OBJECTS).toBe('1');
      for (const name of KEPT) expect(env[name]).toBe(`set-${name}`);
      expect(env.GIT_OPTIONAL_LOCKS).toBe('0');
      // The search path survives in whatever case the platform spells it
      // (`Path` on Windows): a spread copy of process.env keeps the real key.
      const pathKeys = Object.keys(env).filter(k => k.toUpperCase() === 'PATH');
      expect(pathKeys.length).toBe(1);
      expect(env[pathKeys[0]]).toBe(process.env.PATH);
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });

  it('U16: on Windows names are matched case-insensitively, so no other spelling survives', () => {
    const base: NodeJS.ProcessEnv = {
      Path: 'C:\\Windows\\system32',
      Git_Index_File: 'C:\\hook\\index',
      git_dir: 'C:\\elsewhere\\.git',
      git_optional_locks: '1',
      Git_No_Replace_Objects: '0',
      Git_Config_Parameters: "'safe.directory=*'",
    };
    const env = cleanGitEnv(base, 'win32');
    expect(env).toEqual({
      Path: 'C:\\Windows\\system32',
      Git_Config_Parameters: "'safe.directory=*'",
      GIT_OPTIONAL_LOCKS: '0',
      GIT_NO_REPLACE_OBJECTS: '1',
    });
    // POSIX names are case-sensitive: there a lowercase name is another variable.
    expect(cleanGitEnv({ git_dir: 'x', GIT_DIR: 'y' }, 'linux')).toEqual({
      git_dir: 'x',
      GIT_OPTIONAL_LOCKS: '0',
      GIT_NO_REPLACE_OBJECTS: '1',
    });
  });
});
