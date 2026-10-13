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
      expect(env.PATH).toBe(process.env.PATH);
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  });
});
