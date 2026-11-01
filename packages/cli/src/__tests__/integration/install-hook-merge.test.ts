import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

import * as fx from './git-fixture';

/**
 * `vault-guard install-hook` merges into a pre-commit hook it does not own
 * instead of overwriting it, and a free-text mention of vault-guard in a
 * foreign hook is not ownership. Driven end to end through the built CLI and a
 * real `git commit`, with `vault-guard` on PATH resolving to this worktree's
 * build.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

describe('install-hook merges into a foreign native hook', () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  /** A repo with a foreign hook, plus an env whose PATH has the built CLI as `vault-guard`. */
  function repoWithHook(hookText: string): { repo: string; hook: string; env: NodeJS.ProcessEnv } {
    const repo = fx.tmpDir('vg-merge-');
    const bin = fx.tmpDir('vg-merge-bin-');
    dirs.push(repo, bin);
    fx.initRepo(repo);
    const hooksDir = path.join(repo, '.git', 'hooks');
    fx.git(repo, ['config', '--local', 'core.hooksPath', hooksDir]);
    fs.mkdirSync(hooksDir, { recursive: true });
    const hook = path.join(hooksDir, 'pre-commit');
    fs.writeFileSync(hook, hookText, { mode: 0o755 });
    const wrapper = path.join(bin, 'vault-guard');
    fs.writeFileSync(wrapper, `#!/bin/sh\nexec '${process.execPath}' '${fx.CLI_ENTRY}' "$@"\n`, { mode: 0o755 });
    return { repo, hook, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}` } };
  }

  function commit(repo: string, env: NodeJS.ProcessEnv): { code: number; output: string } {
    fx.git(repo, ['add', '-A']);
    const r = spawnSync('git', ['commit', '-q', '-m', 'test commit'], { cwd: repo, env, encoding: 'utf-8' });
    return { code: r.status ?? -1, output: `${r.stdout}${r.stderr}` };
  }

  itPosix('a foreign three-line hook is merged, keeps running, and the merged hook blocks a staged secret', () => {
    const foreign = '#!/bin/sh\n# team hook\necho "team hook ran" > "$(git rev-parse --git-dir)/team-hook-ran"\n';
    const { repo, hook, env } = repoWithHook(foreign);

    const install = fx.runCli(['install-hook'], repo, env);
    expect(install.code).toBe(0);
    expect(install.stdout + install.stderr).toMatch(/Pre-commit hook installed/);
    const merged = fs.readFileSync(hook, 'utf-8');
    expect(merged).toContain('# --- vault-guard ---');
    expect(merged).toContain('# team hook');
    expect(fs.statSync(hook).mode & 0o111).not.toBe(0);

    fx.write(repo, 'src/config.ts', `export const key = '${fx.AWS_KEY}';\n`);
    const blocked = commit(repo, env);
    expect(blocked.code).not.toBe(0);
    expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');
    expect(fs.existsSync(path.join(repo, '.git', 'team-hook-ran'))).toBe(false);

    fs.rmSync(path.join(repo, 'src'), { recursive: true });
    fx.write(repo, 'README.md', 'clean\n');
    const clean = commit(repo, env);
    expect(clean.code).toBe(0);
    expect(fs.existsSync(path.join(repo, '.git', 'team-hook-ran'))).toBe(true);
  });

  itPosix('NB5: a foreign hook that only mentions vault-guard in a comment is merged, not adopted', () => {
    const foreign =
      '#!/bin/sh\n# team lint hook. TODO: also run vault-guard (scan --staged) once the team agrees.\nnpm run lint-staged || true\n';
    const { repo, hook, env } = repoWithHook(foreign);

    const install = fx.runCli(['install-hook'], repo, env);
    expect(install.code).toBe(0);
    expect(install.stdout + install.stderr).not.toMatch(/already installed/i);
    expect(fs.readFileSync(hook, 'utf-8')).toContain('# --- vault-guard ---');

    fx.write(repo, 'src/config.ts', `export const key = '${fx.AWS_KEY}';\n`);
    const blocked = commit(repo, env);
    expect(blocked.code).not.toBe(0);
    expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');
  });

  itPosix.each([
    ['a trailing comment', '#!/bin/sh\nnpm --version >/dev/null  # TODO: && vault-guard scan --staged once the team agrees\n'],
    ['an echoed string', '#!/bin/sh\necho "Reminder: run (vault-guard scan --staged) before pushing"\n'],
    ['a heredoc body', '#!/bin/sh\ncat <<EOF\nvault-guard scan --staged\nEOF\n'],
    ['a multi-line string', "#!/bin/sh\n: '\nvault-guard scan --staged\n'\n"],
    ['an || true', '#!/bin/sh\nvault-guard scan --staged || true\n'],
  ])('M1: a foreign hook that mentions the command in %s is merged, and the merged hook blocks a staged secret', (_label, foreign) => {
    const { repo, hook, env } = repoWithHook(foreign);

    const install = fx.runCli(['install-hook'], repo, env);
    expect(install.code).toBe(0);
    expect(install.stdout + install.stderr).not.toMatch(/already (installed|runs)/i);
    expect(fs.readFileSync(hook, 'utf-8')).toContain('# --- vault-guard ---');

    fx.write(repo, 'src/config.ts', `export const key = '${fx.AWS_KEY}';\n`);
    const blocked = commit(repo, env);
    expect(blocked.code).not.toBe(0);
    expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');
  });

  itPosix('install-hook twice appends nothing, and a trailing exit 0 in the foreign hook does not skip the scan', () => {
    const foreign = '#!/bin/sh\n# team hook\nexit 0\n';
    const { repo, hook, env } = repoWithHook(foreign);

    expect(fx.runCli(['install-hook'], repo, env).code).toBe(0);
    const once = fs.readFileSync(hook, 'utf-8');
    const second = fx.runCli(['install-hook'], repo, env);
    expect(second.code).toBe(0);
    expect(second.stdout + second.stderr).toMatch(/already installed/i);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(once);

    // Even a trailing exit 0 in the foreign hook does not skip the scan.
    fx.write(repo, 'src/config.ts', `export const key = '${fx.AWS_KEY}';\n`);
    expect(commit(repo, env).code).not.toBe(0);
  });
});
