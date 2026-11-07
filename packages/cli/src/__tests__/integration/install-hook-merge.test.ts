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

  const INIT_HOOK_ONLY = ['init', '--skip-workflow', '--skip-agent-rules', '--skip-config'];

  itPosix('a foreign hook that only carries the vault-guard header line is merged, blocks a staged secret, and init --revert gives it back byte for byte', () => {
    const foreign =
      '#!/bin/sh\n# vault-guard pre-commit (installed by @vaultcompass/vault-guard)\necho "team hook ran"\n';
    const { repo, hook, env } = repoWithHook(foreign);

    const install = fx.runCli(INIT_HOOK_ONLY, repo, env);
    expect(install.code).toBe(0);
    expect(fs.readFileSync(hook, 'utf-8')).toContain('# --- end vault-guard ---');
    const again = fx.runCli(['install-hook'], repo, env);
    expect(again.code).toBe(0);
    expect(again.stdout + again.stderr).toMatch(/already installed/i);

    fx.write(repo, 'src/config.ts', `export const key = '${fx.AWS_KEY}';\n`);
    const blocked = commit(repo, env);
    expect(blocked.code).not.toBe(0);
    expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');

    const revert = fx.runCli(['init', '--revert'], repo, env);
    expect(revert.code).toBe(0);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(foreign);
  });

  itPosix('init --revert refuses with exit 1 and keeps the hook when lines were added to the hook init wrote', () => {
    const { repo, hook, env } = repoWithHook('');
    fs.rmSync(hook);

    expect(fx.runCli(INIT_HOOK_ONLY, repo, env).code).toBe(0);
    const edited = `${fs.readFileSync(hook, 'utf-8')}# team addition\nnpm run lint-staged\n`;
    fs.writeFileSync(hook, edited);

    const revert = fx.runCli(['init', '--revert'], repo, env);

    expect(revert.code).toBe(1);
    expect(revert.stdout + revert.stderr).toContain('.git/hooks/pre-commit');
    expect(revert.stdout + revert.stderr).toContain('vault-guard did not write all of it');
    expect(fs.readFileSync(hook, 'utf-8')).toBe(edited);
  });

  itPosix.each([
    ['install-hook', ['install-hook']],
    ['init', INIT_HOOK_ONLY],
  ])('%s refuses with exit 1 a hook vault-guard wrote that was edited after install, and --force rewrites it and says the edits were discarded', (_label, args) => {
    const { repo, hook, env } = repoWithHook('');
    fs.rmSync(hook);
    expect(fx.runCli(['install-hook'], repo, env).code).toBe(0);
    const script = fs.readFileSync(hook, 'utf-8');
    const edited = `${script}# team addition\nnpm run lint-staged\n`;
    fs.writeFileSync(hook, edited);

    const refused = fx.runCli(args, repo, env);
    expect(refused.code).toBe(1);
    expect(refused.stdout + refused.stderr).toContain('.git/hooks/pre-commit');
    expect(refused.stdout + refused.stderr).toMatch(/edited after install/);
    expect(refused.stdout + refused.stderr).toContain('--force');
    expect(fs.readFileSync(hook, 'utf-8')).toBe(edited);

    const forced = fx.runCli([...args, '--force'], repo, env);
    expect(forced.code).toBe(0);
    expect(forced.stdout + forced.stderr).toMatch(/edits .*discarded/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(script);
  });

  itPosix.each([
    ['a line inserted at line 3', (t: string) => { const l = t.split('\n'); l.splice(2, 0, 'export PATH="$HOME/bin:$PATH"'); return l.join('\n'); }],
    ['a template line deleted in the middle', (t: string) => t.split('\n').filter(l => !l.includes('command -v vault-guard')).join('\n')],
  ])('install-hook and init --revert both refuse a hook init wrote with %s, and change nothing', (_label, edit) => {
    const { repo, hook, env } = repoWithHook('');
    fs.rmSync(hook);
    expect(fx.runCli(['init'], repo, env).code).toBe(0);
    const edited = edit(fs.readFileSync(hook, 'utf-8'));
    fs.writeFileSync(hook, edited);
    const manifest = path.join(repo, '.vault-guard', 'manifest.json');
    const manifestBefore = fs.readFileSync(manifest, 'utf-8');

    const install = fx.runCli(['install-hook'], repo, env);
    expect(install.code).toBe(1);
    expect(install.stdout + install.stderr).toMatch(/edited after install/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(edited);

    const revert = fx.runCli(['init', '--revert'], repo, env);
    expect(revert.code).toBe(1);
    expect(revert.stdout + revert.stderr).toContain('vault-guard did not write all of it');
    expect(revert.stdout + revert.stderr).not.toMatch(/uninstalled hook/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(edited);
    expect(fs.readFileSync(manifest, 'utf-8')).toBe(manifestBefore);
    expect(fs.existsSync(path.join(repo, '.vault-guard.json'))).toBe(true);
  });

  itPosix.each(['owned', 'merged'])('init --revert --dry-run leaves a hook that is %s byte for byte', kind => {
    const { repo, hook, env } = repoWithHook('#!/bin/sh\necho "team hook ran"\n');
    if (kind === 'owned') fs.rmSync(hook);
    // init refuses a foreign hook, so the stanza goes in first; init then finds it installed.
    else expect(fx.runCli(['install-hook'], repo, env).code).toBe(0);
    expect(fx.runCli(['init'], repo, env).code).toBe(0);
    const before = fs.readFileSync(hook, 'utf-8');
    expect(before.includes('# --- end vault-guard ---')).toBe(kind === 'merged');

    const dry = fx.runCli(['init', '--revert', '--dry-run'], repo, env);

    expect(dry.code).toBe(0);
    expect(dry.stdout + dry.stderr).toMatch(/would uninstall hook/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(before);
    expect(fs.existsSync(path.join(repo, '.vault-guard', 'manifest.json'))).toBe(true);
  });

  itPosix('init --revert leaves a hook the user rewired to run vault-guard themselves, says so, and removes the other init files', () => {
    const { repo, hook, env } = repoWithHook('');
    fs.rmSync(hook);
    expect(fx.runCli(['init'], repo, env).code).toBe(0);
    const wired = '#!/bin/sh\nnpm test\nvault-guard scan --staged\n';
    fs.writeFileSync(hook, wired);

    const dry = fx.runCli(['init', '--revert', '--dry-run'], repo, env);
    expect(dry.code).toBe(0);
    expect(dry.stdout + dry.stderr).toMatch(/would leave hook in place/);
    expect(fs.existsSync(path.join(repo, '.vault-guard.json'))).toBe(true);

    const revert = fx.runCli(['init', '--revert'], repo, env);
    expect(revert.code).toBe(0);
    expect(revert.stdout + revert.stderr).toMatch(/left hook in place/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(wired);
    expect(fs.existsSync(path.join(repo, '.vault-guard.json'))).toBe(false);
    expect(fs.existsSync(path.join(repo, '.vault-guard', 'manifest.json'))).toBe(false);
  });

  itPosix('init --revert --dry-run predicts the refusal for a hook vault-guard did not write all of, and removes nothing', () => {
    const { repo, hook, env } = repoWithHook('');
    fs.rmSync(hook);
    expect(fx.runCli(['init'], repo, env).code).toBe(0);
    const edited = `${fs.readFileSync(hook, 'utf-8')}npm test\n`;
    fs.writeFileSync(hook, edited);

    const dry = fx.runCli(['init', '--revert', '--dry-run'], repo, env);

    expect(dry.code).toBe(1);
    expect(dry.stdout + dry.stderr).toMatch(/Revert would stop/);
    expect(dry.stdout + dry.stderr).toContain('vault-guard did not write all of it');
    expect(dry.stdout + dry.stderr).not.toMatch(/would uninstall hook/);
    expect(fs.readFileSync(hook, 'utf-8')).toBe(edited);
    expect(fs.existsSync(path.join(repo, '.vault-guard.json'))).toBe(true);
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

describe('install-hook merges into a husky 9 .husky/pre-commit', () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  /** A husky 9 layout (core.hooksPath .husky/_, a shim that runs the tracked hook with sh -e) and the built CLI on PATH. */
  function huskyRepo(tracked: string): { repo: string; hook: string; env: NodeJS.ProcessEnv } {
    const repo = fx.tmpDir('vg-husky-merge-');
    const bin = fx.tmpDir('vg-husky-merge-bin-');
    dirs.push(repo, bin);
    fx.initRepo(repo);
    const gen = path.join(repo, '.husky', '_');
    fs.mkdirSync(gen, { recursive: true });
    fs.writeFileSync(path.join(gen, '.gitignore'), '*\n');
    fs.writeFileSync(
      path.join(gen, 'h'),
      '#!/usr/bin/env sh\ntracked="$(dirname "$(dirname "$0")")/$(basename "$0")"\nsh -e "$tracked" "$@"\nexit $?\n',
      { mode: 0o755 },
    );
    fs.writeFileSync(path.join(gen, 'pre-commit'), '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n', { mode: 0o755 });
    fx.git(repo, ['config', '--local', 'core.hooksPath', '.husky/_']);
    const hook = path.join(repo, '.husky', 'pre-commit');
    fs.writeFileSync(hook, tracked, { mode: 0o755 });
    const wrapper = path.join(bin, 'vault-guard');
    fs.writeFileSync(wrapper, `#!/bin/sh\nexec '${process.execPath}' '${fx.CLI_ENTRY}' "$@"\n`, { mode: 0o755 });
    return { repo, hook, env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ''}` } };
  }

  function commit(repo: string, env: NodeJS.ProcessEnv): { code: number; output: string } {
    fx.git(repo, ['add', '-A']);
    const r = spawnSync('git', ['commit', '-q', '-m', 'test commit'], { cwd: repo, env, encoding: 'utf-8' });
    return { code: r.status ?? -1, output: `${r.stdout}${r.stderr}` };
  }

  itPosix.each([
    ['ends in exit 0', '#!/usr/bin/env sh\nnpm --version >/dev/null\nexit 0\n'],
    ['only mentions vault-guard in a comment', '#!/usr/bin/env sh\n# later: vault-guard scan --staged\nnpm --version >/dev/null\n'],
  ])('N2: a husky hook that %s gets the stanza after the shebang, and a staged secret is blocked', (_label, tracked) => {
    const { repo, hook, env } = huskyRepo(tracked);

    const install = fx.runCli(['install-hook'], repo, env);
    expect(install.code).toBe(0);
    expect(install.stdout + install.stderr).not.toMatch(/already contains/i);
    const merged = fs.readFileSync(hook, 'utf-8');
    expect(merged.startsWith('#!/usr/bin/env sh\n# --- vault-guard ---\n')).toBe(true);

    fx.write(repo, 'src/config.ts', `export const key = '${fx.AWS_KEY}';\n`);
    const blocked = commit(repo, env);
    expect(blocked.code).not.toBe(0);
    expect(blocked.output).toContain('COMMIT BLOCKED: secrets detected');
  });
});
