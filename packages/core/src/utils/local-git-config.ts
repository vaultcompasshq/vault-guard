/**
 * The repository-local git config allowlist that `scan --no-repo-controls`
 * checks before its first other git call.
 *
 * Source: design 2026-10-28 (proposal and outside-policy runs), section 3.2
 * (DECISION 3, the allowlist and the keys left off it on purpose) and section
 * 6 (DECISION 11, review finding B2).
 *
 * WHY. Content in the tree cannot run a program by itself: a `.gitattributes`
 * filter or diff driver only runs when git config names a program for it.
 * A fresh clone writes only `core.*`, `remote.*` and `branch.*` keys, so on a
 * clone the person running the scan made, git is safe. A directory handed
 * over with its own `.git/config` is not: `core.fsmonitor` runs on
 * `ls-files`, `filter.<driver>.clean` runs on `status` and `hash-object`,
 * and the set of keys that can name a program (`core.pager`,
 * `core.sshCommand`, `diff.external`, `credential.helper`, `include.path`,
 * `core.worktree`, ...) is open-ended. So the check is an ALLOWLIST, never a
 * list of known-bad keys: anything not named below refuses the run.
 *
 * `--local` lists the repository's own file and does not follow includes, so
 * an `include.path` or `includeIf.*` key is itself listed, and refused.
 *
 * Deliberately NOT allowed:
 *  - `remote.<name>.promisor` and `remote.<name>.partialclonefilter`: on a
 *    partial clone a later whole-history read would fetch missing objects from
 *    a host the repository's owner chose.
 *  - `extensions.worktreeConfig`: a repository with per-worktree config is
 *    refused rather than read.
 *
 * COPIED, NOT SHARED. dep-guard runs the same check under its own
 * `--no-repo-controls` and is meant to carry a copy of this file, never a
 * shared npm package, so either gate stays safe run alone. The family's
 * convention for code kept in step across repositories is a full copy with a
 * header saying so (see the hygiene script, scripts/check-private-names.cjs);
 * there is no automated cross-repository sync check today. This module
 * therefore imports nothing from vault-guard: copy it whole, and change the
 * allowlist in every copy at once.
 */

import { spawnSync } from 'child_process';

/** Keys allowed exactly, lowercased as `git config --name-only` prints them. */
export const LOCAL_GIT_CONFIG_ALLOWED_KEYS: readonly string[] = [
  'core.repositoryformatversion',
  'core.filemode',
  'core.bare',
  'core.logallrefupdates',
  'core.ignorecase',
  'core.precomposeunicode',
  'core.symlinks',
  'extensions.objectformat',
];

/**
 * Keys allowed for any subsection name: `remote.<name>.<variable>` and
 * `branch.<name>.<variable>`. The name may itself contain dots.
 */
export const LOCAL_GIT_CONFIG_ALLOWED_PER_NAME: Readonly<Record<string, readonly string[]>> = {
  remote: ['url', 'fetch', 'tagopt'],
  branch: ['remote', 'merge', 'rebase'],
};

/**
 * Whether one key, as `git config --local --list --name-only` prints it, is
 * on the allowlist. Section and variable names are case-insensitive in git
 * (it prints them lowercased); a subsection name is kept as written.
 */
export function isAllowedLocalGitConfigKey(key: string): boolean {
  const lower = key.toLowerCase();
  if (LOCAL_GIT_CONFIG_ALLOWED_KEYS.includes(lower)) return true;
  const first = key.indexOf('.');
  const last = key.lastIndexOf('.');
  // A per-name key has a non-empty subsection between the first and last dot.
  if (first <= 0 || last <= first + 1) return false;
  const section = key.slice(0, first).toLowerCase();
  const variable = key.slice(last + 1).toLowerCase();
  const allowed = LOCAL_GIT_CONFIG_ALLOWED_PER_NAME[section];
  return allowed !== undefined && allowed.includes(variable);
}

/** The outcome of {@link checkLocalGitConfig}. */
export type LocalGitConfigVerdict =
  | { ok: true; keys: string[] }
  /** A key off the allowlist: the first one, in the order git listed them. */
  | { ok: false; reason: 'key'; key: string }
  /** git could not list the local config: not a repository, or git failed. */
  | { ok: false; reason: 'git'; detail: string };

/**
 * Read `git config --local --list --name-only -z` in `cwd` and check every key
 * against the allowlist. Reading config runs no program. Fails closed: a git
 * failure is a verdict of its own, never a pass.
 */
export function checkLocalGitConfig(cwd: string, env: NodeJS.ProcessEnv): LocalGitConfigVerdict {
  const r = spawnSync('git', ['config', '--local', '--list', '--name-only', '-z'], {
    cwd,
    env,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.error !== undefined || r.status !== 0) {
    const stderr = typeof r.stderr === 'string' ? r.stderr.trim() : '';
    const detail =
      stderr.length > 0 ? stderr : String(r.error ?? `git exited with status ${String(r.status)}`);
    return { ok: false, reason: 'git', detail };
  }
  const keys = r.stdout.split('\0').filter(k => k.length > 0);
  for (const key of keys) {
    if (!isAllowedLocalGitConfigKey(key)) return { ok: false, reason: 'key', key };
  }
  return { ok: true, keys };
}

/** The sentence a refusal over a key ends with. */
export const LOCAL_GIT_CONFIG_REMEDY = 'Clone the repository fresh and assess the clone.';

/**
 * The refusal message for a verdict that is not ok, naming the key (JSON
 * escaped when it holds a control character, since it is repository text).
 */
export function localGitConfigRefusal(
  verdict: Exclude<LocalGitConfigVerdict, { ok: true }>,
  tool: string,
): string {
  if (verdict.reason === 'git') {
    return (
      `${tool}: could not read the repository's local git config (git config --local --list): ` +
      `${verdict.detail}. Nothing was scanned.`
    );
  }
  // eslint-disable-next-line no-control-regex
  const key = /[\u0000-\u001f\u007f]/.test(verdict.key) ? JSON.stringify(verdict.key) : verdict.key;
  return (
    `${tool}: refusing to run: the repository's local git config sets ${key}, which is not on the ` +
    'allowlist of keys a fresh clone writes. A key like this can make git run a program named by ' +
    `whoever wrote that config. ${LOCAL_GIT_CONFIG_REMEDY} Nothing was scanned.`
  );
}
