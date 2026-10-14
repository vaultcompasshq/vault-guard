/**
 * git's local-repository variables, the set `git rev-parse --local-env-vars`
 * prints, MINUS `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`: those two carry
 * configuration, not repository location, and containers commonly pass
 * `safe.directory` through them. Hard-coded, so there is no run-time failure
 * route; a test fails the build if a git release adds a variable.
 */
export const CLEAN_GIT_ENV_STRIPPED: readonly string[] = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_PREFIX',
  'GIT_IMPLICIT_WORK_TREE',
  'GIT_INTERNAL_SUPER_PREFIX',
  'GIT_GRAFT_FILE',
  'GIT_SHALLOW_FILE',
  'GIT_NO_REPLACE_OBJECTS',
  'GIT_REPLACE_REF_BASE',
  'GIT_CONFIG',
];

/**
 * A copy of `process.env` with git's local-repository variables removed and
 * `GIT_OPTIONAL_LOCKS=0` and `GIT_NO_REPLACE_OBJECTS=1` added (design
 * 2026-10-12, section 6).
 *
 * The plain and pull-request file sets describe the work tree. A pre-commit
 * hook's `GIT_INDEX_FILE` (or a stray `GIT_DIR`) is not the work tree: a
 * submodule listed through the outer repository's index fails or lists the
 * wrong paths, and a hook in one repository that scans another would list the
 * other through the first one's index. `--staged` does NOT use this: the
 * hook's index is exactly what it must read.
 *
 * On Windows environment names are case-insensitive (git for Windows reads
 * `Git_Index_File` as `GIT_INDEX_FILE`), and a spread copy of `process.env`
 * keeps each name in whatever case it was set. So there the names are matched
 * case-insensitively, both to strip and before the two set variables are
 * written, so no second spelling survives beside them. `Path` keeps its own
 * case; Node's spawn finds it case-insensitively. `base` and `platform` are
 * for the tests.
 */
export function cleanGitEnv(
  base: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  const set = { GIT_OPTIONAL_LOCKS: '0', GIT_NO_REPLACE_OBJECTS: '1' };
  const drop = new Set([...CLEAN_GIT_ENV_STRIPPED, ...Object.keys(set)]);
  for (const name of Object.keys(env)) {
    if (drop.has(platform === 'win32' ? name.toUpperCase() : name)) delete env[name];
  }
  env.GIT_OPTIONAL_LOCKS = set.GIT_OPTIONAL_LOCKS;
  // Read the object a listing names, never a refs/replace substitute for it.
  // Hardening for persistent self-hosted workspaces; an Action checkout never
  // fetches refs/replace.
  env.GIT_NO_REPLACE_OBJECTS = set.GIT_NO_REPLACE_OBJECTS;
  return env;
}

/**
 * The environment every plain and pull-request file-set and content git call
 * runs with: {@link cleanGitEnv}.
 */
export function fileSetGitEnv(): NodeJS.ProcessEnv {
  return cleanGitEnv();
}
