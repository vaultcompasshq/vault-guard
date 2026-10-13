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
 */
export function cleanGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of CLEAN_GIT_ENV_STRIPPED) delete env[name];
  env.GIT_OPTIONAL_LOCKS = '0';
  // Read the object a listing names, never a refs/replace substitute for it.
  // Hardening for persistent self-hosted workspaces; an Action checkout never
  // fetches refs/replace.
  env.GIT_NO_REPLACE_OBJECTS = '1';
  return env;
}

/**
 * The environment every plain and pull-request file-set and content git call
 * runs with: {@link cleanGitEnv}.
 */
export function fileSetGitEnv(): NodeJS.ProcessEnv {
  return cleanGitEnv();
}
