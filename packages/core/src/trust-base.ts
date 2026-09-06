/**
 * Pull-request mode: read every control input from the base ref.
 *
 * The defect this closes, stated plainly. Every input that decides what
 * vault-guard reports was read out of the tree it was judging, and on a
 * pull-request run that tree belongs to the pull request. One commit could add
 * a real provider key and, beside it, `"ignore": {"paths": ["**"]}`, or
 * `severity_overrides` turning the matching rule off, or `"fail_on": "none"`,
 * or a `.vault-guard.local.json` the base never had, or a rewritten
 * `.vault-guard.baseline.json` carrying the fingerprint of the very finding it
 * was adding, or a `.gitignore` covering the file the key sits in, or simply
 * the key placed under a directory named `vendor`. Measured on a scratch
 * repository, every one of those turned exit 1 into exit 0 with no line of
 * output saying anything had been muted.
 *
 * The fix is not a heuristic about which edits look suspicious. It is base
 * versus head, and it is plain git: on a pull-request run the CONTROL INPUTS
 * come from the base ref, and the head tree is the thing under judgment. A
 * control input that differs between the two never takes effect for the run,
 * and the report says it was proposed. Outside pull-request mode nothing
 * changes, because a pre-commit hook and a direct CLI run are already inside
 * the trust boundary.
 *
 * Three rules hold everything here together, and they are the same three the
 * sibling gate settled on, deliberately:
 *
 *  - READS ONLY, AND NEVER INTO THE REPOSITORY. `git ls-tree`, `git show`,
 *    `git ls-files` and `git rev-parse`, all of which only read. No checkout
 *    switch, no stash, no temporary worktree, no write of any kind. A scanner
 *    that moved the user's HEAD to do its job would be a worse bug than the
 *    one it fixes.
 *
 *  - FAIL CLOSED ON THE REF. A ref that will not resolve is could-not-run and
 *    exits 2. It is never a reason to fall back to the head, because falling
 *    back to the head is precisely the behaviour being removed, and it would
 *    be reachable by anyone who could make the base ref unfetchable.
 *
 *  - A MISSING PATH AT THE BASE IS NOT A FAILURE. A branch that adopts
 *    vault-guard for the first time has no config at the base, and that means
 *    "no control input", which the scanner already knows how to handle: it
 *    runs on its defaults. The ref is verified first precisely so this case
 *    can be told apart from a broken ref.
 */

import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

import { ConfigError } from './errors';
import { listConfigSearchDirs, parseConfigText, type VaultGuardConfig } from './config';
import { BASELINE_FILENAME, parseBaselineText } from './baseline';
import { DEFAULT_FAIL_ON, isFailOnThreshold, type FailOnThreshold } from './utils/fail-on';

/**
 * Repository config that must never decide what vault-guard reads, prepended
 * to every git command here for the same reason `utils/git-utils.ts` does it:
 * a gate whose inputs can be changed by a line in `.git/config` is not a gate.
 */
const FORCED_GIT_CONFIG = ['-c', 'diff.relative=false', '-c', 'core.quotePath=false'];

/** The two config filenames, in the order {@link loadConfig} tries them. */
const CONFIG_FILENAMES = ['.vault-guard.json', '.vault-guard.local.json'] as const;

/**
 * A base ref this scanner cannot judge against, described for a user. The CLI
 * catches this class, prints the one line, and exits 2 having scanned nothing.
 */
export class TrustBaseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TrustBaseError';
  }
}

/** The one line a report prints when the head proposes a different config. */
export const CONFIG_PROPOSAL_LINE = 'config changed in this pull request';

/** The one line a report prints when the head proposes a different baseline. */
export const BASELINE_PROPOSAL_LINE = 'baseline changed in this pull request';

/** The head carries a config the base ref does not. The run uses its defaults. */
export const CONFIG_ADDED_LINE = 'config added in this pull request';

/** The head carries a baseline the base ref does not. Nothing is suppressed. */
export const BASELINE_ADDED_LINE = 'baseline added in this pull request';

function runGit(cwd: string, args: string[]): string | null {
  try {
    return execFileSync('git', [...FORCED_GIT_CONFIG, ...args], {
      cwd,
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}

/**
 * What a rev resolves to, or null when it does not resolve here.
 *
 * `--quiet` suppresses git's own explanation, so there is nothing worth
 * forwarding on failure: handing the user `Command failed: git rev-parse
 * --verify --quiet origin/nope` gives them a command line to run rather than a
 * thing to fix. Null, and the caller writes the sentence.
 */
function resolve(repoRoot: string, rev: string, kind: 'commit' | 'tree'): string | null {
  const out = runGit(repoRoot, ['rev-parse', '--verify', '--quiet', `${rev}^{${kind}}`]);
  return out === null ? null : out.trim();
}

/** Resolve symlinks so `path.relative` against git's physical root holds. */
function canonicalDir(dir: string): string {
  try {
    return fs.realpathSync.native(dir);
  } catch {
    return dir;
  }
}

/**
 * The worktree root, which every path in this module is expressed relative to.
 *
 * Running git at the root and passing root-relative paths keeps `..` out of
 * the pathspecs entirely, which matters because the config search walks
 * UPWARD from the scan directory: anchored anywhere else, half of the
 * candidate paths would be `../../.vault-guard.json`.
 */
function repoRootOf(startDir: string, ref: string): string {
  const out = runGit(startDir, ['rev-parse', '--show-toplevel']);
  const root = out === null ? '' : out.trim();
  if (!root) {
    throw new TrustBaseError(
      `vault-guard: cannot read control inputs from base ref "${ref}": ` +
        `${startDir} is not inside a git worktree, so there is no base ref to ` +
        'read from. Pull-request mode needs a git checkout. Nothing was scanned.',
    );
  }
  return canonicalDir(root);
}

/**
 * Refuse the run unless the ref names a commit that is NOT the one being
 * judged.
 *
 * Two separate refusals, and the second is the one that matters.
 *
 * Resolving the ref at all is verified BEFORE any path is read, which is what
 * lets a path that is simply absent at the base be read as "no control input"
 * rather than as a broken setup. Without this order the two are the same
 * non-zero exit from git.
 *
 * The ref must then differ from HEAD, because a trust base that IS the head
 * commit puts the whole boundary back where it started: every control input
 * comes from the tree under judgment, no config change can ever differ from
 * its own base, and the run reports pull-request mode while scanning the pull
 * request against its own muting. Nothing about that state is visible in a
 * green tick.
 *
 * It is not a hypothetical typo. A workflow author writing
 * `--trust-base ${{ github.sha }}` gets exactly this, because on a
 * pull_request event with the default actions/checkout that SHA is the merge
 * commit, which is HEAD. The comparison is on the RESOLVED COMMITS rather than
 * on the spelling, since the same commit reached through a branch name, a tag
 * or a raw SHA is the same hole.
 *
 * AND THE TREES MUST DIFFER TOO, which the commit comparison alone does not
 * give. Two different commits can carry one identical tree, and then every
 * control input still comes from the tree under judgment while the commit
 * check waves it through. This is not a curiosity: what GitHub publishes as
 * refs/pull/N/merge is a merge commit whose tree, when the base has not moved
 * since the fork, IS the head branch's tree, and actions/checkout leaves that
 * commit checked out. A workflow passing
 * `--trust-base ${{ github.event.pull_request.head.sha }}` then names a
 * different commit holding the same tree, and the muting passes.
 *
 * Merging the base into the branch changes the head's tree, so a pull request
 * that does that is judged normally rather than swallowed by this rule.
 */
export function assertTrustBaseResolvable(repoRoot: string, ref: string): void {
  const base = resolve(repoRoot, ref, 'commit');
  if (base === null) {
    throw new TrustBaseError(
      `vault-guard: cannot read control inputs from base ref "${ref}": it does ` +
        'not resolve to a commit in this repository. Nothing was scanned. In CI, ' +
        'fetch the base branch (actions/checkout with fetch-depth: 0) before ' +
        'running the gate.',
    );
  }

  const head = resolve(repoRoot, 'HEAD', 'commit');
  if (head === null) {
    // No head commit to compare against, so the one property that makes
    // pull-request mode mean anything cannot be established. Fail closed:
    // this is could-not-run, not a quiet downgrade to trusting the head.
    throw new TrustBaseError(
      `vault-guard: cannot resolve HEAD to compare against base ref "${ref}": ` +
        'this is not a git repository with any commits. Pull-request mode needs ' +
        'both a base commit and a head commit. Nothing was scanned.',
    );
  }

  if (base === head) {
    throw new TrustBaseError(
      `vault-guard: refusing "${ref}" as the trust base: it resolves to ${head}, ` +
        'the same commit as HEAD, so every control input would come from the tree ' +
        'being scanned and pull-request mode would be off while still reporting as ' +
        'on. Pass the base branch (for example origin/main), not the head commit: ' +
        'on a pull_request event github.sha is the merge commit, which is HEAD. ' +
        'Nothing was scanned.',
    );
  }

  const baseTree = resolve(repoRoot, ref, 'tree');
  const headTree = resolve(repoRoot, 'HEAD', 'tree');
  if (baseTree !== null && headTree !== null && baseTree === headTree) {
    throw new TrustBaseError(
      `vault-guard: refusing "${ref}" as the trust base: it is a different ` +
        `commit from HEAD but carries an identical tree (${headTree}), so every ` +
        'control input would come from the tree being scanned and there would be ' +
        'nothing for pull-request mode to compare. A pull request\'s merge ref ' +
        'looks exactly like this when the base has not moved. Pass the base ' +
        'branch (for example origin/main), not the head or merge commit. ' +
        'Nothing was scanned.',
    );
  }
}

export interface ControlFile {
  /** Path relative to the worktree root, as it exists at that side. */
  path: string;
  /** Blob contents. For a symlink this is the LINK TARGET, not the file. */
  text: string;
  /**
   * The git file mode: 100644 a regular file, 100755 an executable one,
   * 120000 a symlink, 160000 a submodule, 040000 a directory.
   *
   * Carried because the CONTENT of a control input is not the whole of it.
   * Replacing the config with a symlink whose target holds the base config's
   * exact bytes changes nothing a content comparison can see, and that is the
   * first half of a two-step: land the link, then edit the link target in a
   * later pull request where the config path never appears in the diff at all.
   */
  mode: string;
  /** The git object type: blob, tree, or commit. */
  type: string;
}

/** True for the two modes that mean an ordinary file git will hand back. */
export function isRegularFileMode(mode: string): boolean {
  return mode === '100644' || mode === '100755';
}

/**
 * The tree entry for one path at a ref, or null when the ref has no such path.
 *
 * ls-tree rather than `git show` alone, because `git show ref:path` on a
 * symlink prints the link target and says nothing about the entry being a
 * link. The mode is the only place that fact lives.
 */
function treeEntry(
  repoRoot: string,
  ref: string,
  relativePath: string,
): { mode: string; type: string } | null {
  const out = runGit(repoRoot, ['ls-tree', ref, '--', `./${relativePath}`]);
  if (out === null) return null;
  const line = out.split('\n').find(candidate => candidate.trim().length > 0);
  if (line === undefined) return null;
  const [mode, type] = line.split(/\s+/);
  if (!mode || !type) return null;
  return { mode, type };
}

/**
 * One file's contents at a ref, or null when the ref does not carry it.
 *
 * The `./` is load-bearing. It keeps the argument out of git's revision
 * grammar, where a path is otherwise free to be read as a stage reference,
 * and it anchors resolution at the directory git is run in.
 */
export function readFileAtRef(
  repoRoot: string,
  ref: string,
  relativePath: string,
): string | null {
  return runGit(repoRoot, ['show', `${ref}:./${relativePath}`]);
}

function controlFileAt(
  repoRoot: string,
  ref: string,
  relativePath: string,
): ControlFile | null {
  const entry = treeEntry(repoRoot, ref, relativePath);
  if (entry === null) return null;
  // A non-blob (a directory, a submodule) has no contents to read, and the
  // empty string keeps it distinguishable from a missing entry while the mode
  // carries what it actually is.
  const text = entry.type === 'blob' ? (readFileAtRef(repoRoot, ref, relativePath) ?? '') : '';
  return { path: relativePath, text, mode: entry.mode, type: entry.type };
}

/**
 * The nearest control file on the same search walk `loadConfig` uses, read at
 * a ref rather than off disk.
 *
 * BOTH sides of the comparison go through this, base and head alike. Reading
 * the head from the working tree instead would follow symlinks: the base side
 * would then hold a link target string while the head side held the linked
 * file's contents, the two would compare equal, and a pull request that turned
 * the config into a symlink would be reported as having changed no control
 * input at all. One reader for both sides is the only way the two can be
 * compared on equal terms. It also means an uncommitted local edit is not
 * mistaken for something the pull request proposes.
 */
function findControlFileAtRef(
  repoRoot: string,
  ref: string,
  searchDirs: string[],
  filenames: readonly string[],
): ControlFile | null {
  for (const dir of searchDirs) {
    for (const filename of filenames) {
      const rel = path.posix.join(dir, filename);
      const found = controlFileAt(repoRoot, ref, rel);
      if (found !== null) return found;
    }
  }
  return null;
}

/**
 * The config search directories, as worktree-root-relative posix paths,
 * nearest to the scan directory first.
 *
 * Derived from {@link listConfigSearchDirs} so the walk policy has exactly one
 * definition: never above the repository root, nearest directory wins. What
 * changes here is only where each directory is LOOKED UP, which is a git tree
 * rather than the filesystem, so a directory that exists in one and not the
 * other is handled by the lookup returning nothing.
 */
function searchDirsRelativeToRoot(startDir: string, repoRoot: string): string[] {
  const out: string[] = [];
  for (const dir of listConfigSearchDirs(canonicalDir(startDir))) {
    const rel = path.relative(repoRoot, canonicalDir(dir)).split(path.sep).join('/');
    if (rel.startsWith('..') || path.isAbsolute(rel)) continue;
    out.push(rel === '' ? '.' : rel);
  }
  return out;
}

/**
 * Whether two control documents differ in what they SAY.
 *
 * Compared as parsed documents rather than as bytes, so a reflowed array or a
 * changed indent is not reported as a proposal to loosen the gate; a report
 * that cries wolf on whitespace is a report reviewers learn to skip. When
 * either side will not parse, the raw text is compared instead, which is the
 * fail-closed direction: an unparseable head config is reported as a change
 * rather than quietly matching.
 */
function documentsDiffer(base: string | null, head: string | null): boolean {
  if (base === null && head === null) return false;
  if (base === null || head === null) return true;
  try {
    return JSON.stringify(JSON.parse(base) ?? null) !== JSON.stringify(JSON.parse(head) ?? null);
  } catch {
    return base !== head;
  }
}

/** What kind of file the head made a control input into, when that changed. */
export type ControlShapeChange = 'symlink' | 'not-a-file' | 'removed' | 'mode';

/**
 * How the head changed the SHAPE of a control input, or null when it did not.
 *
 * Distinct from a content change because the shape is the part a content
 * comparison is blind to, and because each of these deserves its own sentence
 * in the report: "the config is now a link" and "the config now has the
 * execute bit" are not the same news.
 */
function shapeChange(
  base: ControlFile | null,
  head: ControlFile | null,
): ControlShapeChange | null {
  if (head === null) return base === null ? null : 'removed';
  if (head.mode === '120000') return 'symlink';
  if (!isRegularFileMode(head.mode)) return 'not-a-file';
  if (base !== null && base.mode !== head.mode) return 'mode';
  return null;
}

/** One line naming a shape change, for the proposals list. */
function shapeProposal(input: string, change: ControlShapeChange): string {
  switch (change) {
    case 'symlink':
      return `${input} is a symlink at the head commit, not a regular file`;
    case 'not-a-file':
      return `${input} is not a regular file at the head commit`;
    case 'removed':
      return `${input} removed in this pull request`;
    case 'mode':
      return `${input} file mode changed in this pull request`;
  }
}

function asObject(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

function stringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((x): x is string => typeof x === 'string') : [];
}

function ignoreEntries(config: Record<string, unknown> | null): string[] {
  if (config === null) return [];
  const ignore = config.ignore;
  if (ignore === null || typeof ignore !== 'object' || Array.isArray(ignore)) return [];
  const o = ignore as Record<string, unknown>;
  return [...stringList(o.paths), ...stringList(o.patterns)];
}

const FAIL_ON_STRICTNESS: Record<FailOnThreshold, number> = {
  low: 4,
  medium: 3,
  high: 2,
  critical: 1,
  none: 0,
};

function failOnOf(config: Record<string, unknown> | null): FailOnThreshold {
  const v = config?.fail_on;
  return isFailOnThreshold(v) ? v : DEFAULT_FAIL_ON;
}

function countAddedKeys(base: unknown, head: unknown): number {
  const b = base !== null && typeof base === 'object' && !Array.isArray(base)
    ? (base as Record<string, unknown>)
    : {};
  const h = head !== null && typeof head === 'object' && !Array.isArray(head)
    ? (head as Record<string, unknown>)
    : {};
  let n = 0;
  for (const [key, value] of Object.entries(h)) {
    if (!(key in b) || b[key] !== value) n++;
  }
  return n;
}

/**
 * A short parenthetical for the config proposal line, or the empty string.
 *
 * Deliberately cheap and deliberately incomplete. It answers "what did this
 * pull request try to loosen" for the four levers that actually mute the
 * scanner, and says nothing at all when it cannot answer, rather than
 * manufacturing a summary that a reviewer would then trust as exhaustive. The
 * full diff is one `git diff` away and is the authority.
 */
function summariseConfigChange(baseText: string | null, headText: string | null): string {
  const base = asObject(baseText);
  const head = asObject(headText);
  if (head === null) return '';

  const parts: string[] = [];

  const baseIgnores = new Set(ignoreEntries(base));
  const addedIgnores = ignoreEntries(head).filter(p => !baseIgnores.has(p)).length;
  if (addedIgnores > 0) {
    parts.push(`${addedIgnores} pattern${addedIgnores === 1 ? '' : 's'} added to ignore`);
  }

  if (FAIL_ON_STRICTNESS[failOnOf(head)] < FAIL_ON_STRICTNESS[failOnOf(base)]) {
    parts.push('fail_on lowered');
  }

  const overrides = countAddedKeys(base?.severity_overrides, head.severity_overrides);
  if (overrides > 0) {
    parts.push(`${overrides} severity override${overrides === 1 ? '' : 's'} added`);
  }

  const baseExtra = Array.isArray(base?.extra_patterns) ? base.extra_patterns.length : 0;
  const headExtra = Array.isArray(head.extra_patterns) ? head.extra_patterns.length : 0;
  if (headExtra > baseExtra) {
    const n = headExtra - baseExtra;
    parts.push(`${n} extra pattern${n === 1 ? '' : 's'} added`);
  }

  return parts.length === 0 ? '' : ` (${parts.join(', ')})`;
}

/** The same, for the baseline: how many fingerprints the head added or dropped. */
function summariseBaselineChange(baseText: string | null, headText: string | null): string {
  if (headText === null) return '';
  const base = parseBaselineText(baseText ?? '{}').fingerprints;
  const head = parseBaselineText(headText).fingerprints;
  let added = 0;
  for (const fp of head) if (!base.has(fp)) added++;
  let removed = 0;
  for (const fp of base) if (!head.has(fp)) removed++;
  const parts: string[] = [];
  if (added > 0) parts.push(`${added} baseline entr${added === 1 ? 'y' : 'ies'} added`);
  if (removed > 0) parts.push(`${removed} baseline entr${removed === 1 ? 'y' : 'ies'} removed`);
  return parts.length === 0 ? '' : ` (${parts.join(', ')})`;
}

export interface TrustedControls {
  /** The ref every control input was taken from. */
  ref: string;
  /** The worktree root, which `trackedFiles` and the control paths are anchored to. */
  repoRoot: string;
  /** The base ref's config, validated, or `{}` when the base ref carries none. */
  config: VaultGuardConfig;
  /** Worktree-root-relative path the base config came from, or null. */
  configPath: string | null;
  /** The base ref's baseline fingerprints. Empty when the base carries none. */
  baseline: Set<string>;
  /** Worktree-root-relative path the base baseline came from, or null. */
  baselinePath: string | null;
  /** Set when the BASE baseline exists but does not parse. Reported, not fatal. */
  baselineParseError: string | null;
  /** True when the head proposes a different config, in content or in shape. */
  configChanged: boolean;
  /** True when the head proposes a different baseline. */
  baselineChanged: boolean;
  /** How the head changed the config file's type or mode, or null. */
  configShapeChange: ControlShapeChange | null;
  /** The same for the baseline file. */
  baselineShapeChange: ControlShapeChange | null;
  /** One line per control input the head proposes to change. */
  proposals: string[];
  /**
   * Every tracked file, absolute. The file set a pull-request run scans is
   * this intersected with the walk, so a `.gitignore` the head added cannot
   * remove a tracked file from it.
   */
  trackedFiles: string[];
}

/**
 * Every tracked path in the worktree, absolute.
 *
 * `-z` gives NUL-separated, unquoted, verbatim paths, so entries are used
 * exactly as git produced them; trimming would corrupt the legal if unusual
 * filename with leading or trailing whitespace into a path that does not
 * exist.
 */
export function listTrackedFiles(repoRoot: string): string[] {
  const out = runGit(repoRoot, ['ls-files', '-z']);
  if (out === null) return [];
  return out
    .split('\0')
    .filter(Boolean)
    .map(rel => path.resolve(repoRoot, rel));
}

/**
 * Every control input for one pull-request run, taken from the base ref.
 *
 * Throws TrustBaseError when the ref will not resolve or names the tree being
 * scanned, and ConfigError when the BASE config will not parse or validate.
 * Both are could-not-run: exit 2, nothing scanned. A base config that does not
 * validate cannot be waved through by falling back to the defaults, because
 * the defaults may be looser than what the project committed, and a gate that
 * silently loosens itself when a file is malformed is a gate anyone can
 * loosen.
 */
export function loadTrustedControls(startDir: string, ref: string): TrustedControls {
  const repoRoot = repoRootOf(startDir, ref);
  assertTrustBaseResolvable(repoRoot, ref);

  const searchDirs = searchDirsRelativeToRoot(startDir, repoRoot);

  const baseConfig = findControlFileAtRef(repoRoot, ref, searchDirs, CONFIG_FILENAMES);
  const headConfig = findControlFileAtRef(repoRoot, 'HEAD', searchDirs, CONFIG_FILENAMES);
  const baseBaseline = findControlFileAtRef(repoRoot, ref, searchDirs, [BASELINE_FILENAME]);
  const headBaseline = findControlFileAtRef(repoRoot, 'HEAD', searchDirs, [BASELINE_FILENAME]);

  assertBaseSideIsRegularFile(ref, 'config', baseConfig);
  assertBaseSideIsRegularFile(ref, 'baseline', baseBaseline);

  const config =
    baseConfig === null ? {} : parseConfigText(baseConfig.text, `${ref}:${baseConfig.path}`);

  const baselineRead =
    baseBaseline === null ? { fingerprints: new Set<string>() } : parseBaselineText(baseBaseline.text);

  const configShapeChange = shapeChange(baseConfig, headConfig);
  const baselineShapeChange = shapeChange(baseBaseline, headBaseline);

  // Content OR shape OR the path it was found at. A symlink whose target holds
  // the base config's exact bytes has identical content by every measure a
  // text comparison can make, and a config the head added in a subdirectory
  // NEARER the scan root than the base's is a different file entirely even
  // when the bytes match.
  const configChanged =
    documentsDiffer(baseConfig?.text ?? null, headConfig?.text ?? null) ||
    configShapeChange !== null ||
    (baseConfig?.path ?? null) !== (headConfig?.path ?? null);
  const baselineChanged =
    documentsDiffer(baseBaseline?.text ?? null, headBaseline?.text ?? null) ||
    baselineShapeChange !== null ||
    (baseBaseline?.path ?? null) !== (headBaseline?.path ?? null);

  const proposals: string[] = [];
  if (configChanged) {
    proposals.push(
      baseConfig === null && headConfig !== null
        ? CONFIG_ADDED_LINE
        : CONFIG_PROPOSAL_LINE +
            summariseConfigChange(baseConfig?.text ?? null, headConfig?.text ?? null),
    );
  }
  if (configShapeChange !== null) proposals.push(shapeProposal('config', configShapeChange));
  if (baselineChanged) {
    proposals.push(
      baseBaseline === null && headBaseline !== null
        ? BASELINE_ADDED_LINE
        : BASELINE_PROPOSAL_LINE +
            summariseBaselineChange(baseBaseline?.text ?? null, headBaseline?.text ?? null),
    );
  }
  if (baselineShapeChange !== null) proposals.push(shapeProposal('baseline', baselineShapeChange));

  return {
    ref,
    repoRoot,
    config,
    configPath: baseConfig?.path ?? null,
    baseline: baselineRead.fingerprints,
    baselinePath: baseBaseline?.path ?? null,
    baselineParseError: baselineRead.parseError ?? null,
    configChanged,
    baselineChanged,
    configShapeChange,
    baselineShapeChange,
    proposals,
    trackedFiles: listTrackedFiles(repoRoot),
  };
}

/**
 * A control input at the BASE ref that is not a regular file is could-not-run.
 *
 * The head side of that is a proposal, reported and ignored, because the head
 * is what is under judgment. The base side is different: it is the state this
 * run's decisions are supposed to rest on, and a link or a directory there
 * means the run has no approved control input to rest on at all. Reading the
 * link target as if it were the file would let a base-side link decide the
 * run from outside the tree.
 */
function assertBaseSideIsRegularFile(
  ref: string,
  input: string,
  file: ControlFile | null,
): void {
  if (file === null || isRegularFileMode(file.mode)) return;
  throw new TrustBaseError(
    `vault-guard: cannot read control inputs from base ref "${ref}": ${file.path} ` +
      `is not a regular file there (git mode ${file.mode}), so the ${input} this ` +
      'run would rest on is a link or a directory rather than a document. ' +
      'Nothing was scanned.',
  );
}

/** Re-exported so a caller can narrow a thrown control-input failure. */
export { ConfigError };
