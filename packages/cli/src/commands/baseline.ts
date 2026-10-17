import {
  SecretScanner,
  loadConfig,
  ConfigError,
  GitError,
  DiagnosticBus,
  BASELINE_FILENAME,
  parseBaselineText,
  fileDigest,
  resolveFailOn,
  meetsFailThreshold,
  fingerprintForMatch,
  contentFingerprintForMatch,
  rootPositionalFingerprint,
  findGitEntryRoot,
  getGitWorkTreeRoot,
  newPlainFileSetInfo,
  copyKey,
  cleanGitEnv,
  dropHeaderOnlyTwins,
  readRegularFileNoFollow,
  refusalWhat,
  writeFileAtomically,
  writeTargetKind,
  type AtomicWriteHooks,
  type NoFollowRead,
  FAIL_ON_VALUES,
  type BaselineEntry,
  type SecretMatch,
} from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import fs from 'fs';
import path from 'path';

import {
  scanFilesAsync,
  newContentReport,
  type RunSkipCounts,
  type UnreadableFile,
} from '../utils/scan-utils';

/**
 * `vault-guard baseline [path] [--write] [--include-critical]`.
 *
 * The only command that writes `.vault-guard.baseline.json`. `scan`, `check`,
 * `init`, the hook and the Action never do. Without `--write` it is a dry run
 * that prints what would be accepted.
 *
 * It runs the same plain scan as `scan [path]` (the git file set, the working
 * tree config, the effective `fail_on`) and accepts every finding that would
 * block, in tracked files only. Critical findings are refused unless
 * `--include-critical` is passed; the rest is still written and the command
 * exits 1. An incomplete scan writes nothing and exits 2.
 *
 * Inside git it writes at the repository root and refuses to write from any
 * other cwd: the positional list a 1.9.x runner reads is anchored at the cwd,
 * and a root-anchored run only finds a baseline at the root. Outside git it
 * writes in the cwd.
 */
export interface BaselineOptions {
  write: boolean;
  includeCritical: boolean;
  /** Refused: pull-request mode never takes a baseline from the head. */
  trustBase?: string;
  /** Refused: the baseline describes the tree, not the index. */
  staged?: boolean;
}

const COULD_NOT_RUN = 2;

const SEVERITY_RANK: Record<SecretMatch['severity'], number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** The comment stored in every written file, for the reviewer reading it. */
export const BASELINE_FILE_COMMENT =
  'Written by vault-guard baseline --write; review changes to this file like code. ' +
  'vault-guard 1.10 and later match on "entries" only; "fingerprints" is the positional ' +
  'list older versions read. An entry with "file_digest" (a rule that matches a fixed ' +
  'marker, such as a private key header) also requires the SHA-256 of the file raw bytes ' +
  'to be unchanged, so any byte change, including LF versus CRLF line endings, makes it ' +
  'stop matching.';

/** The refusal `baseline --write` prints for a link or non-regular file at its output path. */
function writerRefusal(outPath: string, what: 'symlink' | 'not-a-file'): string {
  return (
    `baseline --write refuses ${outPath}: it ${refusalWhat(what)}. baseline --write never writes ` +
    'through a link. Remove the link (git rm it) and run again. Nothing was written.'
  );
}

/**
 * Write the baseline by temporary file and rename, so a link at the output
 * path is replaced and never written through (design 2026-10-12, 4.3).
 * `hooks.beforeRename` is a test seam, absent in production.
 */
export function writeBaselineAtomically(outPath: string, text: string, hooks?: AtomicWriteHooks): void {
  writeFileAtomically(outPath, text, 0o644, hooks);
}

function canonical(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

function posixRel(root: string, file: string): string {
  const rel = path.relative(canonical(root), canonical(file));
  return rel.split(path.sep).join('/');
}

interface Accepted {
  file: string;
  match: SecretMatch;
}

export async function baselineCommand(target: string, options: BaselineOptions): Promise<number> {
  if (options.trustBase !== undefined) {
    console.error(
      chalk.red('❌ baseline does not take --trust-base:'),
      chalk.white(
        'a pull request cannot accept its own findings. Run vault-guard baseline on the ' +
          'default branch and land the file through review. Nothing was written.',
      ),
    );
    return COULD_NOT_RUN;
  }
  if (options.staged) {
    console.error(
      chalk.red('❌ baseline does not take --staged:'),
      chalk.white('the baseline describes the committed tree, not the index. Nothing was written.'),
    );
    return COULD_NOT_RUN;
  }

  const cwd = process.cwd();
  // Inside or outside git is decided from the TARGET as well as the cwd: a
  // target inside a repository is judged against that repository's root, and
  // the keys and the file must belong to it, wherever the command was run from.
  const targetAbs = path.resolve(cwd, target);
  const targetDir = (() => {
    try {
      return fs.statSync(targetAbs).isDirectory() ? targetAbs : path.dirname(targetAbs);
    } catch {
      return cwd;
    }
  })();
  const cwdInGit = findGitEntryRoot(cwd) !== null;
  const targetInGit = findGitEntryRoot(targetDir) !== null;
  const inGit = cwdInGit || targetInGit;
  let root: string;
  try {
    // A clean git environment, as for every plain-scan git call (design
    // 2026-10-12, section 6).
    root = targetInGit
      ? getGitWorkTreeRoot(targetDir, cleanGitEnv())
      : cwdInGit
        ? getGitWorkTreeRoot(cwd, cleanGitEnv())
        : canonical(cwd);
  } catch (e) {
    if (e instanceof GitError) {
      console.error(chalk.red('❌ Git error:'), chalk.white(e.message));
      return COULD_NOT_RUN;
    }
    throw e;
  }
  if (cwdInGit && !targetInGit) {
    console.error(
      chalk.red('❌ baseline target is outside the repository:'),
      chalk.white(
        `${target} is not inside the git repository at ${root}, so nothing it holds could be ` +
          'committed there. Nothing was written.',
      ),
    );
    return COULD_NOT_RUN;
  }
  if (!inGit) {
    console.log(
      chalk.yellow(
        `not a git repository: nothing is tracked here, so every scanned file counts, and the ` +
          `baseline is ${options.write ? 'written' : 'to be written'} in ${canonical(cwd)}.`,
      ),
    );
  }
  if (options.write && inGit && canonical(cwd) !== root) {
    console.error(
      chalk.red('❌ baseline --write runs from the repository root only:'),
      chalk.white(
        `run it from ${root}. A baseline written here would be keyed and placed relative ` +
          'to this directory, and a run from the root would never read it. To accept only ' +
          `part of the tree, pass that path from the root instead. Nothing was written.`,
      ),
    );
    return COULD_NOT_RUN;
  }

  // The output path is checked before anything is scanned: a link (a dangling
  // one included) or anything but a regular file is refused, and nothing is
  // written (design 2026-10-12, 4.3).
  const outPath = path.join(root, BASELINE_FILENAME);
  let outKind: ReturnType<typeof writeTargetKind>;
  try {
    outKind = writeTargetKind(outPath);
  } catch (e) {
    console.error(chalk.red('❌'), chalk.white(`baseline --write cannot examine ${outPath}: ${String(e)}. Nothing was written.`));
    return COULD_NOT_RUN;
  }
  if (outKind === 'symlink' || outKind === 'not-a-file') {
    console.error(chalk.red('❌'), chalk.white(writerRefusal(outPath, outKind)));
    return COULD_NOT_RUN;
  }

  let config;
  try {
    config = loadConfig(cwd);
  } catch (e) {
    if (e instanceof ConfigError) {
      console.error(chalk.red('❌ Config error:'), chalk.white(e.message));
      return COULD_NOT_RUN;
    }
    throw e;
  }
  const failOnResolved = resolveFailOn(undefined, config.fail_on);
  if (!failOnResolved.ok) {
    console.error(
      chalk.red('❌ Invalid fail-on value:'),
      chalk.white(`${failOnResolved.invalid} (expected one of: ${FAIL_ON_VALUES.join(' | ')})`),
    );
    return COULD_NOT_RUN;
  }
  const failOn = failOnResolved.threshold;
  const scanner = new SecretScanner(config);
  const configIgnorePatterns = [...(config.ignore?.paths ?? []), ...(config.ignore?.patterns ?? [])];

  const plainFileSet = newPlainFileSetInfo();
  const unreadable: UnreadableFile[] = [];
  const stats = { filesScanned: 0, bytesScanned: 0 };
  const skips: RunSkipCounts = { typeFiltered: 0, configIgnored: 0, binary: 0 };
  const contentReport = newContentReport();
  let results;
  try {
    results = dropHeaderOnlyTwins(
      await scanFilesAsync([target], scanner, {
        verbose: false,
        skipBinary: true,
        bus: new DiagnosticBus(),
        stats,
        unreadable,
        skips,
        configIgnorePatterns,
        inlineSuppressed: { count: 0, criticalVendorAnchored: 0 },
        plainFileSet,
        content: contentReport,
      }),
    );
  } catch (e) {
    if (e instanceof GitError) {
      console.error(chalk.red('❌ Git error:'), chalk.white(e.message));
      console.error(chalk.gray('   Nothing was written.'));
      return COULD_NOT_RUN;
    }
    throw e;
  }

  // Anything that would make `scan` exit 2 writes nothing: a baseline built
  // from a scan that did not look at everything would accept less than it says.
  if (unreadable.length > 0) {
    console.error(
      chalk.red.bold('❌ INCOMPLETE:'),
      chalk.white(`${unreadable.length} file(s) or target(s) could not be scanned. Nothing was written.`),
    );
    for (const u of unreadable) {
      console.error(`  ${chalk.cyan(u.file)}`);
      console.error(`    ${chalk.gray(u.reason)}`);
    }
    return COULD_NOT_RUN;
  }
  if (stats.filesScanned === 0) {
    console.error(
      chalk.red('❌ Cannot establish a result:'),
      chalk.white('the target resolved to no files, so there is nothing to accept. Nothing was written.'),
    );
    return COULD_NOT_RUN;
  }

  // Split what the scan found: accepted, refused as critical, or untracked.
  const tracked = (file: string): boolean =>
    plainFileSet.fileSet !== 'git' || plainFileSet.trackedFiles.has(file);
  const accepted: Accepted[] = [];
  const refused: Accepted[] = [];
  const untrackedWithFindings = new Set<string>();
  const worktreeEditsWithFindings = new Set<string>();
  for (const r of results) {
    for (const m of r.matches) {
      if (!meetsFailThreshold(m.severity, failOn)) continue;
      if (!tracked(r.file)) {
        // Never written: no name and no digest of a file the author never committed.
        untrackedWithFindings.add(r.file);
        continue;
      }
      if (m.source === 'worktree') {
        // Found only in an uncommitted edit: the baseline accepts what the
        // index holds, never a change nobody has staged.
        worktreeEditsWithFindings.add(r.file);
        continue;
      }
      // A demoted match is judged by its severity before demotion, so a
      // critical key lowered by the content demotion is refused exactly as it
      // was in 1.11.0 (design 2026-10-17 data files, section 4.5).
      if ((m.demotion?.from ?? m.severity) === 'critical' && !options.includeCritical) {
        refused.push({ file: r.file, match: m });
        continue;
      }
      accepted.push({ file: r.file, match: m });
    }
  }

  // Build the entries. A value-bearing finding gets its content key; a
  // header-only one gets the root-relative positional key plus a digest of the
  // whole file, and is left OUT of the positional list so a 1.9.x runner, which
  // reads only that list, keeps showing it.
  const entries = new Map<string, BaselineEntry & { positional: string[] }>();
  const fingerprints = new Set<string>();
  for (const { file, match: m } of accepted) {
    const valueBearing = scanner.isValueBearing(m.type);
    const positional = fingerprintForMatch(cwd, file, m);
    let key: string | undefined;
    let digest: string | undefined;
    if (valueBearing) {
      key = contentFingerprintForMatch(root, file, m);
      // A demoted match stays OUT of the positional list, which has no
      // severity rule: a 1.9.x reader would otherwise suppress the same match
      // at its full severity. Its entries record is its only key (4.5).
      if (m.demotion === undefined) fingerprints.add(positional);
    } else {
      key = rootPositionalFingerprint(root, file, m);
      // Over the bytes the finding came from, kept by the scan (the index
      // blob inside git), never a fresh read of the disk.
      const kept = contentReport.kept.get(copyKey(file, m.source, m.stage));
      digest = kept !== undefined ? (fileDigest(file, () => kept) ?? undefined) : undefined;
    }
    if (key === undefined || (!valueBearing && digest === undefined)) continue;
    const id = `${key}\0${digest ?? ''}`;
    const existing = entries.get(id);
    if (existing) {
      existing.count++;
      existing.positional.push(positional);
      if (SEVERITY_RANK[m.severity] > SEVERITY_RANK[existing.severity ?? 'low']) existing.severity = m.severity;
      if (m.line < (existing.line ?? m.line)) existing.line = m.line;
      continue;
    }
    entries.set(id, {
      fingerprint: key,
      rule: m.type,
      file: posixRel(root, file),
      line: m.line,
      severity: m.severity,
      count: 1,
      ...(digest !== undefined ? { file_digest: digest } : {}),
      positional: [positional],
    });
  }
  const entryList = [...entries.values()].sort(
    (a, b) => (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0),
  );

  // Compare with the file being replaced, read without following a link. A
  // refusal here means the path changed after the check above: the same exit 2.
  let previous: ReturnType<typeof parseBaselineText> | null = null;
  let prev: NoFollowRead;
  try {
    prev = readRegularFileNoFollow(outPath);
  } catch (e) {
    console.error(chalk.red('❌'), chalk.white(`baseline --write cannot read ${outPath}: ${String(e)}. Nothing was written.`));
    return COULD_NOT_RUN;
  }
  if (prev.kind === 'refused') {
    console.error(chalk.red('❌'), chalk.white(writerRefusal(outPath, prev.what)));
    return COULD_NOT_RUN;
  }
  if (prev.kind === 'file') previous = parseBaselineText(prev.text);
  // A path argument scopes the write. Entries outside the scanned path were
  // not re-examined, so they are kept untouched rather than reported as "no
  // longer found"; the positional list cannot be attributed to paths, so on a
  // scoped write every previous positional key is kept too (only 1.9.x reads
  // it). A write of the whole tree regenerates both lists.
  const scope = posixRel(root, targetAbs);
  const scoped = scope !== '' && scope !== '.';
  const inScope = (file: string | undefined): boolean =>
    !scoped || file === undefined || file === scope || file.startsWith(`${scope}/`);
  const outsideScope: BaselineEntry[] =
    scoped && previous && previous.entries !== null
      ? previous.entries.filter(e => !inScope(e.file))
      : [];
  if (scoped && previous) for (const p of previous.fingerprints) fingerprints.add(p);

  let kept = 0;
  let added = 0;
  let dropped = 0;
  let converted: number | null = null;
  if (previous && previous.entries !== null) {
    const before = new Set(previous.entries.filter(e => inScope(e.file)).map(e => e.fingerprint));
    const after = new Set(entryList.map(e => e.fingerprint));
    for (const k of after) {
      if (before.has(k)) kept++;
      else added++;
    }
    for (const k of before) if (!after.has(k)) dropped++;
  } else if (previous && previous.fingerprints.size > 0) {
    converted = 0;
    const seen = new Set<string>();
    for (const e of entryList) {
      if (e.positional.some(p => previous?.fingerprints.has(p))) converted++;
      else added++;
      for (const p of e.positional) seen.add(p);
    }
    if (!scoped) for (const p of previous.fingerprints) if (!seen.has(p)) dropped++;
  } else {
    added = entryList.length;
  }

  // Report.
  for (const e of entryList) {
    const times = e.count > 1 ? ` (x${e.count})` : '';
    console.log(`  ${chalk.cyan(`${e.file}:${e.line}`)}  ${e.rule}  ${e.severity}${times}`);
  }
  for (const { file, match: m } of refused) {
    console.log(
      chalk.yellow(
        `  not accepted: critical, rotate and remove instead: ${posixRel(root, file)}:${m.line} ${m.type}`,
      ),
    );
  }
  if (untrackedWithFindings.size > 0) {
    console.log(
      chalk.yellow(
        `untracked files with findings: ${untrackedWithFindings.size} (not accepted; commit or remove them)`,
      ),
    );
  }
  if (worktreeEditsWithFindings.size > 0) {
    console.log(
      chalk.yellow(
        `uncommitted working-tree edits with findings: ${worktreeEditsWithFindings.size} ` +
          '(not accepted; stage or revert them)',
      ),
    );
  }
  console.log(
    `kept ${kept}, added ${added}, dropped ${dropped} (no longer found)` +
      (converted !== null ? `, converted ${converted}` : ''),
  );
  if (scoped && previous) {
    console.log(`${outsideScope.length} entries outside the scanned path kept`);
  }

  if (!options.write) {
    console.log(chalk.gray(`Dry run: nothing written. Run with --write to write ${outPath}.`));
    return 0;
  }

  const doc = {
    version: 1 as const,
    comment: BASELINE_FILE_COMMENT,
    fingerprints: [...fingerprints].sort(),
    entries: [
      ...entryList.map(e => {
        const out: Partial<typeof e> = { ...e };
        delete out.positional;
        return out;
      }),
      ...outsideScope,
    ].sort((a, b) => (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0)),
  };
  try {
    writeBaselineAtomically(outPath, `${JSON.stringify(doc, null, 2)}\n`);
  } catch (e) {
    console.error(chalk.red('❌'), chalk.white(`baseline --write could not write ${outPath}: ${String(e)}. Nothing was written.`));
    return COULD_NOT_RUN;
  }
  console.log(chalk.green(`Wrote ${outPath}. Commit it through review.`));
  if (refused.length > 0) {
    console.log(
      chalk.yellow(
        `${refused.length} critical finding(s) not accepted. Rotate and remove them, or pass --include-critical.`,
      ),
    );
    return 1;
  }
  return 0;
}
