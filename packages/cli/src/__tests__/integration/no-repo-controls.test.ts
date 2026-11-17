import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';

import { scanCommand } from '../../commands/scan';
import { newContentReport, newRunSkipCounts, resolveScanRoot, scanHeadBlobsAsync } from '../../utils/scan-utils';
import { BlobBatchReader, GitError, SecretScanner } from '@vaultcompass/vault-guard-core';
import { AWS_KEY, capture, git, gitStub, parse, runCli, stubCalls, subcommand, tmpDir, write } from './git-fixture';

/**
 * `scan --no-repo-controls` (design 2026-10-28, proposal and outside-policy
 * runs, section 6 and the PR 2 test list in 8.1): control inputs come from
 * nowhere, the tree is judged as at HEAD from blobs only, and a local git
 * config off the allowlist refuses the run before any other git call.
 *
 * Each lever has its own fixture, and each asserts both halves: the finding IS
 * reported, and the control file IS listed as present and not honoured. Where
 * the lever works on a plain run, the plain run is asserted too, so the
 * fixture is known to be a real mute and not a no-op.
 */

/**
 * The git-config check, stubbable per test. Mocked by file path, so the call
 * inside core's no-repo-controls.ts is the one replaced.
 */
const mockConfigCheck = { stubbed: false };
jest.mock('../../../../core/src/utils/local-git-config', () => {
  const actual = jest.requireActual('../../../../core/src/utils/local-git-config');
  return {
    ...actual,
    checkLocalGitConfig: (cwd: string, env: NodeJS.ProcessEnv, git?: string) =>
      mockConfigCheck.stubbed ? { ok: true, keys: [] } : actual.checkLocalGitConfig(cwd, env, git),
  };
});

/** Filters, fsmonitor hooks and file modes; the Windows CI job is not a required check. */
const itPosix = process.platform === 'win32' ? it.skip : it;

const IDENTITY = {
  GIT_AUTHOR_NAME: 'Test',
  GIT_AUTHOR_EMAIL: 'test@example.invalid',
  GIT_COMMITTER_NAME: 'Test',
  GIT_COMMITTER_EMAIL: 'test@example.invalid',
};

/**
 * A repository whose local config holds only what `git init` writes: the
 * shared fixture's initRepo sets user.* and commit.gpgsign locally, which this
 * mode rightly refuses. Identity and signing go on the command line instead.
 */
function initClean(dir: string): void {
  git(dir, ['init', '-q', '-b', 'main']);
}

function commitClean(dir: string, message: string): void {
  git(dir, ['add', '-A', '-f']);
  git(dir, ['-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', 'commit', '-q', '-m', message], {
    ...process.env,
    ...IDENTITY,
  });
}

/** A committed repository holding `secret.txt` with an AWS key, plus `extra` files. */
function repoWithSecret(extra: Record<string, string> = {}, secretLine = `aws = "${AWS_KEY}"\n`): string {
  const dir = tmpDir('vg-norc-');
  initClean(dir);
  write(dir, 'secret.txt', secretLine);
  for (const [rel, text] of Object.entries(extra)) write(dir, rel, text);
  commitClean(dir, 'fixture');
  return dir;
}

interface Doc {
  run: Record<string, unknown>;
  results: Array<{ file: string; matches: Array<{ type: string; source?: string; inline_directive_not_honoured?: boolean }> }>;
  repoControls?: { honoured: boolean; present: string[] };
}

const originalCwd = process.cwd();
const originalPath = process.env.PATH;

async function scanIn(
  dir: string,
  opts: {
    format?: 'text' | 'json' | 'sarif';
    staged?: boolean;
    trustBase?: string;
    noRepoControls?: boolean;
    target?: string;
    failOn?: string;
  } = {},
): Promise<{ code: number; log: string; err: string; stdout: string }> {
  process.chdir(dir);
  try {
    return await capture(() =>
      scanCommand(
        opts.target ?? '.',
        opts.format ?? 'json',
        opts.staged ?? false,
        opts.failOn,
        opts.trustBase,
        false,
        opts.noRepoControls ?? true,
      ),
    );
  } finally {
    process.chdir(originalCwd);
  }
}

function files(doc: Doc): string[] {
  return doc.results.flatMap(r => r.matches.map(m => `${r.file}|${m.type}`)).sort();
}

afterEach(() => {
  mockConfigCheck.stubbed = false;
  process.env.PATH = originalPath;
  process.chdir(originalCwd);
});

describe('--no-repo-controls: no control file is honoured, every one present is listed', () => {
  it('a config that ignores everything: the finding is reported and the config is listed', async () => {
    const dir = repoWithSecret({
      '.vault-guard.json': JSON.stringify({ ignore: { paths: ['**'] }, severity_overrides: { 'aws-access': 'off' } }),
    });
    const plain = await scanIn(dir, { noRepoControls: false });
    expect(plain.code).not.toBe(1);

    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.repoControls).toEqual({ honoured: false, present: ['.vault-guard.json'] });
  });

  it('fail_on lowered to none: the finding still blocks and the config is listed', async () => {
    const dir = repoWithSecret({ '.vault-guard.json': JSON.stringify({ fail_on: 'none' }) });
    expect((await scanIn(dir, { noRepoControls: false })).code).toBe(0);

    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.run.fail_on).toBe('medium');
    expect(doc.repoControls?.present).toEqual(['.vault-guard.json']);
  });

  it('a local overlay, at the root and nested: the finding is reported and both overlays are listed', async () => {
    const dir = repoWithSecret({
      '.vault-guard.local.json': JSON.stringify({ fail_on: 'none', ignore: { paths: ['secret.txt'] } }),
      'sub/.vault-guard.local.json': JSON.stringify({ fail_on: 'none' }),
    });
    expect((await scanIn(dir, { noRepoControls: false })).code).toBe(0);

    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.repoControls?.present).toEqual(['.vault-guard.local.json', 'sub/.vault-guard.local.json']);
  });

  it('a baseline listing the finding: the finding is reported and the baseline is listed', async () => {
    const dir = repoWithSecret();
    const w = runCli(['baseline', '--write', '--include-critical'], dir, { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null' });
    expect(w.code).toBe(0);
    commitClean(dir, 'accept the finding');
    expect((await scanIn(dir, { noRepoControls: false })).code).toBe(0);

    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.run.baseline_entries).toBe(0);
    expect(doc.repoControls?.present).toEqual(['.vault-guard.baseline.json']);
  });

  it('an inline ignore directive: the finding is reported and marked as not honoured', async () => {
    const dir = repoWithSecret({}, `aws = "${AWS_KEY}" // vault-guard: ignore-line\n`);
    const plain = await scanIn(dir, { noRepoControls: false });
    expect(plain.code).toBe(0);
    expect((parse(plain.stdout) as unknown as Doc).run.inline_suppressed).toBe(1);

    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.results[0].matches[0].inline_directive_not_honoured).toBe(true);
    expect(doc.run.inline_suppressed).toBe(0);
    expect(doc.repoControls).toEqual({ honoured: false, present: [] });

    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('(inline ignore directive not honoured)');
    expect(text.log).toContain('Inline ignore directives not honoured: 1');
  });

  // No "hidden by a normal run" control here, unlike the levers above: no
  // mode honours .gitignore for a TRACKED file (a plain scan inside git and
  // --trust-base both scan it), so this checks only that the file is listed
  // as present and the finding is still reported.
  it('a .gitignore naming a tracked file: listed as present, and the finding is still reported', async () => {
    const dir = repoWithSecret({ '.gitignore': 'secret.txt\n', 'sub/.gitignore': '*\n' });
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.repoControls?.present).toEqual(['.gitignore', 'sub/.gitignore']);
  });

  // The same: vault-guard has never honoured a linguist-vendored mark in any
  // mode, so there is no normal run that hides the finding to compare with.
  it('a .gitattributes vendored mark: listed as present, and the finding is still reported', async () => {
    const dir = repoWithSecret({ '.gitattributes': 'secret.txt linguist-vendored linguist-generated -diff\n' });
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.repoControls?.present).toEqual(['.gitattributes']);
  });

  it('the text report prints one line per present control file', async () => {
    const dir = repoWithSecret({
      '.vault-guard.json': '{}',
      '.gitignore': 'x\n',
      'deep/dir/.GitAttributes': 'x -text\n',
    });
    const r = await scanIn(dir, { format: 'text' });
    expect(r.code).toBe(1);
    const lines = r.log.split('\n').filter(l => l.startsWith('Present, not honoured: '));
    expect(lines).toEqual([
      'Present, not honoured: .gitignore',
      'Present, not honoured: .vault-guard.json',
      'Present, not honoured: deep/dir/.GitAttributes',
    ]);
    expect(r.log).toContain('Control inputs: none (--no-repo-controls)');
  });

  it('SARIF carries repoControls in the run properties and the mark on the result', async () => {
    const dir = repoWithSecret({ '.vault-guard.json': '{"fail_on":"none"}' }, `aws = "${AWS_KEY}" # vault-guard: ignore-line\n`);
    const r = await scanIn(dir, { format: 'sarif' });
    expect(r.code).toBe(1);
    const sarif = JSON.parse(r.stdout) as {
      runs: Array<{ properties: Record<string, unknown>; results: Array<{ properties?: Record<string, unknown> }> }>;
    };
    expect(sarif.runs[0].properties.repoControls).toEqual({ honoured: false, present: ['.vault-guard.json'] });
    expect(sarif.runs[0].properties.vault_guard_run).toBeDefined();
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].properties?.['vault-guard/inline_directive_not_honoured']).toBe(true);
  });

  it('a run without the flag carries no repoControls block, in JSON or SARIF', async () => {
    const dir = repoWithSecret({ '.vault-guard.json': '{}' });
    const json = await scanIn(dir, { noRepoControls: false });
    expect((parse(json.stdout) as unknown as Doc).repoControls).toBeUndefined();
    const sarif = await scanIn(dir, { noRepoControls: false, format: 'sarif' });
    expect(sarif.stdout).not.toContain('repoControls');
  });
});

describe('--no-repo-controls: the tree is judged as at HEAD, from blobs only', () => {
  it('a file edited on disk and not committed: the HEAD content is judged, in both directions', async () => {
    // Committed with a key, cleaned on disk: still reported, from the head blob.
    const dirty = repoWithSecret();
    write(dirty, 'secret.txt', 'nothing here\n');
    const r = await scanIn(dirty);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(doc.results.flatMap(x => x.matches.map(m => `${x.file}|${m.source}`))).toEqual(['secret.txt|head']);
    expect(doc.run.worktree_copies_scanned).toBe(0);

    // Committed clean, a key written on disk only: not this mode's tree.
    const clean = repoWithSecret({}, 'nothing here\n');
    write(clean, 'secret.txt', `aws = "${AWS_KEY}"\n`);
    write(clean, 'untracked.txt', `aws = "${AWS_KEY}"\n`);
    const c = await scanIn(clean);
    expect(c.code).toBe(0);
    expect((parse(c.stdout) as unknown as Doc).results).toEqual([]);

    // Deleted on disk: still judged from HEAD.
    const gone = repoWithSecret();
    fs.rmSync(path.join(gone, 'secret.txt'));
    expect((await scanIn(gone)).code).toBe(1);
  });

  itPosix('runs only config, rev-parse and cat-file, with the config read first', () => {
    const dir = repoWithSecret({ '.gitignore': 'secret.txt\n', '.gitattributes': 'secret.txt -text\n' });
    write(dir, 'secret.txt', 'edited on disk\n');
    const log = path.join(tmpDir('vg-norc-log-'), 'git.log');
    const bin = gitStub(path.dirname(log), log);
    const r = runCli(['scan', '--no-repo-controls', '--format', 'json', '.'], dir, {
      ...process.env,
      GIT_CONFIG_GLOBAL: '/dev/null',
      PATH: `${bin}${path.delimiter}${process.env.PATH ?? ''}`,
    });
    expect(r.code).toBe(1);
    const subs = stubCalls(log).map(c => subcommand(c.args));
    expect(subs[0]).toBe('config');
    expect(stubCalls(log)[0].args).toEqual(['config', '--local', '--list', '--name-only', '-z']);
    expect([...new Set(subs)].sort()).toEqual(['cat-file', 'config', 'rev-parse']);
  });

  itPosix(
    'filter driver, config check stubbed out: the clean filter never runs and the blob is judged',
    async () => {
      const { dir, marker } = filterFixture();
      mockConfigCheck.stubbed = true;
      const r = await scanIn(dir);
      expect(fs.existsSync(marker)).toBe(false);
      expect(r.code).toBe(1);
      expect(files(parse(r.stdout) as unknown as Doc)).toEqual(['secret.txt|aws-access']);
      expect((parse(r.stdout) as unknown as Doc).repoControls?.present).toEqual(['.gitattributes']);

      // The fixture is live: git status runs the filter on this very tree.
      git(dir, ['status', '--porcelain']);
      expect(fs.existsSync(marker)).toBe(true);
    },
  );

  itPosix('filter driver, config check live: exit 2 naming the key, before any marker', async () => {
    const { dir, marker } = filterFixture();
    const r = await scanIn(dir, { format: 'text' });
    expect(r.code).toBe(2);
    expect(r.err).toContain('filter.x.clean');
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
    expect(r.log).not.toContain('Scanning');
    expect(fs.existsSync(marker)).toBe(false);
  });
});

/**
 * A committed `.gitattributes` assigning `filter=x` to `secret.txt`, a local
 * `filter.x.clean` that writes a marker, and the file stat-dirty, which is
 * the state in which `git status` runs the clean filter (review B2).
 */
function filterFixture(): { dir: string; marker: string } {
  const dir = repoWithSecret({ '.gitattributes': 'secret.txt filter=x\n' });
  const marker = path.join(tmpDir('vg-norc-marker-'), 'clean-ran');
  git(dir, ['config', '--local', 'filter.x.clean', `touch '${marker}'; cat`]);
  const future = new Date(Date.now() + 120_000);
  fs.utimesSync(path.join(dir, 'secret.txt'), future, future);
  expect(fs.existsSync(marker)).toBe(false);
  return { dir, marker };
}

describe('--no-repo-controls: the local git config allowlist', () => {
  itPosix('core.fsmonitor in local config: exit 2 naming the key, and the hook never runs', async () => {
    const dir = repoWithSecret();
    const scratch = tmpDir('vg-norc-fsm-');
    const marker = path.join(scratch, 'fsmonitor-ran');
    const hook = path.join(scratch, 'fsmonitor.sh');
    fs.writeFileSync(hook, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`, { mode: 0o755 });
    git(dir, ['config', '--local', 'core.fsmonitor', hook]);

    const r = await scanIn(dir, { format: 'text' });
    expect(r.code).toBe(2);
    expect(r.err).toContain('core.fsmonitor');
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
    expect(fs.existsSync(marker)).toBe(false);

    // The fixture is live: the listing a plain scan runs fires the hook.
    git(dir, ['ls-files', '-co', '--exclude-standard']);
    expect(fs.existsSync(marker)).toBe(true);
  });

  it('a fresh clone of a repository with a remote passes the check', async () => {
    const origin = repoWithSecret();
    const parent = tmpDir('vg-norc-clone-');
    git(parent, ['clone', '-q', origin, 'c']);
    const r = await scanIn(path.join(parent, 'c'));
    expect(r.code).toBe(1);
  });

  it.each([
    ['include.path', 'other.cfg'],
    ['core.worktree', '/elsewhere'],
    ['remote.origin.promisor', 'true'],
    ['remote.origin.partialclonefilter', 'blob:none'],
    ['extensions.worktreeConfig', 'true'],
    ['user.name', 'Somebody'],
  ])('%s in local config: exit 2 naming the key', async (key, value) => {
    const dir = repoWithSecret();
    git(dir, ['config', '--local', key, value]);
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain(key.toLowerCase());
    expect(r.stdout).toBe('');
  });
});

describe('--no-repo-controls: refused combinations', () => {
  it('with --trust-base or --staged: a usage error, exit 2, before any git call', async () => {
    const dir = repoWithSecret();
    const log = path.join(tmpDir('vg-norc-log-'), 'git.log');
    const bin = gitStub(path.dirname(log), log);
    process.env.PATH = `${bin}${path.delimiter}${originalPath ?? ''}`;

    const tb = await scanIn(dir, { trustBase: 'HEAD' });
    expect(tb.code).toBe(2);
    expect(tb.err).toContain('--no-repo-controls cannot be combined with --trust-base');
    const st = await scanIn(dir, { staged: true });
    expect(st.code).toBe(2);
    expect(st.err).toContain('--no-repo-controls cannot be combined with --staged');
    expect(stubCalls(log)).toEqual([]);

    const cli = runCli(['scan', '--no-repo-controls', '--trust-base', 'main', '.'], dir);
    expect(cli.code).toBe(2);
    expect(cli.stderr).toContain('--no-repo-controls cannot be combined with --trust-base');
  });

  it('a repository with no commit: exit 2', async () => {
    const dir = tmpDir('vg-norc-empty-');
    initClean(dir);
    write(dir, 'secret.txt', `aws = "${AWS_KEY}"\n`);
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('HEAD does not resolve to a commit');
    expect(r.stdout).toBe('');
  });

  it('a target outside the repository: exit 2', async () => {
    const dir = repoWithSecret();
    const elsewhere = tmpDir('vg-norc-out-');
    process.chdir(dir);
    try {
      const r = await capture(() => scanCommand(elsewhere, 'json', false, undefined, undefined, false, true));
      expect(r.code).toBe(2);
      expect(r.err).toContain('outside');
    } finally {
      process.chdir(originalCwd);
    }
  });
});

function sha(dir: string, rev = 'HEAD'): string {
  return git(dir, ['rev-parse', rev]).trim();
}

/** A commit whose tree is exactly `entries` (mode, blob text, raw name), built with plumbing. */
function craftedTree(entries: Array<{ name: string; text: string }>): string {
  const dir = tmpDir('vg-norc-crafted-');
  initClean(dir);
  const lines: Buffer[] = [];
  for (const e of entries) {
    const oid = execFileSync('git', ['hash-object', '-w', '--stdin'], { cwd: dir, input: e.text }).toString().trim();
    lines.push(Buffer.concat([Buffer.from(`100644 blob ${oid}\t`), Buffer.from(e.name, 'latin1'), Buffer.from('\n')]));
  }
  const tree = execFileSync('git', ['mktree'], { cwd: dir, input: Buffer.concat(lines) }).toString().trim();
  const commit = execFileSync('git', ['commit-tree', tree, '-m', 'crafted'], {
    cwd: dir,
    env: { ...process.env, ...IDENTITY },
  })
    .toString()
    .trim();
  git(dir, ['update-ref', 'refs/heads/main', commit]);
  return dir;
}

describe('--no-repo-controls: what the report says about the tree', () => {
  it('names the scanned commit in text, JSON and SARIF', async () => {
    const dir = repoWithSecret();
    const head = sha(dir);
    const json = await scanIn(dir);
    expect((JSON.parse(json.stdout) as { scannedCommit?: string }).scannedCommit).toBe(head);
    const sarif = JSON.parse((await scanIn(dir, { format: 'sarif' })).stdout) as {
      runs: Array<{ properties: Record<string, unknown> }>;
    };
    expect(sarif.runs[0].properties.scannedCommit).toBe(head);
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain(`Scanned commit: ${head} (untracked and uncommitted files are not judged)`);
  });

  it('lists every submodule as not scanned, in text, JSON and SARIF, without exiting 2', async () => {
    const dir = repoWithSecret();
    const pinned = sha(dir);
    git(dir, ['update-index', '--add', '--cacheinfo', `160000,${pinned},vendor-lib`]);
    git(dir, ['update-index', '--add', '--cacheinfo', `160000,${pinned},deps/inner`]);
    git(dir, ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'submodules'], { ...process.env, ...IDENTITY });

    const json = await scanIn(dir);
    expect(json.code).toBe(1);
    expect((JSON.parse(json.stdout) as { notScanned?: unknown }).notScanned).toEqual({
      submodules: ['deps/inner', 'vendor-lib'],
      builtInSkips: [],
      builtInSkipsOmitted: 0,
    });
    const sarif = JSON.parse((await scanIn(dir, { format: 'sarif' })).stdout) as {
      runs: Array<{ properties: Record<string, unknown> }>;
    };
    expect(sarif.runs[0].properties.notScanned).toEqual({
      submodules: ['deps/inner', 'vendor-lib'],
      builtInSkips: [],
      builtInSkipsOmitted: 0,
    });
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log.split('\n').filter(l => l.startsWith('Not scanned, submodule: '))).toEqual([
      'Not scanned, submodule: deps/inner',
      'Not scanned, submodule: vendor-lib',
    ]);
  });
});

describe('--no-repo-controls: a tree whose entries cannot be told apart is refused', () => {
  it('two names that are not valid UTF-8 and decode alike: exit 2, nothing scanned', async () => {
    const dir = craftedTree([
      { name: 'k\xfe.txt', text: `aws = "${AWS_KEY}"\n` },
      { name: 'k\xff.txt', text: 'clean\n' },
    ]);
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('cannot be told apart');
    expect(r.stdout).toBe('');
  });

  it('one name listed twice in a crafted tree: exit 2, nothing scanned', async () => {
    const dir = craftedTree([
      { name: 'a.txt', text: `aws = "${AWS_KEY}"\n` },
      { name: 'a.txt', text: 'clean\n' },
    ]);
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('cannot be told apart');
  });
});

describe('--no-repo-controls: a file with no HEAD blob is never read from disk', () => {
  it('scanHeadBlobsAsync rejects a file the HEAD listing did not name, with a key on disk', async () => {
    const dir = repoWithSecret({}, 'clean\n');
    const stray = path.join(dir, 'stray.txt');
    fs.writeFileSync(stray, `aws = "${AWS_KEY}"\n`);
    const blobs = new Map<string, string>();
    const p = scanHeadBlobsAsync([stray], blobs, dir, new SecretScanner({}), {});
    await expect(p).rejects.toBeInstanceOf(GitError);
    await expect(p).rejects.toMatchObject({ command: 'git cat-file --batch' });
  });
});

describe('--no-repo-controls: the repository must use its own git directory and objects', () => {
  it('.git is a gitdir pointer file: exit 2, clone fresh', async () => {
    const dir = repoWithSecret();
    const elsewhere = path.join(tmpDir('vg-norc-gitdir-'), 'real.git');
    fs.renameSync(path.join(dir, '.git'), elsewhere);
    fs.writeFileSync(path.join(dir, '.git'), `gitdir: ${elsewhere}\n`);
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('.git at the repository root is a file or a link');
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
    expect(r.stdout).toBe('');
  });

  it('objects/info/alternates (a --shared clone): exit 2, clone fresh', async () => {
    const origin = repoWithSecret();
    const parent = tmpDir('vg-norc-shared-');
    git(parent, ['clone', '-q', '--shared', origin, 'c']);
    const r = await scanIn(path.join(parent, 'c'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('.git/objects/info/alternates exists');
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
  });

  it('objects/info/http-alternates: exit 2, clone fresh', async () => {
    const dir = repoWithSecret();
    fs.writeFileSync(path.join(dir, '.git', 'objects', 'info', 'http-alternates'), 'https://example.invalid/objects\n');
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('.git/objects/info/http-alternates exists');
  });
});

/**
 * A victim repository whose git directory reaches another repository's
 * objects, HEAD naming that repository's commit, which holds a key. Without
 * the refusal the run judged the other tree and reported other-secret.txt.
 */
function borrowedStore(how: 'commondir' | 'objects-link' | 'pack-link' | 'loose-link'): string {
  const other = repoWithSecret({}, 'clean\n');
  write(other, 'other-secret.txt', `aws = "${AWS_KEY}"\n`);
  commitClean(other, 'other');
  const otherHead = sha(other);
  const victim = repoWithSecret({}, 'clean\n');
  const objects = path.join(victim, '.git', 'objects');
  if (how === 'commondir') {
    fs.rmSync(objects, { recursive: true });
    fs.mkdirSync(objects);
    fs.writeFileSync(path.join(victim, '.git', 'commondir'), `${path.join(other, '.git')}\n`);
    fs.writeFileSync(path.join(victim, '.git', 'HEAD'), `${otherHead}\n`);
  } else if (how === 'objects-link') {
    fs.rmSync(objects, { recursive: true });
    fs.symlinkSync(path.join(other, '.git', 'objects'), objects);
    fs.writeFileSync(path.join(victim, '.git', 'HEAD'), `${otherHead}\n`);
  } else if (how === 'pack-link') {
    git(other, ['repack', '-a', '-d', '-q']);
    fs.rmSync(path.join(objects, 'pack'), { recursive: true, force: true });
    fs.symlinkSync(path.join(other, '.git', 'objects', 'pack'), path.join(objects, 'pack'));
  } else {
    // One loose object directory replaced by a link to the other store's.
    const loose = fs.readdirSync(path.join(other, '.git', 'objects')).find(n => /^[0-9a-f]{2}$/.test(n));
    if (loose === undefined) throw new Error('fixture: no loose object directory');
    fs.rmSync(path.join(objects, loose), { recursive: true, force: true });
    fs.symlinkSync(path.join(other, '.git', 'objects', loose), path.join(objects, loose));
  }
  return victim;
}

describe('--no-repo-controls: a git directory that borrows another store is refused', () => {
  itPosix('a .git/commondir pointing at another repository: exit 2, the other tree is not judged', async () => {
    const r = await scanIn(borrowedStore('commondir'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('.git/commondir exists');
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
    expect(r.stdout).toBe('');
  });

  itPosix('.git/objects a link to another repository\'s objects: exit 2, the other tree is not judged', async () => {
    const r = await scanIn(borrowedStore('objects-link'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('.git/objects is not a real directory');
    expect(r.stdout).toBe('');
  });

  itPosix('.git/objects/pack a link to another store: exit 2', async () => {
    const r = await scanIn(borrowedStore('pack-link'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('.git/objects/pack is a link');
  });

  itPosix('a loose object directory linked to another store: exit 2', async () => {
    const r = await scanIn(borrowedStore('loose-link'));
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/\.git\/objects\/[0-9a-f]{2} is a link/);
  });

  itPosix('a symlinked HEAD, refs/ or packed-refs naming another repository\'s commit: exit 2, the other tree is not judged', async () => {
    // Refs are not checked for links: a ref can only name a commit this
    // repository's own object store holds, and the other repository's commit
    // is not in it, so HEAD fails to resolve.
    for (const how of ['head', 'refs', 'packed'] as const) {
      const other = repoWithSecret({}, 'clean\n');
      write(other, 'other-secret.txt', `aws = "${AWS_KEY}"\n`);
      commitClean(other, 'other');
      git(other, ['pack-refs', '--all']);
      const victim = repoWithSecret({}, 'clean\n');
      const gd = path.join(victim, '.git');
      if (how === 'head') {
        fs.rmSync(path.join(gd, 'HEAD'));
        fs.writeFileSync(path.join(other, 'detached'), `${sha(other)}\n`);
        fs.symlinkSync(path.join(other, 'detached'), path.join(gd, 'HEAD'));
      } else if (how === 'refs') {
        fs.rmSync(path.join(gd, 'refs'), { recursive: true });
        fs.symlinkSync(path.join(other, '.git', 'refs'), path.join(gd, 'refs'));
      } else {
        fs.rmSync(path.join(gd, 'refs', 'heads', 'main'));
        fs.copyFileSync(path.join(other, '.git', 'packed-refs'), path.join(gd, 'packed-refs'));
      }
      const r = await scanIn(victim);
      expect([how, r.code]).toEqual([how, 2]);
      expect(r.stdout).toBe('');
      expect(r.stdout).not.toContain('other-secret.txt');
    }
  });

  itPosix('a plain git clone of a repository passes the object-store check', async () => {
    const src = repoWithSecret();
    const clone = tmpDir('vg-norc-clone-');
    git(clone, ['clone', '-q', src, 'c']);
    const r = await scanIn(path.join(clone, 'c'));
    expect(r.code).toBe(1);
  });
});

/**
 * Overwrite an object's loose file with `body` as an object of `type`, so the
 * file holds bytes that do not hash to the id it is stored under.
 */
function overwriteObject(dir: string, oid: string, type: string, body: Buffer): void {
  const file = path.join(dir, '.git', 'objects', oid.slice(0, 2), oid.slice(2));
  fs.chmodSync(file, 0o644);
  fs.writeFileSync(file, zlib.deflateSync(Buffer.concat([Buffer.from(`${type} ${body.length}\0`), body])));
}

const rawOid = (oid: string): Buffer => Buffer.from(oid, 'hex');

describe('--no-repo-controls: the object store must hold what its ids claim', () => {
  const NOT_HELD = 'the object store does not hold what its ids claim';

  function expectRefused(r: { code: number; err: string; stdout: string; log: string }): void {
    expect(r.code).toBe(2);
    expect(r.err).toContain(NOT_HELD);
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
    expect(r.stdout).toBe('');
    expect(r.log).not.toContain('No secrets found');
  }

  itPosix('a loose blob rewritten to clean content: exit 2 naming the path', async () => {
    const dir = repoWithSecret({ 'ok.txt': 'fine\n' });
    overwriteObject(dir, sha(dir, 'HEAD:secret.txt'), 'blob', Buffer.from('clean\n'));
    const r = await scanIn(dir);
    expectRefused(r);
    expect(r.err).toContain('"secret.txt"');
  });

  itPosix('a blob read and then skipped as binary is still checked', async () => {
    const dir = tmpDir('vg-norc-bin-');
    initClean(dir);
    write(dir, 'pic.png', 'not really a png\n');
    commitClean(dir, 'png');
    overwriteObject(dir, sha(dir, 'HEAD:pic.png'), 'blob', Buffer.from('other\n'));
    expectRefused(await scanIn(dir));
  });

  itPosix('a tree object rewritten to point secret.txt at a clean blob: exit 2', async () => {
    const dir = repoWithSecret({ 'ok.txt': 'fine\n' });
    const clean = sha(dir, 'HEAD:ok.txt');
    const body = Buffer.concat([
      Buffer.from('100644 ok.txt\0'),
      rawOid(clean),
      Buffer.from('100644 secret.txt\0'),
      rawOid(clean),
    ]);
    overwriteObject(dir, sha(dir, 'HEAD^{tree}'), 'tree', body);
    expectRefused(await scanIn(dir));
  });

  itPosix('a commit object rewritten to name a clean tree: exit 2', async () => {
    const dir = tmpDir('vg-norc-commit-');
    initClean(dir);
    write(dir, 'secret.txt', 'clean\n');
    commitClean(dir, 'clean first');
    const cleanTree = sha(dir, 'HEAD^{tree}');
    write(dir, 'secret.txt', `aws = "${AWS_KEY}"\n`);
    commitClean(dir, 'key second');
    const raw = execFileSync('git', ['cat-file', 'commit', 'HEAD'], { cwd: dir }).toString();
    const forged = raw.replace(/^tree [0-9a-f]+/, `tree ${cleanTree}`);
    expect(forged).not.toBe(raw);
    overwriteObject(dir, sha(dir), 'commit', Buffer.from(forged));
    // The untampered repository judges the key; the forged one must not pass as clean.
    expectRefused(await scanIn(dir));
  });

  itPosix('a repository with packed objects (git gc) still scans and reports the key', async () => {
    const dir = repoWithSecret({ 'sub/a.txt': 'one\n', 'sub/deep/b.txt': 'two\n' });
    git(dir, ['gc', '-q']);
    expect(fs.existsSync(path.join(dir, '.git', 'objects', sha(dir).slice(0, 2), sha(dir).slice(2)))).toBe(false);
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    expect(files(parse(r.stdout) as Doc)).toEqual(['secret.txt|aws-access']);
  });

  itPosix('a sha256 repository scans, and its tampered blob is refused', async () => {
    const dir = tmpDir('vg-norc-sha256-');
    try {
      git(dir, ['init', '-q', '-b', 'main', '--object-format=sha256']);
    } catch {
      return; // This git cannot make a sha256 repository.
    }
    write(dir, 'secret.txt', `aws = "${AWS_KEY}"\n`);
    write(dir, 'sub/ok.txt', 'fine\n');
    commitClean(dir, 'sha256');
    expect(sha(dir)).toHaveLength(64);
    const ok = await scanIn(dir);
    expect(ok.code).toBe(1);
    overwriteObject(dir, sha(dir, 'HEAD:secret.txt'), 'blob', Buffer.from('clean\n'));
    expectRefused(await scanIn(dir));
  });

  itPosix('a lstat-walk refusal prints a capped path for a deep nest', async () => {
    const dir = repoWithSecret();
    let deep = path.join(dir, '.git', 'objects');
    for (let i = 0; i < 60; i++) deep = path.join(deep, 'dddddddddd');
    fs.mkdirSync(deep, { recursive: true });
    fs.symlinkSync('/nonexistent', path.join(deep, 'link'));
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/\.\.\. \(\d+ characters\)/);
    expect(r.err.length).toBeLessThan(1200);
  });
});

/**
 * A repository built from raw objects, so a tree can carry modes `git mktree`
 * would never write. `put` hashes a blob; `tree` writes a tree object verbatim.
 */
function rawRepo(
  build: (api: {
    blob: (text: string | Buffer) => string;
    tree: (rows: Array<[string, string, string]>) => string;
    rawTree: (bytes: Buffer) => string;
  }) => string,
): string {
  const dir = tmpDir('vg-norc-raw-');
  initClean(dir);
  const run = (args: string[], input: string | Buffer): string =>
    execFileSync('git', args, { cwd: dir, input }).toString().trim();
  const root = build({
    blob: text => run(['hash-object', '-w', '--stdin'], text),
    tree: rows =>
      run(
        ['hash-object', '-t', 'tree', '--literally', '-w', '--stdin'],
        Buffer.concat(rows.map(([mode, name, oid]) => Buffer.concat([Buffer.from(`${mode} ${name}\0`), rawOid(oid)]))),
      ),
    rawTree: bytes => run(['hash-object', '-t', 'tree', '--literally', '-w', '--stdin'], bytes),
  });
  const commit = execFileSync('git', ['commit-tree', root, '-m', 'raw'], {
    cwd: dir,
    env: { ...process.env, ...IDENTITY },
  })
    .toString()
    .trim();
  git(dir, ['update-ref', 'refs/heads/main', commit]);
  return dir;
}

describe('--no-repo-controls: a mode is classified the way git does, and never skipped', () => {
  const KEY = `aws = "${AWS_KEY}"\n`;

  itPosix.each(['100664', '100600', '0100644', '100744', '100755', '100444'])(
    'a regular file with mode %s is scanned and its key reported',
    async mode => {
      const dir = rawRepo(({ blob, tree }) => tree([[mode, 'f.txt', blob(KEY)]]));
      const r = await scanIn(dir);
      expect(r.code).toBe(1);
      expect(files(parse(r.stdout) as Doc)).toEqual(['f.txt|aws-access']);
    },
  );

  itPosix.each(['40000', '40755', '040755', '040000', '0040000'])('a tree written with mode %s is descended into', async mode => {
    const dir = rawRepo(({ blob, tree }) => tree([[mode, 'd', tree([['100644', 'inner.txt', blob(KEY)]])]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    expect(files(parse(r.stdout) as Doc)).toEqual(['d/inner.txt|aws-access']);
  });

  itPosix('a symlink target holding a key is scanned and reported under the link path', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['120000', 'link', blob(KEY)], ['100644', 'ok.txt', blob('fine\n')]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    expect(files(parse(r.stdout) as Doc)).toEqual(['link|aws-access']);
    const doc = parse(r.stdout) as unknown as { notScanned: Record<string, unknown> };
    expect(doc.notScanned).not.toHaveProperty('symlinks');
  });

  itPosix.each([['link', '120000'], ['skipped.log', '100644']])(
    'an entry %s (mode %s) naming an object the store does not have: exit 2',
    async (name, mode) => {
      const dir = rawRepo(({ blob, tree }) => tree([[mode, name, 'a'.repeat(40)], ['100644', 'ok.txt', blob('fine\n')]]));
      const r = await scanIn(dir);
      expect(r.code).toBe(2);
      expect(r.err).toContain(`"${name}"`);
      expect(r.err).toContain('which is missing');
      expect(r.stdout).toBe('');
    },
  );

  itPosix.each(['160000', '0160000'])('a gitlink written with mode %s is listed as a submodule', async mode => {
    const dir = rawRepo(({ blob, tree }) => tree([[mode, 'sub', blob('x\n')], ['100644', 'ok.txt', blob('fine\n')]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(0);
    const doc = parse(r.stdout) as unknown as { notScanned: { submodules: string[] } };
    expect(doc.notScanned.submodules).toEqual(['sub']);
  });

  itPosix.each([
    ['not octal', '10064x'],
    ['not octal at all', 'abc'],
    ['only a permission', '1'],
    ['every type bit set', '170000'],
    ['a fifo', '010644'],
    ['a character device', '020644'],
    ['no type bits', '000644'],
  ])('a mode that is %s (%s): exit 2 naming the entry and its mode', async (_why, mode) => {
    const dir = rawRepo(({ blob, tree }) => tree([[mode, 'weird.txt', blob(KEY)]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('"weird.txt"');
    expect(r.err).toContain(`"${mode}"`);
    expect(r.stdout).toBe('');
  });

  itPosix('a file mode whose object is a tree: exit 2, not skipped', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'f.txt', tree([['100644', 'inner.txt', blob(KEY)]])]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('"f.txt"');
    expect(r.err).toContain('is a tree');
  });

  itPosix('a tree mode whose object is a blob: exit 2, not skipped', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['40000', 'd', blob(KEY)]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('is where a tree is named');
  });
});

describe('--no-repo-controls: a tree that expands without bound is refused', () => {
  itPosix('ten levels each naming one subtree ten times: exit 2 within seconds, too large to list', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      let level = tree([['100644', 'leaf.txt', blob('x\n')]]);
      for (let i = 0; i < 10; i++) {
        level = tree(Array.from({ length: 10 }, (_, k): [string, string, string] => ['40000', `d${k}`, level]));
      }
      return level;
    });
    const t0 = Date.now();
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('too large to list');
    expect(r.err).toContain('2000000 tree rows');
    expect(r.stdout).toBe('');
    expect(Date.now() - t0).toBeLessThan(60_000);
  }, 120_000);

  itPosix('a tree nested deeper than the depth limit: exit 2, too large to list', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      let level = tree([['100644', 'leaf.txt', blob('x\n')]]);
      for (let i = 0; i < 1005; i++) level = tree([['40000', 'd', level]]);
      return level;
    });
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('deeper than 1000 directories');
  }, 120_000);
});

describe('--no-repo-controls: an over-limit file is verified, then reported as over the limit', () => {
  itPosix('a loose object replaced by a huge blob: exit 2, the object store does not hold what its ids claim', async () => {
    const dir = repoWithSecret({ 'ok.txt': 'fine\n' }, 'x\n');
    overwriteObject(dir, sha(dir, 'HEAD:secret.txt'), 'blob', Buffer.alloc(40 * 1024 * 1024, 0x61));
    const r = await scanIn(dir, { format: 'text' });
    expect(r.code).toBe(2);
    expect(r.err).toContain('the object store does not hold what its ids claim');
    expect(r.err).toContain('Clone the repository fresh and assess the clone.');
    expect(r.err).not.toContain('MiB: over');
  }, 180_000);

  itPosix('a real file over the scan limit: exit 2, kept as too_large, no clone-fresh advice', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'big.dat', blob('a'.repeat(33 * 1024 * 1024))]]));
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('over the 32 MiB scan limit');
    expect(r.err).not.toContain('Clone the repository fresh');
    expect(r.err).not.toContain('ignore.paths');
    expect(r.err).toContain('reads no config');
    const doc = JSON.parse(r.stdout) as { run: { unscannable?: Array<{ kind: string }> } } & Record<string, unknown>;
    expect(JSON.stringify(doc)).toContain('too_large');
  }, 180_000);
});

describe('--no-repo-controls: a blob named by many paths is scanned once and reported under each', () => {
  itPosix('30 paths, one blob: read once, reported 30 times', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      const oid = blob(`aws = "${AWS_KEY}"\n`);
      return tree(Array.from({ length: 30 }, (_, i): [string, string, string] => ['100644', `f${String(i).padStart(2, '0')}.txt`, oid]));
    });
    const spy = jest.spyOn(BlobBatchReader.prototype, 'read');
    try {
      const r = await scanIn(dir);
      expect(r.code).toBe(1);
      expect(files(parse(r.stdout) as Doc)).toHaveLength(30);
      const oids = spy.mock.calls.map(c => c[0]);
      expect(oids).toHaveLength(1);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('--no-repo-controls: names the built-in rules skip are listed, not hidden', () => {
  const KEY = `aws = "${AWS_KEY}"\n`;

  itPosix('a vendored directory, a minified file, a lockfile and a log holding keys: exit 0, each listed', async () => {
    const dir = rawRepo(({ blob, tree }) =>
      tree([
        ['40000', 'node_modules', tree([['100644', 'k.js', blob(KEY)]])],
        ['100644', 'x.min.js', blob(KEY)],
        ['100644', 'yarn.lock', blob(KEY)],
        ['100644', 'run.log', blob(KEY)],
        ['100644', 'ok.txt', blob('fine\n')],
      ]),
    );
    const r = await scanIn(dir);
    expect(r.code).toBe(0);
    const doc = parse(r.stdout) as unknown as { notScanned: { builtInSkips: Array<{ path: string; reason: string }>; builtInSkipsOmitted: number } };
    expect(doc.notScanned.builtInSkips.map(s => s.path)).toEqual(['node_modules', 'run.log', 'x.min.js', 'yarn.lock']);
    expect(doc.notScanned.builtInSkipsOmitted).toBe(0);
    const sarif = JSON.parse((await scanIn(dir, { format: 'sarif' })).stdout) as { runs: Array<{ properties: { notScanned: { builtInSkips: unknown[] } } }> };
    expect(sarif.runs[0].properties.notScanned.builtInSkips).toHaveLength(4);
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('Not scanned, built-in skip: node_modules');
    expect(text.log).toContain('No secrets found in the files scanned; 4 paths were not scanned, listed above');
    expect(text.log).not.toContain('No secrets found\n');
  });

  itPosix('JSON lists every skip; the text shows a capped share and says how many are not shown', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      const oid = blob(KEY);
      return tree([
        ['100644', 'ok.txt', blob('fine\n')],
        ...Array.from({ length: 205 }, (_, i): [string, string, string] => ['100644', `a${String(i).padStart(3, '0')}.log`, oid]),
      ]);
    });
    const r = await scanIn(dir);
    expect(r.code).toBe(0);
    const doc = parse(r.stdout) as unknown as { notScanned: { builtInSkips: unknown[]; builtInSkipsOmitted: number } };
    expect(doc.notScanned.builtInSkips).toHaveLength(205);
    expect(doc.notScanned.builtInSkipsOmitted).toBe(0);
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('5 more (log file, skipped by a built-in name rule) not shown; the JSON report lists all');
    expect(text.log).toContain('205 paths were not scanned, 200 listed above and 5 not shown (the JSON report lists all)');
  });

  itPosix('250 lockfiles do not crowd out the one log that holds a key', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      const oid = blob('x\n');
      return tree([
        ['100644', 'ok.txt', blob('fine\n')],
        ['100644', 'zz.log', blob(KEY)],
        ...Array.from({ length: 250 }, (_, i): [string, string, string] => ['100644', `a${String(i).padStart(3, '0')}.lock`, oid]),
      ]);
    });
    const r = await scanIn(dir);
    const doc = parse(r.stdout) as unknown as { notScanned: { builtInSkips: Array<{ path: string }> } };
    expect(doc.notScanned.builtInSkips).toHaveLength(251);
    expect(doc.notScanned.builtInSkips.some(s => s.path === 'zz.log')).toBe(true);
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('Not scanned, built-in skip: zz.log (log file');
    expect(text.log).toContain('251 paths were not scanned, 101 listed above and 150 not shown (the JSON report lists all)');
  });

  itPosix('a key after a binary header is listed as not scanned, and the verdict is qualified', async () => {
    const dir = rawRepo(({ blob, tree }) =>
      tree([
        ['100644', 'logo.png', blob(Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]), Buffer.from(KEY)]))],
        ['100644', 'ok.txt', blob('fine\n')],
      ]),
    );
    const r = await scanIn(dir);
    expect(r.code).toBe(0);
    const doc = parse(r.stdout) as unknown as { notScanned: { builtInSkips: Array<{ path: string; reason: string }> } };
    expect(doc.notScanned.builtInSkips).toEqual([
      { path: 'logo.png', reason: 'binary file (image): its extension and its first bytes agree, so it was not scanned' },
    ]);
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('Not scanned, built-in skip: logo.png (binary file (image)');
    expect(text.log).toContain('No secrets found in the files scanned; 1 path was not scanned, listed above');
  });
});

describe('--no-repo-controls: one very wide tree is refused while it is parsed', () => {
  itPosix('2,100,000 rows in one tree: exit 2, too large to list, quickly', async () => {
    const dir = rawRepo(({ blob, rawTree }) => {
      const oid = rawOid(blob('x\n'));
      const rows = 2_100_000;
      const parts: Buffer[] = [];
      for (let i = 0; i < rows; i++) parts.push(Buffer.from(`100644 n${i}\0`), oid);
      return rawTree(Buffer.concat(parts));
    });
    const t0 = Date.now();
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('too large to list');
    expect(r.err).toContain('2000000 tree rows');
    expect(Date.now() - t0).toBeLessThan(90_000);
  }, 300_000);
});

describe('--no-repo-controls: sharing a blob between paths never changes what a path reports', () => {
  // Blobs built to react to every path input the scan reads.
  const MIXED = Buffer.concat([
    // PNG magic then text: a binary-by-name skip under x.png, a text scan under .png.
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    Buffer.from(`\nx = """\npassword = "hunter2hunter2xx"\n"""\naws = "${AWS_KEY}"\n`),
  ]);
  // Generic password assignments: downgraded in test, docs and locale paths.
  const TEXT = Buffer.from(`password = "Vq7Lp2Xz9Rt4Mk8Wn3Bd"\napi_key = "Zq9Lp2Xz9Rt4Mk8Wn3BdQ"\naws = "${AWS_KEY}"\n`);
  // A key inside a Rust test module: lower severity only where the inline-test finder applies.
  const RUST = Buffer.from(
    `fn main() {}\n#[cfg(test)]\nmod tests {\n    const K: &str = "${AWS_KEY}";\n    let password = "Vq7Lp2Xz9Rt4Mk8Wn3Bd";\n}\n`,
  );
  // Generic assignments inside a Python triple-quoted string: no finding only under a .py name.
  const PY = Buffer.from('doc = """\npassword = "Vq7Lp2Xz9Rt4Mk8Wn3Bd"\napi_key = "Zq9Lp2Xz9Rt4Mk8Wn3BdQ"\n"""\n');
  const BLOBS = { MIXED, TEXT, RUST, PY };

  /** [path, other path, blob, whether the two paths must be judged differently]. */
  const PAIRS: Array<[string, string, keyof typeof BLOBS, boolean]> = [
    ['x.png', '.png', 'MIXED', true],
    ['.png', 'x.png', 'MIXED', true],
    ['a.b/file', 'file', 'MIXED', false],
    ['X.PNG', 'x.png', 'MIXED', false],
    ['x.png', 'x.png.', 'MIXED', true],
    ['file.', 'file', 'MIXED', false],
    ['x.py', 'x.PY', 'PY', true],
    ['x.py', 'x.txt', 'PY', true],
    ['foo.min.js', 'bar.js', 'MIXED', false],
    ['docs/a.txt', 'src/a.txt', 'TEXT', true],
    ['test/a.js', 'src/a.js', 'TEXT', true],
    ['locales/a.txt', 'src/a.txt', 'TEXT', true],
    ['yarn.lock', 'a.txt', 'MIXED', false],
    ['a/b.rs', 'a/b.RS', 'RUST', false],
    ['a/b.rs', 'a/b.txt', 'RUST', true],
  ];

  interface Snapshot {
    results: unknown;
    stats: { filesScanned: number; bytesScanned: number };
    binary: number;
    typeMismatch: unknown;
    placeholders: number;
    inline: number;
    kept: string[];
    unreadable: unknown;
  }

  const snapshot = async (
    dir: string,
    blobs: Map<string, string>,
    files: string[],
    shareBlobs: boolean,
  ): Promise<Snapshot> => {
    const stats = { filesScanned: 0, bytesScanned: 0 };
    const skips = newRunSkipCounts();
    const placeholderSkips = { count: 0, locations: [] as Array<{ file: string; line: number }> };
    const inlineSuppressed = { count: 0, criticalVendorAnchored: 0 };
    const content = newContentReport();
    const unreadable: never[] = [];
    const results = await scanHeadBlobsAsync(files, blobs, dir, new SecretScanner({}), {
      blobOnly: true,
      shareBlobs,
      skipBinary: true,
      inlineDirectives: 'mark',
      stats,
      skips,
      placeholderSkips,
      inlineSuppressed,
      content,
      unreadable,
    });
    const rel = (f: string): string => path.relative(dir, f);
    return {
      results: results.map(r => ({ ...r, file: rel(r.file) })).sort((x, y) => (x.file < y.file ? -1 : 1)),
      stats,
      binary: skips.binary,
      typeMismatch: skips.typeMismatch.map(t => ({ ...t, file: rel(t.file) })),
      placeholders: placeholderSkips.count,
      inline: inlineSuppressed.count,
      kept: [...content.kept.keys()].map(k => rel(k.split('\0')[0]) + '|' + k.split('\0').slice(1).join('|')).sort(),
      unreadable,
    };
  };

  it.each(PAIRS)('%s and %s (%s): the shared run reports each path as scanning it alone does', async (a, b, which, differs) => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'seed.bin', blob(BLOBS[which])]]));
    const oid = sha(dir, 'HEAD:seed.bin');
    const paths = [a, b].map(p => path.join(dir, p));
    const blobs = new Map(paths.map(p => [p, oid]));
    const aloneA = await snapshot(dir, blobs, [paths[0]], false);
    const aloneB = await snapshot(dir, blobs, [paths[1]], false);
    const sum: Snapshot = {
      results: [...(aloneA.results as unknown[]), ...(aloneB.results as unknown[])].sort((x, y) =>
        (x as { file: string }).file < (y as { file: string }).file ? -1 : 1,
      ),
      stats: {
        filesScanned: aloneA.stats.filesScanned + aloneB.stats.filesScanned,
        bytesScanned: aloneA.stats.bytesScanned + aloneB.stats.bytesScanned,
      },
      binary: aloneA.binary + aloneB.binary,
      typeMismatch: [...(aloneA.typeMismatch as unknown[]), ...(aloneB.typeMismatch as unknown[])],
      placeholders: aloneA.placeholders + aloneB.placeholders,
      inline: aloneA.inline + aloneB.inline,
      kept: [...aloneA.kept, ...aloneB.kept].sort(),
      unreadable: [...(aloneA.unreadable as unknown[]), ...(aloneB.unreadable as unknown[])],
    };
    expect(await snapshot(dir, blobs, paths, true)).toEqual(sum);
    expect(await snapshot(dir, blobs, paths, false)).toEqual(sum);
    // Not vacuous: where the rules judge the two paths differently, the alone results differ.
    const matchesOf = (snap: Snapshot): string =>
      JSON.stringify((snap.results as Array<{ matches: unknown }>).map(r => r.matches));
    if (differs) {
      expect([matchesOf(aloneA), aloneA.binary, aloneA.typeMismatch]).not.toEqual([
        matchesOf(aloneB),
        aloneB.binary,
        aloneB.typeMismatch,
      ]);
    }
  });

  itPosix('a blob under x.png and under .png: the key under the dotfile name is reported', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      const oid = blob(MIXED);
      return tree([['100644', 'x.png', oid], ['100644', '.png', oid]]);
    });
    const r = await scanIn(dir);
    expect(files(parse(r.stdout) as Doc).some(f => f.startsWith('.png|'))).toBe(true);
  });

  itPosix('the same blob under a docs path and a source path is judged per path', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      const oid = blob(TEXT);
      return tree([
        ['40000', 'docs', tree([['100644', 'a.txt', oid]])],
        ['40000', 'src', tree([['100644', 'a.txt', oid]])],
      ]);
    });
    const doc = parse((await scanIn(dir)).stdout) as unknown as {
      results: Array<{ file: string; matches: Array<{ type: string; severity: string }> }>;
    };
    const sev = (file: string): string[] => (doc.results.find(r => r.file === file)?.matches ?? []).map(m => `${m.type}:${m.severity}`);
    expect(sev('src/a.txt').length).toBeGreaterThan(0);
    expect(sev('src/a.txt')).not.toEqual(sev('docs/a.txt'));
    expect(sev('src/a.txt').some(x => x.endsWith(':high') || x.endsWith(':critical'))).toBe(true);
  });
});

/** Every fs function that reads or inspects a path, spied for the run of `fn`; the paths seen are returned. */
async function fsPathsTouched(fn: () => Promise<unknown>): Promise<Array<[string, string]>> {
  // The module object itself (a namespace import is frozen), so the code under test sees the spies.
  const realFs = jest.requireActual<typeof import('fs')>('fs');
  const seen: Array<[string, string]> = [];
  const spies: jest.SpyInstance[] = [];
  const watch = (obj: object, name: string, label: string): void => {
    const o = obj as Record<string, (...a: unknown[]) => unknown>;
    if (typeof o[name] !== 'function') return;
    const real = o[name];
    spies.push(
      jest.spyOn(o, name).mockImplementation(function (this: unknown, ...args: unknown[]) {
        const first = args[0];
        if (typeof first === 'string' || first instanceof URL || Buffer.isBuffer(first)) seen.push([label, String(first)]);
        return real.apply(this, args);
      }),
    );
  };
  for (const n of ['readFileSync', 'readdirSync', 'statSync', 'lstatSync', 'existsSync', 'openSync', 'readlinkSync', 'accessSync', 'opendirSync', 'createReadStream', 'readFile', 'readdir', 'stat', 'lstat', 'open', 'access', 'readlink', 'opendir', 'realpath', 'writeFileSync', 'mkdirSync']) {
    watch(realFs, n, `fs.${n}`);
    watch(realFs.promises, n, `fs.promises.${n}`);
  }
  // realpathSync is a function with a .native member: spy the member, then keep it on the spy.
  const realpathNative = realFs.realpathSync.native;
  watch(realFs.realpathSync, 'native', 'fs.realpathSync.native');
  const nativeSpy = realFs.realpathSync.native;
  watch(realFs, 'realpathSync', 'fs.realpathSync');
  (realFs.realpathSync as unknown as { native: typeof realpathNative }).native = nativeSpy;
  try {
    await fn();
  } finally {
    for (const sp of spies) sp.mockRestore();
  }
  return seen;
}

describe('--no-repo-controls: the working tree is never consulted', () => {
  itPosix('no fs call touches a path outside .git (the repository root itself excepted)', async () => {
    const dir = rawRepo(({ blob, tree }) =>
      tree([
        ['100644', 'a.txt', blob(`aws = "${AWS_KEY}"\n`)],
        ['40000', 'src', tree([['100644', 'app.js', blob('x = 1\n')]])],
        ['40000', 'data', tree([['100644', 'keys.tsv', blob(GROUPED_TSV)]])],
      ]),
    );
    const root = fs.realpathSync.native(dir);
    const touched = await fsPathsTouched(async () => {
      for (const format of ['text', 'json', 'sarif'] as const) {
        await scanIn(dir, { format });
        await scanIn(dir, { format, target: 'data' });
      }
    });
    // Allowed: anything under .git (the object-store checks), and realpath of the
    // repository root itself, which only locates the checkout and reads no file in it.
    const stray = touched.filter(([method, p]) => {
      const abs = path.resolve(p);
      const inGit = abs === path.join(root, '.git') || abs.startsWith(path.join(root, '.git') + path.sep);
      const locatesRoot = method.startsWith('fs.realpathSync') && (abs === root || abs === path.resolve(dir));
      // Finding git: a stat or realpath of a file named git on a PATH entry.
      const findsGit = /(^|[\\/])git(\.exe|\.com)?$/.test(abs) && /stat|realpath|lstat/i.test(method);
      // The ancestor walk: an lstat of <ancestor>/.git for each directory above the root.
      const ancestorGit =
        method === 'fs.lstatSync' && path.basename(abs) === '.git' && !abs.startsWith(root + path.sep) && abs !== path.join(root, '.git');
      return !inGit && !locatesRoot && !findsGit && !ancestorGit;
    });
    // The spy is live: the object-store lstat checks under .git were seen.
    expect(touched.some(([m, p]) => m === 'fs.lstatSync' && p.includes(`${path.sep}.git${path.sep}objects`))).toBe(true);
    expect(stray).toEqual([]);
  });
});

/** 25 rows of a header-only rule in a tab-delimited file: forms a group. */
const GROUPED_TSV = ['id\tpayload', ...Array.from({ length: 25 }, (_, i) => `${i}\t{"type": "service_account"}`)].join('\n') + '\n';

describe('--no-repo-controls: the working tree cannot change the result', () => {
  const HIGH = 'password: "Vq7Lp2Xz9Rt4Mk8Wn3Bd"\n';
  const sevOf = (stdout: string): string[] =>
    (parse(stdout) as Doc).results.flatMap(r => r.matches.map(m => (m as unknown as { severity: string }).severity));

  itPosix.each(['test', 'docs', 'locales'])(
    'src/app.js with src on disk a link to %s/: still judged as src/app.js (high)',
    async target => {
      const dir = rawRepo(({ blob, tree }) => tree([['40000', 'src', tree([['100644', 'app.js', blob(HIGH)]])]]));
      expect(sevOf((await scanIn(dir)).stdout)).toEqual(['high']);
      fs.mkdirSync(path.join(dir, target));
      fs.symlinkSync(target, path.join(dir, 'src'));
      const r = await scanIn(dir);
      expect(r.code).toBe(1);
      expect(sevOf(r.stdout)).toEqual(['high']);
    },
  );

  const stripTiming = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(stripTiming);
    if (v !== null && typeof v === 'object') {
      return Object.fromEntries(
        Object.entries(v as Record<string, unknown>)
          .filter(([k]) => !/(^|_)(ms|duration|elapsed|time|timestamp|seconds)($|_)|Ms$|At$/i.test(k))
          .map(([k, x]) => [k, stripTiming(x)]),
      );
    }
    return v;
  };

  itPosix('replacing the whole working tree with hostile content leaves the report byte-identical', async () => {
    const dir = rawRepo(({ blob, tree }) =>
      tree([
        ['100644', 'a.txt', blob(`aws = "${AWS_KEY}"\n`)],
        ['100644', '.gitignore', blob('a.txt\n')],
        ['100644', '.vault-guard.json', blob('{"ignore":{"paths":["a.txt"]}}')],
        ['40000', 'src', tree([['100644', 'app.js', blob(HIGH)]])],
        ['40000', 'docs', tree([['100644', 'g.txt', blob(HIGH)]])],
        ['120000', 'lnk', blob(`aws = "${AWS_KEY}"\n`)],
        ['40000', 'data', tree([['100644', 'keys.tsv', blob(GROUPED_TSV)]])],
      ]),
    );
    const first = JSON.stringify(stripTiming(parse((await scanIn(dir)).stdout)));
    // A header-only rule in 25 rows of a delimited file forms a group, whose members digest is keyed on the path.
    expect(first).toContain('members_digest');
    // Hostile working tree: links into other directories, different bodies, a
    // directory where a file was, a config that would silence everything.
    fs.mkdirSync(path.join(dir, 'test'));
    fs.mkdirSync(path.join(dir, 'a.txt'));
    fs.writeFileSync(path.join(dir, '.vault-guard.json'), '{"ignore":{"paths":["**"]}}');
    fs.writeFileSync(path.join(dir, '.vault-guard.baseline.json'), '{"entries":[]}');
    fs.symlinkSync('test', path.join(dir, 'src'));
    fs.symlinkSync('/', path.join(dir, 'docs'));
    fs.symlinkSync('test', path.join(dir, 'data'));
    fs.writeFileSync(path.join(dir, 'lnk'), 'clean\n');
    fs.writeFileSync(path.join(dir, 'new-key.txt'), `aws = "${AWS_KEY}"\n`);
    const second = JSON.stringify(stripTiming(parse((await scanIn(dir)).stdout)));
    expect(JSON.parse(second)).toEqual(JSON.parse(first));
    expect(second).toBe(first);
  });
});

describe('--no-repo-controls: budgets and what is held', () => {
  const sizeMiB = (n: number, fill: string): string => fill.repeat(n * 1024 * 1024);

  itPosix('over-limit blobs past the verification budget are reported as not verified, exit 2', async () => {
    const dir = rawRepo(({ blob, tree }) =>
      tree([
        ['100644', 'big1.dat', blob(sizeMiB(33, 'a'))],
        ['100644', 'big2.dat', blob(sizeMiB(33, 'b'))],
      ]),
    );
    const blobs = new Map([
      [path.join(dir, 'big1.dat'), sha(dir, 'HEAD:big1.dat')],
      [path.join(dir, 'big2.dat'), sha(dir, 'HEAD:big2.dat')],
    ]);
    const unreadable: Array<{ kind?: 'too_large' | 'read_error' | 'scan_budget'; file: string; reason: string }> = [];
    await scanHeadBlobsAsync([...blobs.keys()], blobs, dir, new SecretScanner({}), {
      blobOnly: true,
      verifyOnlyBudgetBytes: 40 * 1024 * 1024,
      unreadable,
      concurrency: 1,
    });
    expect(unreadable.map(u => u.kind).sort()).toEqual(['read_error', 'too_large']);
    expect(unreadable.find(u => u.kind === 'read_error')?.reason).toContain('not verified');
  }, 180_000);

  itPosix('kept bytes of a shared header-only blob are filed under every path', async () => {
    const PEM = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\n-----END RSA PRIVATE KEY-----\n';
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'a.txt', blob(PEM)], ['100644', 'b.txt', blob(PEM)]]));
    const blobs = new Map([
      [path.join(dir, 'a.txt'), sha(dir, 'HEAD:a.txt')],
      [path.join(dir, 'b.txt'), sha(dir, 'HEAD:b.txt')],
    ]);
    for (const shareBlobs of [true, false]) {
      const content = newContentReport();
      await scanHeadBlobsAsync([...blobs.keys()], blobs, dir, new SecretScanner({}), { blobOnly: true, shareBlobs, content });
      const keys = [...content.kept.keys()].map(k => path.relative(dir, k.split('\0')[0]) + '|' + k.split('\0')[1]).sort();
      expect([shareBlobs, keys]).toEqual([shareBlobs, ['a.txt|head', 'b.txt|head']]);
    }
  });

  itPosix('a blob named twice, the second name last in the tree, is not held for the second name', async () => {
    const N = 30;
    const dir = rawRepo(({ blob, tree }) =>
      tree([
        ...Array.from({ length: N }, (_, i): [string, string, string] => ['100644', `a${String(i).padStart(2, '0')}.txt`, blob(`line ${i}\n`)]),
        ...Array.from({ length: N }, (_, i): [string, string, string] => ['100644', `z${String(i).padStart(2, '0')}.txt`, blob(`line ${i}\n`)]),
      ]),
    );
    const names = [...Array.from({ length: N }, (_, i) => `a${String(i).padStart(2, '0')}.txt`), ...Array.from({ length: N }, (_, i) => `z${String(i).padStart(2, '0')}.txt`)];
    const blobs = new Map(names.map(n => [path.join(dir, n), sha(dir, `HEAD:${n}`)]));
    const readers = new Set<BlobBatchReader>();
    const real = BlobBatchReader.prototype.read;
    const spy2 = jest.spyOn(BlobBatchReader.prototype, 'read').mockImplementation(function (this: BlobBatchReader, oid: string) {
      readers.add(this);
      return real.call(this, oid);
    });
    try {
      await scanHeadBlobsAsync([...blobs.keys()], blobs, dir, new SecretScanner({}), { blobOnly: true, concurrency: 10 });
    } finally {
      spy2.mockRestore();
    }
    const maxHeld = Math.max(...[...readers].map(r => r.maxHeld));
    // Held at once: at most the reads in flight, not all N blobs waiting for their second name.
    expect(maxHeld).toBeLessThan(N);
  });
});

describe('--no-repo-controls: which repository is judged', () => {
  const identity = { ...process.env, ...IDENTITY };

  /** An outer repository tracking sub/app.js (a key), with a planted, untracked clean repository in sub/. */
  function plantedNested(): { outer: string; sub: string } {
    const outer = tmpDir('vg-norc-outer-');
    initClean(outer);
    write(outer, 'sub/app.js', `aws = "${AWS_KEY}"\n`);
    write(outer, 'top.txt', 'x\n');
    commitClean(outer, 'outer');
    const sub = path.join(outer, 'sub');
    git(sub, ['init', '-q', '-b', 'main']);
    write(sub, 'clean.txt', 'ok\n');
    git(sub, ['add', 'clean.txt']);
    git(sub, ['-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'clean'], identity);
    return { outer, sub };
  }

  itPosix('a planted .git in a subdirectory of an outer repository: exit 2, nothing judged, no git run in the parent', async () => {
    const { outer, sub } = plantedNested();
    const log = path.join(tmpDir('vg-norc-nlog-'), 'git.log');
    process.env.PATH = `${gitStub(path.dirname(log), log)}${path.delimiter}${process.env.PATH ?? ''}`;
    const r = await scanIn(sub);
    expect(r.code).toBe(2);
    expect(r.err).toContain('sits inside another git work tree');
    expect(r.err).toContain(fs.realpathSync.native(outer));
    expect(r.stdout).toBe('');
    // No program ran against the outer repository: no git was started with it (or any ancestor) as cwd.
    const outerReal = fs.realpathSync.native(outer);
    expect(stubCalls(log).map(c => fs.realpathSync.native(c.cwd)).filter(c => c === outerReal)).toEqual([]);
  });

  itPosix('an ancestor whose .git is a file (a worktree pointer) also refuses', async () => {
    const outer = tmpDir('vg-norc-fileoutr-');
    fs.writeFileSync(path.join(outer, '.git'), 'gitdir: /nonexistent\n');
    const inner = path.join(outer, 'checkout');
    fs.mkdirSync(inner);
    initClean(inner);
    write(inner, 'k.txt', `aws = "${AWS_KEY}"\n`);
    commitClean(inner, 'inner');
    const r = await scanIn(inner);
    expect(r.code).toBe(2);
    expect(r.err).toContain('sits inside another git work tree');
  });

  itPosix('a clean clone placed outside any repository is judged', async () => {
    const src = repoWithSecret();
    const holder = tmpDir('vg-norc-clone-');
    git(holder, ['clone', '-q', src, 'c']);
    expect((await scanIn(path.join(holder, 'c'))).code).toBe(1);
  });

  itPosix('from the root, a target naming that subdirectory still finds the key', async () => {
    const { outer } = plantedNested();
    const r = await scanIn(outer, { target: 'sub' });
    expect(r.code).toBe(1);
    expect(files(parse(r.stdout) as Doc)).toEqual(['sub/app.js|aws-access']);
  });

  itPosix('an outer work tree that does not track the inner repository is refused too, by design', async () => {
    const outer = tmpDir('vg-norc-unrel-');
    initClean(outer);
    write(outer, 'other.txt', 'x\n');
    commitClean(outer, 'outer');
    const inner = path.join(outer, 'checkout');
    fs.mkdirSync(inner);
    initClean(inner);
    write(inner, 'k.txt', `aws = "${AWS_KEY}"\n`);
    commitClean(inner, 'inner');
    const r = await scanIn(inner);
    expect(r.code).toBe(2);
    expect(r.err).toContain('sits inside another git work tree');
  });

  itPosix('run from a subdirectory of the repository: exit 2, run it from the root', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['40000', 'src', tree([['100644', 'a.txt', blob(`aws = "${AWS_KEY}"\n`)]])]]));
    fs.mkdirSync(path.join(dir, 'src'));
    const r = await scanIn(path.join(dir, 'src'));
    expect(r.code).toBe(2);
    expect(r.err).toContain('must run from the root of the repository being assessed');
    expect(r.err).toContain(fs.realpathSync.native(dir));
  });

  itPosix('a symlinked working directory is the root once resolved, and the report names the real root', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'a.txt', blob(`aws = "${AWS_KEY}"\n`)]]));
    const link = path.join(tmpDir('vg-norc-link-'), 'link');
    fs.symlinkSync(dir, link);
    const r = await scanIn(link);
    expect(r.code).toBe(1);
    expect((parse(r.stdout) as unknown as { scannedRoot: string }).scannedRoot).toBe(fs.realpathSync.native(dir));
    const text = await scanIn(link, { format: 'text' });
    expect(text.log).toContain(`Scanned repository root: ${fs.realpathSync.native(dir)}`);
    const sarif = JSON.parse((await scanIn(link, { format: 'sarif' })).stdout) as { runs: Array<{ properties: Record<string, unknown> }> };
    expect(sarif.runs[0].properties.scannedRoot).toBe(fs.realpathSync.native(dir));
  });
});

describe('--no-repo-controls: git is run by absolute path', () => {
  itPosix('a git found on PATH inside the repository being assessed: exit 2', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'a.txt', blob(`aws = "${AWS_KEY}"\n`)]]));
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const realGit = execFileSync('/bin/sh', ['-c', 'command -v git']).toString().trim();
    fs.writeFileSync(path.join(bin, 'git'), `#!/bin/sh\nexec ${realGit} "$@"\n`, { mode: 0o755 });
    process.env.PATH = `${bin}${path.delimiter}${process.env.PATH ?? ''}`;
    const r = await scanIn(dir);
    expect(r.code).toBe(2);
    expect(r.err).toContain('is inside');
    expect(r.err).toContain('assessed');
    expect(r.stdout).toBe('');
  });

  // The Windows job runs this: libuv looks in the child's working directory before
  // PATH for a bare name, so a git.exe in the repository would have been run.
  const itWin32 = process.platform === 'win32' ? it : it.skip;
  itWin32('a git.exe at the repository root is never executed', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'a.txt', blob(`aws = "${AWS_KEY}"\n`)]]));
    fs.copyFileSync(process.execPath, path.join(dir, 'git.exe'));
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    expect(files(parse(r.stdout) as Doc)).toEqual(['a.txt|aws-access']);
  });
});

describe('--no-repo-controls: filters keyed on repository-chosen evidence keep the finding and say so', () => {
  const K = 'Zq9Lp2Xz9Rt4Mk8Wn3BdQ1x7Yv5';
  interface M {
    type: string;
    severity: string;
    context_filter_not_honoured?: string;
    severity_before_path_rules?: string;
  }
  const matchesOf = (stdout: string, file: string): M[] =>
    ((parse(stdout) as unknown as { results: Array<{ file: string; matches: M[] }> }).results.find(r => r.file === file)?.matches ?? []);

  itPosix('an appid comment in a website path: kept, marked doc-context, and the lowering is recorded', async () => {
    const dir = rawRepo(({ blob, tree }) =>
      tree([['40000', 'lib', tree([['40000', 'website', tree([['100644', 'keys2.js', blob(`const api_key = "${K}"; // appid\n`)]])]])]]),
    );
    const r = await scanIn(dir);
    const m = matchesOf(r.stdout, 'lib/website/keys2.js');
    expect(m).toHaveLength(1);
    expect(m[0].context_filter_not_honoured).toBe('doc-context');
    expect(m[0].severity_before_path_rules).toBe('high');
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('Context filters not honoured: 1 finding(s)');
    expect(text.log).toContain('(doc-context filter not honoured)');
  });

  itPosix('a generic key inside a Python triple-quoted string: kept, marked', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'x.py', blob(`doc = """\napi_key = "${K}"\n"""\n`)]]));
    const m = matchesOf((await scanIn(dir)).stdout, 'x.py');
    expect(m.map(x => x.context_filter_not_honoured)).toContain('python-triple-quoted');
  });

  itPosix('an unquoted generic key followed by "(": kept, marked', async () => {
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'a.txt', blob(`api_key = ${K}(x)\n`)]]));
    const m = matchesOf((await scanIn(dir)).stdout, 'a.txt');
    expect(m.map(x => x.context_filter_not_honoured)).toContain('call-follows');
  });
});

describe('--no-repo-controls: path rules that lower a severity are visible', () => {
  const K = 'Zq9Lp2Xz9Rt4Mk8Wn3BdQ1x7Yv5';
  function websiteRepo(): string {
    return rawRepo(({ blob, tree }) =>
      tree([
        ['40000', 'lib', tree([['40000', 'website', tree([['100644', 'keys.js', blob(`const api_key = "${K}";\n`)]])]])],
        ['100644', 'run.log', blob('x\n')],
        ['100644', 'ok.txt', blob('fine\n')],
      ]),
    );
  }

  itPosix('a finding lowered by a website path carries its severity before the rules, in JSON, SARIF and text', async () => {
    const dir = websiteRepo();
    const r = await scanIn(dir);
    expect(r.code).toBe(0);
    const doc = parse(r.stdout) as unknown as { results: Array<{ matches: Array<{ severity: string; severity_before_path_rules?: string }> }> };
    expect(doc.results[0].matches[0]).toMatchObject({ severity: 'low', severity_before_path_rules: 'high' });
    const sarif = JSON.parse((await scanIn(dir, { format: 'sarif' })).stdout) as {
      runs: Array<{ results: Array<{ properties?: Record<string, unknown> }> }>;
    };
    expect(sarif.runs[0].results[0].properties?.['vault-guard/severity_before_path_rules']).toBe('high');
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('(lowered by path rules from high)');
    expect(text.log).toContain('Lowered by path rules: 1 finding(s)');
  });

  itPosix('the below-gate verdict counts the lowered findings, qualifies the pass and advises only --fail-on', async () => {
    const dir = websiteRepo();
    const text = await scanIn(dir, { format: 'text' });
    expect(text.log).toContain('1 finding(s) below the gate "medium", 1 of them lowered by path rules');
    expect(text.log).toContain('1 path was not scanned');
    expect(text.log).toContain('--fail-on low makes every finding block');
    expect(text.log).not.toContain('fail_on');
    expect((await scanIn(dir, { format: 'text', failOn: 'low' })).code).toBe(1);
  });
});

describe('--no-repo-controls: smaller disclosures', () => {
  itPosix('an archive-family binary skip says its content may still be readable text', async () => {
    const tar = Buffer.alloc(512, 0);
    tar.write('ustar', 257);
    tar.write(`aws = "${AWS_KEY}"\n`, 300);
    const dir = rawRepo(({ blob, tree }) => tree([['100644', 'a.tar', blob(tar)], ['100644', 'ok.txt', blob('fine\n')]]));
    const doc = parse((await scanIn(dir)).stdout) as unknown as { notScanned: { builtInSkips: Array<{ path: string; reason: string }> } };
    expect(doc.notScanned.builtInSkips[0].reason).toContain('may still be readable text');
  });

  it('resolveScanRoot decides file or directory from the tree, never by stat', () => {
    expect(resolveScanRoot(['../lib/x.js'], '/r/sub', () => true)).toBe('/r/lib');
    expect(resolveScanRoot(['../lib/x.js'], '/r/sub', () => false)).toBe('/r/lib/x.js');
  });
});
