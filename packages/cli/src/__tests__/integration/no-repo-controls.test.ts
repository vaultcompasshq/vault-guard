import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as zlib from 'zlib';

import { scanCommand } from '../../commands/scan';
import { scanHeadBlobsAsync } from '../../utils/scan-utils';
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
    checkLocalGitConfig: (cwd: string, env: NodeJS.ProcessEnv) =>
      mockConfigCheck.stubbed ? { ok: true, keys: [] } : actual.checkLocalGitConfig(cwd, env),
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
  opts: { format?: 'text' | 'json' | 'sarif'; staged?: boolean; trustBase?: string; noRepoControls?: boolean } = {},
): Promise<{ code: number; log: string; err: string; stdout: string }> {
  process.chdir(dir);
  try {
    return await capture(() =>
      scanCommand(
        '.',
        opts.format ?? 'json',
        opts.staged ?? false,
        undefined,
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
    blob: (text: string) => string;
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

  itPosix('the same blob under a docs path and a source path is judged per path', async () => {
    const dir = rawRepo(({ blob, tree }) => {
      const oid = blob(`password = "hunter2hunter2xx"\naws = "${AWS_KEY}"\n`);
      return tree([
        ['40000', 'docs', tree([['100644', 'a.md', oid]])],
        ['40000', 'src', tree([['100644', 'a.md', oid]])],
        ['100644', 'plain.md', oid],
      ]);
    });
    const shared = await scanIn(dir);
    const each = ['docs/a.md', 'src/a.md', 'plain.md'];
    const found = (parse(shared.stdout) as Doc).results.map(r => r.file).sort();
    expect(found.every(f => each.includes(f))).toBe(true);
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

  itPosix('the list is capped, with the count of the rest', async () => {
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
    expect(doc.notScanned.builtInSkips).toHaveLength(200);
    expect(doc.notScanned.builtInSkipsOmitted).toBe(5);
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
