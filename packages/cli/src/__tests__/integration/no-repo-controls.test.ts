import * as fs from 'fs';
import * as path from 'path';

import { scanCommand } from '../../commands/scan';
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

  it('a .gitignore listing the file: the finding is reported and the .gitignore is listed', async () => {
    const dir = repoWithSecret({ '.gitignore': 'secret.txt\n', 'sub/.gitignore': '*\n' });
    const r = await scanIn(dir);
    expect(r.code).toBe(1);
    const doc = parse(r.stdout) as unknown as Doc;
    expect(files(doc)).toEqual(['secret.txt|aws-access']);
    expect(doc.repoControls?.present).toEqual(['.gitignore', 'sub/.gitignore']);
  });

  it('a .gitattributes vendored mark: the finding is reported and the .gitattributes is listed', async () => {
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

  itPosix('runs only config, rev-parse, ls-tree and cat-file, with the config read first', () => {
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
    expect([...new Set(subs)].sort()).toEqual(['cat-file', 'config', 'ls-tree', 'rev-parse']);
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
