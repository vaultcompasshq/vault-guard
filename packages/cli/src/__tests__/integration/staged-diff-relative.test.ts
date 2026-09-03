import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Regression: `vault-guard scan --staged` must not depend on the caller's
 * working directory, and must not be steerable by ordinary repository config.
 *
 * `diff.relative` is a plain, user-settable repo config. With it on, git
 * makes `git diff --cached --name-only` (a) print paths relative to the
 * process cwd instead of the worktree root and (b) omit every staged path
 * outside that cwd. Both halves are fail-open for a pre-commit gate:
 *   - the omitted files are never scanned at all, with no output of any kind;
 *   - the surviving cwd-relative name is then handed to `git show :<path>`,
 *     whose `:<path>` syntax is worktree-root-relative by definition, so the
 *     blob read fails and the file is not scanned either.
 * The observed result before this fix was "1 warning(s)" followed by
 * "SUCCESS: No secrets found" and exit 0, over a real staged credential.
 *
 * Driven through the built CLI rather than `scanCommand` in-process, because
 * the trigger is the child process's own working directory.
 */
describe('scan --staged ignores diff.relative', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');

  const SECRET =
    'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n';

  let repo: string;

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  beforeEach(() => {
    // realpath: on macOS os.tmpdir() is a symlink, and git reports the
    // physical worktree root, so an unresolved path would make every
    // root-relative comparison in this test spurious.
    repo = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'vg-diff-relative-')),
    );
    spawnSync('git', ['init', '-q', '-b', 'main'], { cwd: repo });
    spawnSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repo });
    spawnSync('git', ['config', 'user.name', 'Test'], { cwd: repo });
    // The whole point of the test.
    spawnSync('git', ['config', 'diff.relative', 'true'], { cwd: repo });

    fs.mkdirSync(path.join(repo, 'pkg', 'deep'), { recursive: true });
    fs.writeFileSync(path.join(repo, 'pkg', 'deep', 'staged.ts'), SECRET, 'utf-8');
    fs.writeFileSync(path.join(repo, 'top.env'), SECRET, 'utf-8');
    spawnSync('git', ['add', '-A'], { cwd: repo });
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  const runStagedScan = (cwd: string, extraArgs: string[] = []) =>
    spawnSync(process.execPath, [cliEntry, 'scan', '--staged', ...extraArgs], {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });

  it('blocks a staged secret when run from a subdirectory', () => {
    const proc = runStagedScan(path.join(repo, 'pkg', 'deep'));

    expect(proc.error).toBeUndefined();
    expect(proc.stdout).not.toMatch(/SUCCESS/);
    expect(proc.stdout).toContain('staged.ts');
    expect(proc.status).toBe(1);
  });

  it('sees staged files outside the subdirectory it is run from', () => {
    const proc = runStagedScan(path.join(repo, 'pkg', 'deep'));

    // Both staged files are in the index; diff.relative used to hide the one
    // above the cwd entirely, with no diagnostic and no exit-code change.
    expect(proc.stdout).toContain('2 file(s) in the index');
    expect(proc.stdout).toContain('top.env');
  });

  it('reports the same staged file set from the root and from a subdirectory', () => {
    const fromRoot = runStagedScan(repo, ['--format', 'json']);
    const fromSub = runStagedScan(path.join(repo, 'pkg', 'deep'), ['--format', 'json']);

    const filesOf = (stdout: string): string[] => {
      const body = JSON.parse(stdout.trim()) as { results: Array<{ file: string }> };
      return body.results.map(r => path.basename(r.file)).sort();
    };

    expect(filesOf(fromSub.stdout)).toEqual(filesOf(fromRoot.stdout));
    expect(filesOf(fromSub.stdout)).toEqual(['staged.ts', 'top.env']);
    expect(fromSub.status).toBe(1);
  });
});
