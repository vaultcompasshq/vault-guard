import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { scanCommand } from '../commands/scan';

/**
 * A staged submodule pointer must not block the commit.
 *
 * `git diff --cached --name-only` lists a submodule pointer bump as an
 * ordinary path, but its index entry is a gitlink (mode 160000), not a blob:
 * `git show :<path>` answers "fatal: bad object". Once an unreadable staged
 * entry became fatal, every ordinary submodule bump started exiting 2, and
 * the installed hook told the developer that secrets had been detected and
 * offered `--no-verify`. A gitlink is not a file the scanner failed to read;
 * there is no content there to scan, and nothing to warn about.
 *
 * The gitlink is created with `update-index --cacheinfo` rather than
 * `submodule add`: it produces the identical mode-160000 index entry, which
 * is the whole trigger, without needing a nested checkout, a `.gitmodules`
 * file, or `protocol.file.allow` for a local-path submodule URL.
 */
describe('scan --staged ignores a staged submodule pointer', () => {
  const SECRET =
    'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n';

  let repo: string;
  let stdout: string[];
  let stderr: string[];
  const originalCwd = process.cwd();

  const stageGitlink = (at: string): void => {
    // Any well-formed object id works: git records the pointer without
    // resolving it, which is exactly what a bumped-but-not-fetched
    // submodule pointer looks like in the index.
    const oid = 'a'.repeat(40);
    execSync(`git update-index --add --cacheinfo 160000,${oid},${at}`, {
      cwd: repo,
      stdio: 'ignore',
    });
  };

  beforeEach(() => {
    repo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-submodule-')));
    execSync('git init -q', { cwd: repo, stdio: 'ignore' });
    execSync('git config user.email "test@example.com"', { cwd: repo, stdio: 'ignore' });
    execSync('git config user.name "Test"', { cwd: repo, stdio: 'ignore' });
    execSync('git config --local core.hooksPath hooks', { cwd: repo, stdio: 'ignore' });
    process.chdir(repo);

    stdout = [];
    stderr = [];
    jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdout.push(args.map(String).join(' '));
    });
    // Captured, not discarded: the incomplete-scan report writes through
    // console.error, so asserting its absence against stdout alone would be
    // an assertion that can never fail.
    jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(' '));
    });
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      stdout.push(String(chunk));
      return true;
    });
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      stderr.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.chdir(originalCwd);
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('lets a commit through when only a submodule pointer is staged', async () => {
    stageGitlink('vendor/sub');

    const code = await scanCommand('.', 'text', true);

    // The incomplete-scan report goes to stderr, so that is where its
    // absence has to be asserted. A gitlink must produce no warning of any
    // kind either: it is not a file that failed to scan, it is not a file.
    expect(stderr.join('\n')).not.toMatch(/INCOMPLETE/);
    expect(stderr.join('\n')).not.toMatch(/warning/i);
    expect(code).toBe(0);
  });

  it('still finds a real staged secret sitting beside the submodule', async () => {
    stageGitlink('vendor/sub');
    fs.writeFileSync(path.join(repo, 'leak.env'), SECRET);
    execSync('git add leak.env', { cwd: repo, stdio: 'ignore' });

    const code = await scanCommand('.', 'text', true);

    expect(stdout.join('\n')).toContain('leak.env');
    expect(code).toBe(1);
  });
});
