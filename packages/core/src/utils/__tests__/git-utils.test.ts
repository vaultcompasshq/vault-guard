import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { getGitStagedFilePaths, readGitIndexFile, STAGED_DIFF_ARGV } from '../git-utils';

/**
 * Synthetic Anthropic-shaped key, joined at runtime.
 *
 * A committed provider-key shape trips credential scanners regardless of the
 * value being fake and the file being a test, so no fragment here matches a
 * rule on its own. Same convention as `bench/generate-fixtures.cjs`.
 */
const ANTHROPIC_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

/**
 * The staged listing keeps `diff.relative` from mattering in more than one
 * way: the config is forced off in the argv AND the command runs at the
 * worktree root. That redundancy is deliberate for a pre-commit gate, but a
 * behaviour test can only observe the combination, so deleting the flag
 * would leave every other test green and the belt quietly gone. These
 * assertions are what make the flag load-bearing on its own.
 */
describe('staged diff argv', () => {
  it('forces diff.relative off, before the subcommand', () => {
    const valueAt = STAGED_DIFF_ARGV.indexOf('diff.relative=false');

    expect(valueAt).toBeGreaterThan(0);
    expect(STAGED_DIFF_ARGV[valueAt - 1]).toBe('-c');
    // `git -c key=value <subcommand>`: a `-c` AFTER the subcommand is not a
    // config override at all, it is an argument to the subcommand.
    expect(STAGED_DIFF_ARGV.indexOf('diff')).toBeGreaterThan(valueAt);
  });

  it('forces core.quotePath off, before the subcommand', () => {
    const valueAt = STAGED_DIFF_ARGV.indexOf('core.quotePath=false');

    expect(valueAt).toBeGreaterThan(0);
    expect(STAGED_DIFF_ARGV[valueAt - 1]).toBe('-c');
    expect(STAGED_DIFF_ARGV.indexOf('diff')).toBeGreaterThan(valueAt);
  });

  it('excludes submodule gitlinks, which have no blob to scan', () => {
    expect(STAGED_DIFF_ARGV).toContain('--ignore-submodules=all');
  });
});

describe('git-utils staged index', () => {
  let repo: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    // realpath: `os.tmpdir()` is a symlink on macOS, and git reports the
    // PHYSICAL worktree root. getGitStagedFilePaths now resolves git's output
    // against that root, so it returns physical paths; comparing them against
    // an unresolved fixture path would fail for a reason that has nothing to
    // do with the behaviour under test. Same treatment the init test received
    // for the same reason.
    repo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-git-utils-')));
    execSync('git init -q', { cwd: repo, stdio: 'ignore' });
    execSync('git config user.email "test@example.com"', { cwd: repo, stdio: 'ignore' });
    execSync('git config user.name "Test"', { cwd: repo, stdio: 'ignore' });
    // Isolate from a global core.hooksPath on the machine.
    execSync('git config --local core.hooksPath hooks', { cwd: repo, stdio: 'ignore' });
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(repo, { recursive: true, force: true });
  });

  it('lists staged paths even when the worktree file was deleted (AD)', () => {
    const leak = path.join(repo, 'leak.env');
    fs.writeFileSync(
      leak,
      `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}\n`,
    );
    execSync('git add leak.env', { cwd: repo, stdio: 'ignore' });
    fs.unlinkSync(leak);

    const staged = getGitStagedFilePaths(repo);
    expect(staged).toContain(path.resolve(repo, 'leak.env'));
  });

  it('reads staged blob content from the index, not the worktree', () => {
    const file = path.join(repo, 'partial.ts');
    fs.writeFileSync(file, 'const clean = true;\n');
    execSync('git add partial.ts', { cwd: repo, stdio: 'ignore' });
    // Worktree now has a secret; index still has the clean blob.
    fs.writeFileSync(
      file,
      `const k = "${ANTHROPIC_KEY}";\n`,
    );

    const fromIndex = readGitIndexFile(repo, 'partial.ts');
    expect(fromIndex).toContain('const clean = true');
    expect(fromIndex).not.toContain('sk-ant-api03');
  });

  it('reads staged blob after worktree delete', () => {
    fs.writeFileSync(path.join(repo, 'gone.env'), `SECRET=${ANTHROPIC_KEY}\n`);
    execSync('git add gone.env', { cwd: repo, stdio: 'ignore' });
    fs.unlinkSync(path.join(repo, 'gone.env'));

    const blob = readGitIndexFile(repo, 'gone.env');
    expect(blob).toContain('sk-ant-api03');
  });

  // POSIX only. A filename containing a colon is invalid on Windows (NTFS
  // reserves the colon for alternate data streams), so this file cannot be
  // created or staged there and git rejects the pathspec as outside the
  // repository. The stage-ref steering attack this test guards against
  // therefore cannot occur on Windows, and the fixture cannot be built there.
  const itPosix = process.platform === 'win32' ? it.skip : it;
  itPosix('reads the crafted path own blob, not a stage-ref-steered different one', () => {
    // `git show :<path>` also accepts `:<stage>:<path>`, so a staged file whose
    // repo-relative path begins `0:` would be parsed as stage 0 of the SHORTER
    // name. Staged beside a clean file of that shorter name, the scanner would
    // read the clean content while recording the finding against the crafted
    // path -- a real staged secret committed under a clean bill of health.
    fs.writeFileSync(path.join(repo, 'app.ts'), 'const clean = true;\n');
    fs.writeFileSync(path.join(repo, '0:app.ts'), `const k = "${ANTHROPIC_KEY}";\n`);
    execSync('git add -A', { cwd: repo, stdio: 'ignore' });

    const blob = readGitIndexFile(repo, '0:app.ts');
    // Its OWN content (the secret), never the clean file it could be steered onto.
    expect(blob).toContain('sk-ant-api03');
    expect(blob).not.toContain('const clean = true');
  });

  describe('with diff.relative set on the repository', () => {
    const SECRET =
      `ANTHROPIC_API_KEY=${ANTHROPIC_KEY}\n`;
    let deep: string;

    beforeEach(() => {
      execSync('git config diff.relative true', { cwd: repo, stdio: 'ignore' });
      deep = path.join(repo, 'pkg', 'deep');
      fs.mkdirSync(deep, { recursive: true });
      fs.writeFileSync(path.join(deep, 'staged.ts'), SECRET);
      fs.writeFileSync(path.join(repo, 'top.env'), SECRET);
      execSync('git add -A', { cwd: repo, stdio: 'ignore' });
    });

    it('returns worktree-root paths for a caller standing in a subdirectory', () => {
      expect(getGitStagedFilePaths(deep).sort()).toEqual([
        path.join(deep, 'staged.ts'),
        path.join(repo, 'top.env'),
      ]);
    });

    it('returns the same file set from the root and from a subdirectory', () => {
      expect(getGitStagedFilePaths(deep).sort()).toEqual(getGitStagedFilePaths(repo).sort());
    });

    it('reads a staged blob addressed from a subdirectory', () => {
      expect(readGitIndexFile(deep, path.join(deep, 'staged.ts'))).toContain('sk-ant-api03');
      expect(readGitIndexFile(deep, path.join(repo, 'top.env'))).toContain('sk-ant-api03');
    });
  });
});
