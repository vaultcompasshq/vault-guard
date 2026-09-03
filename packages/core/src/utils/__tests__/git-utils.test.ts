import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { getGitStagedFilePaths, readGitIndexFile } from '../git-utils';

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
      'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n',
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
      'const k = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX";\n',
    );

    const fromIndex = readGitIndexFile(repo, 'partial.ts');
    expect(fromIndex).toContain('const clean = true');
    expect(fromIndex).not.toContain('sk-ant-api03');
  });

  it('reads staged blob after worktree delete', () => {
    fs.writeFileSync(path.join(repo, 'gone.env'), 'SECRET=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n');
    execSync('git add gone.env', { cwd: repo, stdio: 'ignore' });
    fs.unlinkSync(path.join(repo, 'gone.env'));

    const blob = readGitIndexFile(repo, 'gone.env');
    expect(blob).toContain('sk-ant-api03');
  });

  describe('with diff.relative set on the repository', () => {
    const SECRET =
      'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n';
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
