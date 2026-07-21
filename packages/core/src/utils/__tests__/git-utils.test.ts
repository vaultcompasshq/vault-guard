import fs from 'fs';
import os from 'os';
import path from 'path';
import { execSync } from 'child_process';
import { getGitStagedFilePaths, readGitIndexFile } from '../git-utils';

describe('git-utils staged index', () => {
  let repo: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    repo = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-git-utils-'));
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
});
