import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { GitError, SecretScanner } from '@vaultcompass/vault-guard-core';
import { scanWorkspaceDirectory } from '../workspace-scan';

describe('scanWorkspaceDirectory', () => {
  it('returns empty when no secrets in temp workspace', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-'));
    try {
      fs.writeFileSync(path.join(dir, 'readme.txt'), 'hello world\n', 'utf8');
      const scanner = new SecretScanner();
      const { results, filesScanned, bytesScanned, overBudget } = await scanWorkspaceDirectory(
        dir,
        scanner,
      );
      expect(results).toEqual([]);
      expect(filesScanned).toBe(1);
      expect(bytesScanned).toBeGreaterThan(0);
      expect(overBudget).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('lists an oversized file as not scanned, and does not count it as scanned', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-big-'));
    try {
      fs.writeFileSync(path.join(dir, 'ok.txt'), 'hello\n', 'utf8');
      fs.writeFileSync(path.join(dir, 'huge.txt'), Buffer.alloc(33 * 1024 * 1024, 0x61));
      const { filesScanned, bytesScanned, unscannable } = await scanWorkspaceDirectory(
        dir,
        new SecretScanner(),
      );
      expect(unscannable).toHaveLength(1);
      expect(unscannable[0].file).toContain('huge.txt');
      expect(unscannable[0].reason).toMatch(/not scanned/);
      expect(filesScanned).toBe(1);
      expect(bytesScanned).toBeLessThan(1024);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  /**
   * The agent-driven MCP surface gets the same post-hoc scan budget the CLI has.
   * It cannot preempt a synchronous runaway scan; it reports that the file's
   * result is not trusted so an agent is not handed a silent "clean".
   */
  it('reports a file whose scan exceeds the budget', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-budget-'));
    try {
      fs.writeFileSync(path.join(dir, 'slow.txt'), 'nothing to see\n', 'utf8');
      const busy = (ms: number): void => {
        const end = Date.now() + ms;
        while (Date.now() < end) { /* deliberately synchronous */ }
      };
      const slowScanner = {
        scanContent: () => { busy(60); return []; },
        scan: () => { busy(60); return []; },
      } as unknown as SecretScanner;

      const { overBudget } = await scanWorkspaceDirectory(dir, slowScanner, 10, [], 10);

      expect(overBudget).toHaveLength(1);
      expect(overBudget[0].file).toContain('slow.txt');
      expect(overBudget[0].budget_ms).toBe(10);
      expect(overBudget[0].elapsed_ms).toBeGreaterThanOrEqual(10);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  describe('inside a git repository: the same file set as the CLI', () => {
    // Joined at runtime so no committed fragment matches a rule on its own.
    const FAKE_KEY = ['sk-ant-', 'api03-', 'Kq7mZr2xVb9nTd4wHs6yLc3p', 'Jf8gRu5eNa1vBt0iOy7kPd2s', 'Xw4hEj6uCi3q'].join('');
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const itPosix = process.platform === 'win32' ? it.skip : it;
    let dir: string;

    function git(args: string[]): void {
      execFileSync('git', args, { cwd: dir, stdio: 'ignore' });
    }

    beforeEach(() => {
      dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-git-')));
      git(['init', '-q', '-b', 'main']);
      git(['config', 'user.email', 'test@example.invalid']);
      git(['config', 'user.name', 'Test']);
      git(['config', 'commit.gpgsign', 'false']);
    });

    afterEach(() => {
      try {
        fs.chmodSync(path.join(dir, 'locked'), 0o755);
      } catch {
        /* not created in every case */
      }
      fs.rmSync(dir, { recursive: true, force: true });
    });

    it('scans a tracked file that .gitignore matches', async () => {
      fs.writeFileSync(path.join(dir, '.gitignore'), '.env\n');
      fs.writeFileSync(path.join(dir, '.env'), `ANTHROPIC_API_KEY=${FAKE_KEY}\n`);
      git(['add', '-A', '-f']);
      git(['commit', '-q', '-m', 'base']);
      const { results } = await scanWorkspaceDirectory(dir, new SecretScanner());
      expect(results.map(r => path.basename(r.file))).toEqual(['.env']);
    });

    itPosix('lists a tracked file it cannot examine as not scanned', async () => {
      if (isRoot) return;
      fs.writeFileSync(path.join(dir, 'ok.txt'), 'hello\n');
      fs.mkdirSync(path.join(dir, 'locked'));
      fs.writeFileSync(path.join(dir, 'locked', 'creds.txt'), 'hello\n');
      git(['add', '-A']);
      git(['commit', '-q', '-m', 'base']);
      fs.chmodSync(path.join(dir, 'locked'), 0o000);
      const { unscannable } = await scanWorkspaceDirectory(dir, new SecretScanner());
      expect(unscannable).toHaveLength(1);
      expect(unscannable[0].kind).toBe('read_error');
      expect(unscannable[0].file).toContain('creds.txt');
    });

    it('fails with a git error, rather than walking, when git cannot read the repository', async () => {
      fs.rmSync(path.join(dir, '.git'), { recursive: true, force: true });
      // A .git file pointing nowhere: git refuses, and the file set must not
      // quietly fall back to a walk that skips tracked files.
      fs.writeFileSync(path.join(dir, '.git'), 'gitdir: ./no-such-git-dir\n');
      fs.writeFileSync(path.join(dir, 'ok.txt'), 'hello\n');
      await expect(scanWorkspaceDirectory(dir, new SecretScanner())).rejects.toThrow(GitError);
    });
  });
});

/**
 * Design 2026-10-12, U19: the MCP workspace scan reads tracked content from
 * the index blob, as a plain CLI scan does, so a head-side working-tree-
 * encoding cannot hide a key from an editor any more than from CI.
 */
describe('scanWorkspaceDirectory reads tracked content from git (U19)', () => {
  const itPosix = process.platform === 'win32' ? it.skip : it;
  const key = ['AKIA', 'Q7MZR2XVB9', 'NTD4WH'].join('');
  const run = (cwd: string, args: string[]): string =>
    execFileSync('git', args, { cwd, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] });

  itPosix('U19: scan_workspace on a re-encoding clone returns the finding', async () => {
    const src = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-u19-src-')));
    const parent = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-u19-')));
    try {
      run(src, ['init', '-q', '-b', 'main']);
      run(src, ['config', 'user.email', 'test@example.invalid']);
      run(src, ['config', 'user.name', 'Test']);
      fs.mkdirSync(path.join(src, 'src'));
      fs.writeFileSync(path.join(src, 'src', 'leak.ts'), `export const k = "${key}";\n`);
      run(src, ['add', '-A']);
      run(src, ['commit', '-q', '-m', 'one']);
      fs.writeFileSync(path.join(src, '.gitattributes'), 'src/leak.ts working-tree-encoding=UTF-16LE\n');
      run(src, ['add', '.gitattributes']);
      run(src, ['commit', '-q', '-m', 'two']);
      run(parent, ['clone', '-q', src, 'c']);
      const clone = path.join(parent, 'c');
      expect(fs.readFileSync(path.join(clone, 'src', 'leak.ts'))[1]).toBe(0);
      const { results } = await scanWorkspaceDirectory(clone, new SecretScanner());
      expect(results.map(r => path.relative(clone, r.file))).toEqual([path.join('src', 'leak.ts')]);
      expect(results[0].matches[0].source).toBe('index');
    } finally {
      fs.rmSync(src, { recursive: true, force: true });
      fs.rmSync(parent, { recursive: true, force: true });
    }
  });
});
