import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { scanCommand } from '../commands/scan';

/**
 * A staged file vault-guard could not examine must never be reported as
 * clean.
 *
 * Before this fix every per-file read failure on the staged path was
 * downgraded to a `file.read_error` diagnostic, printed as "N warning(s)",
 * and the run still ended with "SUCCESS: No secrets found" and exit 0. That
 * is a fail-open in the one code path whose entire job is to fail closed:
 * the staged list is a closed enumeration of exactly what is about to be
 * committed, so a file missing from the scan is a file the gate did not
 * check, not a file it decided to skip.
 *
 * The trigger used here is a genuinely unreadable index entry -- the loose
 * object backing a staged blob is removed, as a pruned or corrupted object
 * store would leave it -- rather than a mocked failure, so the test exercises
 * git's real error path.
 */
describe('scan --staged fails closed on an unreadable staged file', () => {
  const SECRET =
    'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n';

  let repo: string;
  let stdout: string[];
  let stderr: string[];
  const originalCwd = process.cwd();

  const captured = (): string => stdout.join('\n');
  const capturedErr = (): string => stderr.join('\n');

  beforeEach(() => {
    repo = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), 'vg-staged-unreadable-')),
    );
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
    jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
      stderr.push(args.map(String).join(' '));
    });
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

  /** Stage `name` with the given content, then destroy the blob it points at. */
  const stageThenBreak = (name: string, content: string): void => {
    fs.writeFileSync(path.join(repo, name), content);
    execSync(`git add ${name}`, { cwd: repo, stdio: 'ignore' });
    const entry = execSync(`git ls-files -s ${name}`, { cwd: repo, encoding: 'utf-8' });
    const sha = entry.trim().split(/\s+/)[1];
    fs.unlinkSync(path.join(repo, '.git', 'objects', sha.slice(0, 2), sha.slice(2)));
  };

  it('exits non-zero and claims no success in text mode', async () => {
    stageThenBreak('leak.env', SECRET);

    const code = await scanCommand('.', 'text', true);

    expect(captured()).not.toMatch(/SUCCESS/);
    expect(code).toBe(2);
  });

  it('names the file and the reason it could not be read', async () => {
    stageThenBreak('leak.env', SECRET);

    await scanCommand('.', 'text', true);

    expect(capturedErr()).toContain('leak.env');
    expect(capturedErr()).toMatch(/could not be read|could not examine/i);
  });

  it('still reports secrets found in the staged files that did read', async () => {
    stageThenBreak('broken.env', SECRET);
    // Deliberately DIFFERENT content: identical bytes would hash to the same
    // blob, and staging the second file would restore the very loose object
    // stageThenBreak just deleted.
    fs.writeFileSync(
      path.join(repo, 'readable.env'),
      'OTHER_KEY=sk-ant-api03-zyxwvutsrqponmlkjihgfedcba9876543210ZYXWVUTSRQPONMLKJIHGFEDCBA\n',
    );
    execSync('git add readable.env', { cwd: repo, stdio: 'ignore' });

    const code = await scanCommand('.', 'text', true);

    expect(captured()).toContain('readable.env');
    // The unreadable file wins the exit code: a partial scan is not a pass,
    // and it is not the ordinary "found a secret" failure either.
    expect(code).toBe(2);
  });

  it('reports the unreadable file in JSON and exits non-zero', async () => {
    stageThenBreak('leak.env', SECRET);

    const code = await scanCommand('.', 'json', true);

    const body = JSON.parse(captured().trim()) as {
      run?: { unscannable_files?: number };
      diagnostics?: Array<{ code: string; severity: string }>;
    };
    expect(body.run?.unscannable_files).toBe(1);
    expect(body.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'file.read_error', severity: 'error' }),
      ]),
    );
    expect(code).toBe(2);
  });

  it('reports the unreadable file in SARIF and exits non-zero', async () => {
    stageThenBreak('leak.env', SECRET);

    const code = await scanCommand('.', 'sarif', true);

    const body = JSON.parse(captured().trim()) as {
      runs: Array<{
        properties?: { vault_guard_run?: { unscannable_files?: number } };
        tool: { driver: { notifications?: Array<{ id: string; level: string }> } };
      }>;
    };
    expect(body.runs[0].properties?.vault_guard_run?.unscannable_files).toBe(1);
    expect(body.runs[0].tool.driver.notifications).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'file.read_error', level: 'error' }),
      ]),
    );
    expect(code).toBe(2);
  });
});

/**
 * The scope decision, pinned deliberately.
 *
 * A directory walk is an OPEN set discovered by the scanner, not a closed
 * list of what is about to be committed. Unreadable entries in it are
 * ordinary on a real developer machine (root-owned caches, half-removed
 * node_modules, sockets, other users' files), and making them fatal would
 * turn `vault-guard scan .` into a command that refuses to run for reasons
 * the user cannot fix -- whose predictable outcome is that people stop
 * running it, which is strictly worse for the thing this tool defends. So
 * the directory path keeps DIAGNOSING: the unreadable file is reported and
 * counted, and the gate's exit code still reflects the findings only.
 *
 * The fail-closed promise is load-bearing on the staged path, and that is
 * where it is enforced.
 */
describe('directory scan keeps diagnosing an unreadable file', () => {
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  let dir: string;
  let locked: string;
  let stdout: string[];
  const originalCwd = process.cwd();

  beforeEach(() => {
    dir = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-dir-unreadable-')));
    locked = path.join(dir, 'locked.env');
    fs.writeFileSync(path.join(dir, 'clean.ts'), 'export const x = 1;\n');
    fs.writeFileSync(locked, 'SECRET=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n');
    if (!isRoot) fs.chmodSync(locked, 0o000);
    process.chdir(dir);

    stdout = [];
    jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      stdout.push(args.map(String).join(' '));
    });
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      stdout.push(String(chunk));
      return true;
    });
    jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.chdir(originalCwd);
    if (!isRoot) fs.chmodSync(locked, 0o644);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('does not fail the gate, and counts the file it could not read', async () => {
    if (isRoot) return; // root reads the 0o000 file, so there is nothing to diagnose

    const code = await scanCommand('.', 'json', false);

    const body = JSON.parse(stdout.join('\n').trim()) as {
      run?: { unscannable_files?: number };
      diagnostics?: Array<{ code: string; severity: string }>;
    };
    expect(body.run?.unscannable_files).toBe(1);
    expect(body.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'file.read_error', severity: 'error' }),
      ]),
    );
    expect(code).toBe(0);
  });
});
