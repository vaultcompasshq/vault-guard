import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanCommand } from '../../commands/scan';

/**
 * The scope decision for the fail-closed rule, pinned deliberately.
 *
 * Through 1.9.0 a directory walk kept DIAGNOSING an unreadable file and exited
 * 0, on the theory that unreadable entries in a walked tree are ordinary
 * (root-owned caches, sockets). From 1.9.1 it fails closed like `--staged`: a
 * CI gate judging a repository cannot call a tree clean over a file it could
 * not read. The deliberate way out is the config's `ignore` list, which is
 * counted and reported; see `directory-pr-fail-closed.test.ts`.
 *
 * This lives under `__tests__/integration/` because `pnpm test:windows`
 * excludes that directory. The test turns on `chmod 0o000`, which on Windows
 * sets only the read-only attribute and leaves the file perfectly readable,
 * so the case cannot be made to hold there. The repo's other 0o000 test
 * (`sarif-output.test.ts`) sits here for the same reason.
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

  it('fails closed (exit 2), and counts the file it could not read', async () => {
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
    // 1.9.1: was 0. A tracked file nobody could read is a file nobody checked.
    expect(code).toBe(2);
  });
});
