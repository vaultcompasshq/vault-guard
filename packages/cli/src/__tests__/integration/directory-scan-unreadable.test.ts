import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanCommand } from '../../commands/scan';

/**
 * The scope decision for the fail-closed rule, pinned deliberately.
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
 * where it is enforced -- see `staged-unreadable-fail-closed.test.ts`.
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
