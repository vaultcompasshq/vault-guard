import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { handleFatalError } from '../../cli';

/**
 * Exit 1 means findings only. Usage errors (an unknown option, an unknown
 * --format value) and an unexpected crash are "could not run", exit 2.
 */
describe('usage errors and crashes exit 2, never 1', () => {
  const cliEntry = path.join(__dirname, '..', '..', '..', 'dist', 'cli-entry.js');
  let workdir: string;

  const run = (args: string[]) =>
    spawnSync(process.execPath, [cliEntry, ...args], { cwd: workdir, encoding: 'utf-8' });

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  beforeEach(() => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-usage-'));
    fs.writeFileSync(path.join(workdir, 'a.ts'), 'const x = 1;\n');
  });

  afterEach(() => {
    fs.rmSync(workdir, { recursive: true, force: true });
  });

  it('scan . --bogus exits 2', () => {
    const proc = run(['scan', '.', '--bogus']);
    expect(proc.status).toBe(2);
    expect(proc.stderr).toMatch(/unknown option/i);
  });

  it('an unknown --format value exits 2 instead of falling back to text', () => {
    const proc = run(['scan', '.', '--format', 'bogus']);
    expect(proc.status).toBe(2);
    expect(proc.stderr).toMatch(/format/i);
    expect(proc.stdout).not.toMatch(/SUCCESS/);
  });

  it('scan --help exits 0', () => {
    expect(run(['scan', '--help']).status).toBe(0);
  });

  it('--version exits 0', () => {
    expect(run(['--version']).status).toBe(0);
  });

  it('-h, --help and the help subcommand exit 0 and print usage', () => {
    for (const args of [['-h'], ['--help'], ['help'], ['help', 'scan']]) {
      const proc = run(args);
      expect(proc.status).toBe(0);
      expect(proc.stdout).toMatch(/Usage:/);
    }
  });

  it('a missing required option exits 2', () => {
    const proc = run(['data', 'export']);
    expect(proc.status).toBe(2);
    expect(proc.stderr).toMatch(/required option/i);
  });

  it('an unknown command exits 2', () => {
    expect(run(['nosuchcommand']).status).toBe(2);
  });

  it('a clean scan still exits 0', () => {
    expect(run(['scan', '.']).status).toBe(0);
  });

  describe('handleFatalError', () => {
    const original = process.exitCode;
    afterEach(() => {
      process.exitCode = original;
      jest.restoreAllMocks();
    });

    it('a thrown non-ConfigError exits 2', () => {
      jest.spyOn(console, 'error').mockImplementation(() => undefined);
      process.exitCode = 0;

      handleFatalError(new TypeError('boom'));

      expect(process.exitCode).toBe(2);
    });
  });
});
