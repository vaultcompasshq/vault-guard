import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Every base a staged run needs is the REPOSITORY ROOT, not the caller's
 * working directory.
 *
 * Making files above the cwd visible for the first time exposed this: the
 * paths were correct, but every base used to render, serialize, ignore-match
 * and fingerprint them was still `process.cwd()`. A staged file above the
 * cwd therefore fell out of `path.relative` and came back absolute, which
 * put the developer's home directory and username into JSON `file` and into
 * SARIF `uri` while that uri still claimed `uriBaseId: "%SRCROOT%"` -- not a
 * legal relative reference, and unresolvable in code scanning. It also made
 * two things depend on where the hook happened to be invoked from: an
 * `ignore` pattern matched from the root and not from a subdirectory, and a
 * baseline fingerprint changed with the cwd, so baselines became specific to
 * one machine's layout.
 *
 * Driven through the built CLI because the whole point is the child
 * process's own working directory.
 */
describe('staged scan paths are relative to the repository root', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');

  const SECRET =
    'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n';

  let repo: string;
  let deep: string;

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  beforeEach(() => {
    repo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-staged-base-')));
    deep = path.join(repo, 'pkg', 'deep');
    spawnSync('git', ['init', '-q', '-b', 'main'], { cwd: repo });
    spawnSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repo });
    spawnSync('git', ['config', 'user.name', 'Test'], { cwd: repo });
    spawnSync('git', ['config', 'core.hooksPath', 'hooks'], { cwd: repo });
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, 'placeholder.ts'), 'export const x = 1;\n');
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  const run = (cwd: string, extraArgs: string[] = []) =>
    spawnSync(process.execPath, [cliEntry, 'scan', '--staged', ...extraArgs], {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });

  /** Stage a secret at the repository ROOT, above the subdirectory we run from. */
  const stageRootSecret = (): void => {
    fs.writeFileSync(path.join(repo, 'top.env'), SECRET);
    spawnSync('git', ['add', '-A'], { cwd: repo });
  };

  it('prints a repository-relative path in text output', () => {
    stageRootSecret();

    const proc = run(deep);

    expect(proc.stdout).toContain('top.env');
    expect(proc.stdout).not.toContain(repo);
    expect(proc.status).toBe(1);
  });

  it('emits a repository-relative file path in JSON', () => {
    stageRootSecret();

    const proc = run(deep, ['--format', 'json']);
    const body = JSON.parse(proc.stdout.trim()) as { results: Array<{ file: string }> };

    expect(body.results.map(r => r.file)).toEqual(['top.env']);
    expect(proc.stdout).not.toContain(repo);
  });

  it('emits a repository-relative uri in SARIF, matching its %SRCROOT% claim', () => {
    stageRootSecret();

    const proc = run(deep, ['--format', 'sarif']);
    const body = JSON.parse(proc.stdout.trim()) as {
      runs: Array<{
        results: Array<{
          locations: Array<{
            physicalLocation: { artifactLocation: { uri: string; uriBaseId: string } };
          }>;
        }>;
      }>;
    };
    const loc = body.runs[0].results[0].locations[0].physicalLocation.artifactLocation;

    expect(loc.uri).toBe('top.env');
    expect(loc.uriBaseId).toBe('%SRCROOT%');
    expect(proc.stdout).not.toContain(repo);
  });

  it('applies an ignore pattern the same way from the root and from a subdirectory', () => {
    fs.mkdirSync(path.join(repo, 'fixtures'));
    fs.writeFileSync(path.join(repo, 'fixtures', 'leak.env'), SECRET);
    fs.writeFileSync(
      path.join(repo, '.vault-guard.json'),
      JSON.stringify({ ignore: { paths: ['fixtures/**'] } }, null, 2),
    );
    spawnSync('git', ['add', '-A'], { cwd: repo });

    const fromRoot = run(repo);
    const fromSub = run(deep);

    expect(fromRoot.status).toBe(0);
    expect(fromSub.status).toBe(fromRoot.status);
  });

  it('fingerprints a staged finding identically from the root and from a subdirectory', () => {
    stageRootSecret();

    const fingerprintsOf = (cwd: string): string[] => {
      const proc = run(cwd, ['--format', 'json']);
      const body = JSON.parse(proc.stdout.trim()) as {
        results: Array<{ matches: Array<{ fingerprint: string }> }>;
      };
      return body.results.flatMap(r => r.matches.map(m => m.fingerprint));
    };

    const fromRoot = fingerprintsOf(repo);
    expect(fromRoot).toHaveLength(1);
    expect(fingerprintsOf(deep)).toEqual(fromRoot);
  });
});
