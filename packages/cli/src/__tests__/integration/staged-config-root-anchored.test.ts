import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * The config a staged run loads must come from the same place its paths are
 * anchored: the repository root.
 *
 * Anchoring the staged run at the repository root left one base behind.
 * `loadConfig` still walked up from the CALLER's directory, so a
 * `.vault-guard.json` in a subdirectory was loaded while its `ignore.paths`
 * were matched against the root. `ignore.paths: ["fixtures/**"]` written by
 * the author of `sub/.vault-guard.json` then meant `sub/fixtures/` to them
 * and `<root>/fixtures/` to the matcher: running the hook from `sub/`
 * skipped a root-level staged secret the author never intended to exempt,
 * and scanned the directory they did. A pattern that silently exempts files
 * nobody exempted is the same shape of fail-open this branch exists to
 * remove.
 *
 * The consequence, which is intended and not a gap: a config (or baseline)
 * that lives only in a subdirectory is NOT consulted on a staged run at all.
 * The staged file set is repository-wide, so the rules applied to it have to
 * be repository-wide too; a per-directory config cannot govern files outside
 * its own directory. A directory scan is unaffected and still loads the
 * config from the cwd it was pointed at.
 */
describe('staged config is loaded from the repository root', () => {
  const packageRoot = path.join(__dirname, '..', '..', '..');
  const cliEntry = path.join(packageRoot, 'dist', 'cli-entry.js');

  const SECRET =
    'ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWX\n';

  let repo: string;
  let sub: string;

  beforeAll(() => {
    if (!fs.existsSync(cliEntry)) {
      throw new Error(`Built CLI missing at ${cliEntry}. Run pnpm build before tests.`);
    }
  });

  beforeEach(() => {
    repo = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-staged-config-')));
    sub = path.join(repo, 'sub');
    spawnSync('git', ['init', '-q', '-b', 'main'], { cwd: repo });
    spawnSync('git', ['config', 'user.email', 'test@example.com'], { cwd: repo });
    spawnSync('git', ['config', 'user.name', 'Test'], { cwd: repo });
    spawnSync('git', ['config', 'core.hooksPath', 'hooks'], { cwd: repo });

    // A staged secret under `fixtures/` at the ROOT, and another under
    // `fixtures/` inside the subdirectory. "fixtures/**" names a different
    // one of these depending on which directory it is resolved against.
    fs.mkdirSync(path.join(repo, 'fixtures'), { recursive: true });
    fs.writeFileSync(path.join(repo, 'fixtures', 'root-sample.ts'), SECRET);
    fs.mkdirSync(path.join(sub, 'fixtures'), { recursive: true });
    fs.writeFileSync(path.join(sub, 'fixtures', 'sub-sample.ts'), SECRET);
  });

  afterEach(() => {
    fs.rmSync(repo, { recursive: true, force: true });
  });

  const writeConfig = (dir: string): void => {
    fs.writeFileSync(
      path.join(dir, '.vault-guard.json'),
      JSON.stringify({ ignore: { paths: ['fixtures/**'] } }, null, 2),
    );
  };

  const stageAll = (): void => {
    spawnSync('git', ['add', '-A'], { cwd: repo });
  };

  const scannedFiles = (cwd: string, args: string[]): string[] => {
    const proc = spawnSync(process.execPath, [cliEntry, 'scan', ...args, '--format', 'json'], {
      cwd,
      encoding: 'utf-8',
      maxBuffer: 20 * 1024 * 1024,
    });
    const body = JSON.parse(proc.stdout.trim()) as { results: Array<{ file: string }> };
    return body.results.map(r => r.file).sort();
  };

  it('does not let a subdirectory config exempt a root-level staged secret', () => {
    writeConfig(sub);
    stageAll();

    // The pattern in sub/.vault-guard.json must never be what decides
    // whether <root>/fixtures/root-sample.ts gets scanned.
    expect(scannedFiles(sub, ['--staged'])).toContain('fixtures/root-sample.ts');
  });

  it('reports the same staged file set from the root and from the subdirectory', () => {
    writeConfig(sub);
    stageAll();

    expect(scannedFiles(sub, ['--staged'])).toEqual(scannedFiles(repo, ['--staged']));
  });

  it('still honours a root-level config from either directory', () => {
    writeConfig(repo);
    stageAll();

    const fromRoot = scannedFiles(repo, ['--staged']);
    expect(fromRoot).not.toContain('fixtures/root-sample.ts');
    expect(scannedFiles(sub, ['--staged'])).toEqual(fromRoot);
  });

  it('still loads a directory scan config from the directory it was pointed at', () => {
    writeConfig(sub);

    // Not --staged: a directory walk is anchored at its target, so the
    // nearest config walking up from there is the right one, and
    // "fixtures/**" means what its author meant.
    expect(scannedFiles(sub, ['.'])).not.toContain('fixtures/sub-sample.ts');
  });
});
