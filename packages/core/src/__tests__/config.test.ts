import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadConfig } from '../config';
import { ConfigError } from '../errors';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Create a temp directory tree and return the root path. */
function makeTempDir(label: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `vg-config-test-${label}-`));
}

/** Recursively remove a temp dir. */
function rmrf(dir: string): void {
  fs.rmSync(dir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('loadConfig', () => {
  // Keep refs to clean up in afterEach.
  const roots: string[] = [];
  afterEach(() => {
    for (const r of roots.splice(0)) rmrf(r);
  });

  // --- happy path -----------------------------------------------------------

  it('loads a valid config from startDir', () => {
    const root = makeTempDir('valid');
    roots.push(root);
    fs.writeFileSync(
      path.join(root, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 2.5 }),
    );
    const cfg = loadConfig(root);
    expect(cfg.entropy_threshold).toBe(2.5);
  });

  it('returns empty object when no config file exists', () => {
    const root = makeTempDir('empty');
    roots.push(root);
    const cfg = loadConfig(root);
    expect(cfg).toEqual({});
  });

  // --- error handling -------------------------------------------------------

  it('throws ConfigError on malformed JSON, with the file path in the message', () => {
    const root = makeTempDir('broken');
    roots.push(root);
    const cfgPath = path.join(root, '.vault-guard.json');
    fs.writeFileSync(cfgPath, '{ this is not json }');

    expect(() => loadConfig(root)).toThrow(ConfigError);

    try {
      loadConfig(root);
    } catch (e) {
      expect(e).toBeInstanceOf(ConfigError);
      const err = e as ConfigError;
      expect(err.filePath).toBe(cfgPath);
      expect(err.message).toContain(cfgPath);
    }
  });

  // --- .git boundary --------------------------------------------------------

  it('walks up to .git boundary and finds config in repo root', () => {
    // Structure:
    //   root/
    //     .git/
    //     .vault-guard.json   <- should be found
    //     sub/dir/            <- startDir
    const root = makeTempDir('boundary');
    roots.push(root);
    fs.mkdirSync(path.join(root, '.git'));
    fs.writeFileSync(
      path.join(root, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 1.0 }),
    );
    const startDir = path.join(root, 'sub', 'dir');
    fs.mkdirSync(startDir, { recursive: true });

    const cfg = loadConfig(startDir);
    expect(cfg.entropy_threshold).toBe(1.0);
  });

  it('does NOT ascend past the .git boundary', () => {
    // Structure:
    //   root/
    //     .vault-guard.json   <- ABOVE .git, must not be loaded
    //     project/
    //       .git/             <- boundary
    //       deep/sub/         <- startDir
    const root = makeTempDir('above-boundary');
    roots.push(root);
    fs.writeFileSync(
      path.join(root, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 9.9 }),
    );
    const project = path.join(root, 'project');
    fs.mkdirSync(path.join(project, '.git'), { recursive: true });
    const startDir = path.join(project, 'deep', 'sub');
    fs.mkdirSync(startDir, { recursive: true });

    const cfg = loadConfig(startDir);
    // The above-boundary config must be ignored; no config in [project..project],
    // so result should be empty.
    expect(cfg).toEqual({});
  });

  it('does NOT load from parent when there is no .git anywhere (only startDir searched)', () => {
    // Without a .git root, search stops at startDir.
    // Structure:
    //   root/
    //     .vault-guard.json   <- must NOT be loaded
    //     child/              <- startDir (no config here)
    const root = makeTempDir('no-git');
    roots.push(root);
    fs.writeFileSync(
      path.join(root, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 7.7 }),
    );
    const child = path.join(root, 'child');
    fs.mkdirSync(child);

    const cfg = loadConfig(child);
    expect(cfg).toEqual({});
  });

  it('does NOT load from parent when there is no .git, but loads from startDir itself', () => {
    const root = makeTempDir('no-git-self');
    roots.push(root);
    const child = path.join(root, 'child');
    fs.mkdirSync(child);
    fs.writeFileSync(
      path.join(child, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 5.5 }),
    );

    const cfg = loadConfig(child);
    expect(cfg.entropy_threshold).toBe(5.5);
  });

  it('treats a .git FILE (git worktree) as the repo boundary', () => {
    // In git worktrees, .git is a plain file containing "gitdir: /path/to/..."
    // The trust boundary is the directory containing that file.
    // Structure:
    //   root/
    //     .git               <- FILE, not directory
    //     .vault-guard.json  <- should be found (within boundary)
    //     sub/dir/           <- startDir
    const root = makeTempDir('worktree');
    roots.push(root);
    // Write .git as a file (like git worktree does)
    fs.writeFileSync(path.join(root, '.git'), 'gitdir: /some/other/path/.git/worktrees/test');
    fs.writeFileSync(
      path.join(root, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 3.3 }),
    );
    const startDir = path.join(root, 'sub', 'dir');
    fs.mkdirSync(startDir, { recursive: true });

    const cfg = loadConfig(startDir);
    expect(cfg.entropy_threshold).toBe(3.3);
  });

  it('prefers config closest to startDir when multiple exist within boundary', () => {
    // Structure:
    //   root/
    //     .git/
    //     .vault-guard.json   <- entropy 1.0 (root)
    //     sub/
    //       .vault-guard.json <- entropy 2.0 (closer)
    //       dir/              <- startDir
    const root = makeTempDir('closest');
    roots.push(root);
    fs.mkdirSync(path.join(root, '.git'));
    fs.writeFileSync(
      path.join(root, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 1.0 }),
    );
    const sub = path.join(root, 'sub');
    fs.mkdirSync(sub);
    fs.writeFileSync(
      path.join(sub, '.vault-guard.json'),
      JSON.stringify({ entropy_threshold: 2.0 }),
    );
    const startDir = path.join(sub, 'dir');
    fs.mkdirSync(startDir);

    const cfg = loadConfig(startDir);
    // Nearest config (sub/) wins.
    expect(cfg.entropy_threshold).toBe(2.0);
  });
});
