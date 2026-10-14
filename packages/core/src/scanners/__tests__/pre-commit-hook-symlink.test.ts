import { execFileSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

import { PreCommitHook } from '../pre-commit-hook';

/**
 * The hook installer never writes through a link (design 2026-10-12,
 * section 13, ruled in scope 2026-10-12). For each of the seven write sites,
 * a committed link to a file outside the repository and a dangling link: the
 * outside file is byte-identical (or not created), and the step reports the
 * refusal.
 */

const itPosix = process.platform === 'win32' ? it.skip : it;
const REFUSAL = 'is a symlink, not a regular file; vault-guard does not write through a link';
const FOREIGN = '#!/bin/sh\necho foreign hook\n';

interface Site {
  name: string;
  /** Repository-relative path of the file the step writes. */
  rel: string;
  /** Prepare anything else the site needs before the link is planted. */
  prepare?: (repo: string) => void;
  /** Outside content for the "link to an existing file" variant. */
  outsideText: string;
  run: (hook: PreCommitHook, repo: string) => { success: boolean; message: string };
}

const SITES: Site[] = [
  {
    name: 'native pre-commit',
    rel: '.git/hooks/pre-commit',
    outsideText: FOREIGN,
    run: (h, repo) => h.install({ cwd: repo, manager: 'native' }),
  },
  {
    name: 'native pre-commit.cmd',
    rel: '.git/hooks/pre-commit.cmd',
    outsideText: '@echo foreign\r\n',
    run: (h, repo) => h.install({ cwd: repo, manager: 'native' }),
  },
  {
    name: 'husky append',
    rel: '.husky/pre-commit',
    outsideText: FOREIGN,
    run: (h, repo) => h.install({ cwd: repo, manager: 'husky' }),
  },
  {
    name: 'husky create',
    rel: '.husky/pre-commit',
    outsideText: FOREIGN,
    run: (h, repo) => h.install({ cwd: repo, manager: 'husky' }),
  },
  {
    name: 'husky uninstall rewrite',
    rel: '.husky/pre-commit',
    outsideText: `${FOREIGN}\n# --- vault-guard ---\nvault-guard scan --staged || exit 1\n`,
    run: (h, repo) => h.uninstall({ cwd: repo, manager: 'husky' }),
  },
  {
    name: 'lefthook-local.yml',
    rel: 'lefthook-local.yml',
    outsideText: 'pre-commit:\n  commands: {}\n',
    run: (h, repo) => h.install({ cwd: repo, manager: 'lefthook' }),
  },
  {
    name: '.pre-commit-config.yaml',
    rel: '.pre-commit-config.yaml',
    outsideText: 'repos: []\n',
    run: (h, repo) => h.install({ cwd: repo, manager: 'precommit' }),
  },
];

describe('hook installer and links', () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function repo(): { parent: string; repo: string } {
    const parent = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-hook-link-')));
    dirs.push(parent);
    const r = path.join(parent, 'repo');
    fs.mkdirSync(r);
    execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: r });
    return { parent, repo: r };
  }

  for (const site of SITES) {
    itPosix(`a link to a file outside the repository at the ${site.name} site is refused`, () => {
      const { parent, repo: r } = repo();
      const outside = path.join(parent, 'outside.txt');
      fs.writeFileSync(outside, site.outsideText);
      fs.mkdirSync(path.dirname(path.join(r, site.rel)), { recursive: true });
      fs.symlinkSync(outside, path.join(r, site.rel));
      const result = site.run(new PreCommitHook(), r);
      expect(result.success).toBe(false);
      expect(result.message).toContain(REFUSAL);
      expect(fs.readFileSync(outside, 'utf-8')).toBe(site.outsideText);
      expect(fs.lstatSync(path.join(r, site.rel)).isSymbolicLink()).toBe(true);
    });

    itPosix(`a dangling link at the ${site.name} site is refused and its target not created`, () => {
      const { parent, repo: r } = repo();
      const target = path.join(parent, 'not-yet-there.txt');
      fs.mkdirSync(path.dirname(path.join(r, site.rel)), { recursive: true });
      fs.symlinkSync(target, path.join(r, site.rel));
      const result = site.run(new PreCommitHook(), r);
      if (site.name === 'husky uninstall rewrite') {
        // Nothing to strip from a link to nowhere; what matters is no write.
        expect(fs.existsSync(target)).toBe(false);
        return;
      }
      expect(result.success).toBe(false);
      expect(result.message).toContain(REFUSAL);
      expect(fs.existsSync(target)).toBe(false);
    });
  }

  itPosix('a husky directory that is itself a link is refused', () => {
    const { parent, repo: r } = repo();
    const outsideDir = path.join(parent, 'elsewhere');
    fs.mkdirSync(outsideDir);
    fs.symlinkSync(outsideDir, path.join(r, '.husky'));
    const result = new PreCommitHook().install({ cwd: r, manager: 'husky' });
    expect(result.success).toBe(false);
    expect(result.message).toContain('is a symlink, not a regular file');
    expect(fs.readdirSync(outsideDir)).toEqual([]);
  });

  itPosix('a regular hook file is still written, with mode 0755', () => {
    const { repo: r } = repo();
    fs.mkdirSync(path.join(r, '.husky'));
    fs.writeFileSync(path.join(r, '.husky', 'pre-commit'), FOREIGN, { mode: 0o755 });
    const result = new PreCommitHook().install({ cwd: r, manager: 'husky' });
    expect(result.success).toBe(true);
    const text = fs.readFileSync(path.join(r, '.husky', 'pre-commit'), 'utf-8');
    expect(text.startsWith(FOREIGN)).toBe(true);
    expect(text).toContain('vault-guard scan --staged');
    expect(fs.statSync(path.join(r, '.husky', 'pre-commit')).mode & 0o777).toBe(0o755);
  });
});
