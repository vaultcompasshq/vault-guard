import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import { PreCommitHook } from '@vaultcompass/vault-guard-core';
import {
  applyInit,
  initCommand,
  planInit,
  revertInit,
} from '../commands/init';
import {
  MANIFEST_RELATIVE_PATH,
  defaultVaultGuardConfigJson,
  githubWorkflowYaml,
  templateContentForPath,
} from '../init/templates';
import { readCliVersion } from '../version';

function git(args: string[], cwd: string): void {
  const result = spawnSync('git', args, { cwd, stdio: 'ignore' });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed in ${cwd}`);
  }
}

describe('vault-guard init', () => {
  let testDir: string;
  const originalCwd = process.cwd();

  beforeEach(() => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-init-'));
    git(['init', '-q'], testDir);
    git(['config', '--local', 'core.hooksPath', 'hooks'], testDir);
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  it('dry-run prints manifest without writing files', async () => {
    const code = await initCommand({ cwd: testDir, dryRun: true });
    expect(code).toBe(0);

    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(false);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(false);

    const plan = planInit({ cwd: testDir, dryRun: true });
    expect(plan.ok).toBe(true);
    expect(plan.actions.some(a => a.kind === 'create')).toBe(true);
    expect(plan.actions.some(a => a.path === '.vault-guard.json')).toBe(true);
  });

  it('creates managed files and manifest on first run', async () => {
    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(0);

    expect(fs.readFileSync(path.join(testDir, '.vault-guard.json'), 'utf8')).toBe(
      defaultVaultGuardConfigJson(),
    );
    expect(fs.existsSync(path.join(testDir, '.github/workflows/vault-guard.yml'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, '.vault-guard/mcp-snippet.json'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, '.vault-guard/agent-rules.md'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(true);

    const hook = new PreCommitHook();
    expect(hook.isInstalled({ cwd: testDir, manager: 'native' })).toBe(true);
  });

  it('is idempotent on second run', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);
    const manifestMtime = fs.statSync(path.join(testDir, MANIFEST_RELATIVE_PATH)).mtimeMs;

    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(0);

    const plan = planInit({ cwd: testDir });
    expect(plan.alreadyInitialized).toBe(true);
    expect(fs.statSync(path.join(testDir, MANIFEST_RELATIVE_PATH)).mtimeMs).toBe(manifestMtime);
  });

  it('conflicts when a managed file exists with foreign content', async () => {
    fs.writeFileSync(path.join(testDir, '.vault-guard.json'), '{"foreign": true}\n');

    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(2);

    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(false);
  });

  it('reverts manifest-tracked files and hook', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);
    expect(await initCommand({ cwd: testDir, revert: true })).toBe(0);

    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(false);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(false);

    const hook = new PreCommitHook();
    expect(hook.isInstalled({ cwd: testDir, manager: 'native' })).toBe(false);
  });

  it('revert dry-run does not delete files', async () => {
    expect(await initCommand({ cwd: testDir })).toBe(0);
    expect(await initCommand({ cwd: testDir, revert: true, dryRun: true })).toBe(0);

    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(true);
    expect(fs.existsSync(path.join(testDir, MANIFEST_RELATIVE_PATH))).toBe(true);
  });

  it('emits JSON manifest in --json mode', async () => {
    const logs: string[] = [];
    const spy = jest.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      logs.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      return true;
    });

    try {
      const code = await initCommand({ cwd: testDir, dryRun: true, json: true });
      expect(code).toBe(0);
      const payload = JSON.parse(logs.join(''));
      expect(payload.ok).toBe(true);
      expect(payload.manifestPath).toBe(MANIFEST_RELATIVE_PATH);
      expect(Array.isArray(payload.actions)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('applyInit does not run when plan has conflicts', () => {
    fs.writeFileSync(path.join(testDir, '.vault-guard.json'), 'not-json\n');
    const plan = planInit({ cwd: testDir });
    expect(plan.ok).toBe(false);
    applyInit(plan, { cwd: testDir });
    expect(fs.existsSync(path.join(testDir, '.github/workflows/vault-guard.yml'))).toBe(false);
  });

  it('skip flags omit optional artifacts from the plan', () => {
    const plan = planInit({
      cwd: testDir,
      skipWorkflow: true,
      skipConfig: true,
      skipAgentRules: true,
      skipHook: true,
    });
    expect(plan.actions.map(a => a.path)).not.toContain('.vault-guard.json');
    expect(plan.actions.map(a => a.path)).not.toContain('.github/workflows/vault-guard.yml');
    expect(plan.actions.map(a => a.path)).not.toContain('.vault-guard/mcp-snippet.json');
  });

  it('revertInit fails without manifest', () => {
    const result = revertInit({ cwd: testDir });
    expect(result.ok).toBe(false);
  });

  it('reports not_a_git_repository when hook required outside git', async () => {
    const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-init-nogit-'));
    try {
      const code = await initCommand({ cwd: nonGit, skipHook: false });
      expect(code).toBe(2);
    } finally {
      fs.rmSync(nonGit, { recursive: true, force: true });
    }
  });

  it('allows file-only init outside git when hook skipped', async () => {
    const nonGit = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-init-nogit-'));
    try {
      const code = await initCommand({ cwd: nonGit, skipHook: true });
      expect(code).toBe(0);
      expect(fs.existsSync(path.join(nonGit, '.vault-guard.json'))).toBe(true);
    } finally {
      fs.rmSync(nonGit, { recursive: true, force: true });
    }
  });

  it('conflicts when a foreign pre-commit hook already exists', async () => {
    const hook = new PreCommitHook();
    const hookPath = hook.getPreCommitHookPath(testDir, 'native');
    fs.mkdirSync(path.dirname(hookPath), { recursive: true });
    fs.writeFileSync(hookPath, '#!/bin/sh\necho custom-hook\n', { mode: 0o755 });

    const code = await initCommand({ cwd: testDir });
    expect(code).toBe(2);
    expect(fs.readFileSync(hookPath, 'utf8')).toContain('custom-hook');
    expect(fs.existsSync(path.join(testDir, '.vault-guard.json'))).toBe(false);
  });

  it('conflict dry-run still exits 2', async () => {
    const workflowPath = path.join(testDir, '.github/workflows/vault-guard.yml');
    fs.mkdirSync(path.dirname(workflowPath), { recursive: true });
    fs.writeFileSync(
      workflowPath,
      templateContentForPath('.github/workflows/vault-guard.yml').replace('main', 'develop'),
    );
    const code = await initCommand({ cwd: testDir, dryRun: true });
    expect(code).toBe(2);
  });

  it('advises when husky is present but native manager is selected', () => {
    fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
    const plan = planInit({ cwd: testDir, manager: 'native' });
    expect(plan.advisories.some(a => a.manager === 'husky')).toBe(true);
    expect(plan.advisories.find(a => a.manager === 'husky')?.guidance).toMatch(/husky/i);
  });

  it('does not advise husky when manager is husky', () => {
    fs.mkdirSync(path.join(testDir, '.husky'), { recursive: true });
    const plan = planInit({ cwd: testDir, manager: 'husky', skipHook: true });
    expect(plan.advisories.some(a => a.manager === 'husky')).toBe(false);
  });

  it('advises when lefthook.yml exists under native manager', () => {
    fs.writeFileSync(path.join(testDir, 'lefthook.yml'), 'pre-commit:\n  commands: {}\n');
    const plan = planInit({ cwd: testDir, manager: 'native' });
    expect(plan.advisories.some(a => a.manager === 'lefthook')).toBe(true);
  });

  it('conflicts on foreign lefthook-local.yml when manager is lefthook', () => {
    fs.writeFileSync(path.join(testDir, 'lefthook-local.yml'), 'pre-commit:\n  commands:\n    other:\n      run: echo hi\n');
    const plan = planInit({ cwd: testDir, manager: 'lefthook', skipConfig: true, skipWorkflow: true, skipAgentRules: true });
    expect(plan.ok).toBe(false);
    expect(plan.conflicts.some(c => c.path === 'lefthook-local.yml' && c.reason === 'foreign_hook')).toBe(true);
  });

  it('pins the workflow template Action tag to the CLI package version', () => {
    const yaml = githubWorkflowYaml();
    const match = yaml.match(/uses: vaultcompasshq\/vault-guard@(\S+)/);
    expect(match).not.toBeNull();
    const pin = (match as RegExpMatchArray)[1];

    // Shape guard first: this must always look like a real semver tag, not
    // e.g. an empty string or "vundefined" if readCliVersion() ever broke.
    expect(pin).toMatch(/^v\d+\.\d+\.\d+$/);

    // Then the actual pin: derived from the CLI's own package.json version at
    // read time (not a hardcoded literal), so a version bump (e.g. the
    // changeset in this repo bumping package.json to 1.4.2) can never make
    // this test stale — both sides read the same file at test time.
    expect(pin).toBe(`v${readCliVersion()}`);
  });

  describe('husky-generated hooks dir (husky 9)', () => {
    // Same husky 9 shape as the core package's fixture: core.hooksPath is
    // the generated, gitignored .husky/_ directory; the tracked hook lives
    // one directory up at .husky/<hookname>.
    function buildHusky9Layout(dir: string): void {
      const genDir = path.join(dir, '.husky', '_');
      fs.mkdirSync(genDir, { recursive: true });
      fs.writeFileSync(path.join(genDir, '.gitignore'), '*\n');
      fs.writeFileSync(
        path.join(genDir, 'h'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/../pre-commit"\n',
        { mode: 0o755 },
      );
      fs.writeFileSync(
        path.join(genDir, 'pre-commit'),
        '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n',
        { mode: 0o755 },
      );
      git(['config', '--local', 'core.hooksPath', '.husky/_'], dir);
    }

    it('bare init lands the vault-guard stanza in .husky/pre-commit, not .husky/_', async () => {
      buildHusky9Layout(testDir);

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(code).toBe(0);

      const trackedPath = path.join(testDir, '.husky', 'pre-commit');
      expect(fs.existsSync(trackedPath)).toBe(true);
      expect(fs.readFileSync(trackedPath, 'utf-8')).toContain('scan --staged');
    });

    it('never writes under .husky/_ during init', async () => {
      buildHusky9Layout(testDir);
      const before = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();

      await initCommand({ cwd: testDir, skipConfig: true, skipWorkflow: true, skipAgentRules: true });

      const after = fs.readdirSync(path.join(testDir, '.husky', '_')).sort();
      expect(after).toEqual(before);
    });

    it('bare init reports already installed when .husky/pre-commit already has the vault-guard stanza', () => {
      buildHusky9Layout(testDir);
      fs.writeFileSync(
        path.join(testDir, '.husky', 'pre-commit'),
        '#!/usr/bin/env sh\nvault-guard scan --staged\n',
        { mode: 0o755 },
      );

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });

      expect(plan.ok).toBe(true);
      expect(plan.hook?.installed).toBe(true);
      expect(plan.hook?.path).toBe(path.join(testDir, '.husky', 'pre-commit'));
    });

    it('names .husky/pre-commit as the conflict when a foreign tracked hook already exists there', async () => {
      buildHusky9Layout(testDir);
      fs.writeFileSync(
        path.join(testDir, '.husky', 'pre-commit'),
        '#!/usr/bin/env sh\necho custom-hook\n',
        { mode: 0o755 },
      );

      const code = await initCommand({
        cwd: testDir,
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(code).toBe(2);

      const plan = planInit({
        cwd: testDir,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });
      expect(
        plan.conflicts.some(c => c.path === '.husky/pre-commit' && c.reason === 'foreign_hook'),
      ).toBe(true);
    });

    it('dry-run reports the tracked .husky/pre-commit path, not the generated dir', () => {
      buildHusky9Layout(testDir);

      const plan = planInit({
        cwd: testDir,
        dryRun: true,
        manager: 'native',
        skipConfig: true,
        skipWorkflow: true,
        skipAgentRules: true,
      });

      expect(plan.hook?.path).toBe(path.join(testDir, '.husky', 'pre-commit'));
    });
  });

  it('conflicts on foreign pre-commit.cmd for native manager', () => {
    // The beforeEach hook sets a RELATIVE core.hooksPath ("hooks"), which
    // resolves against the working-tree root, not .git -- so the foreign
    // file has to be planted where install() will actually look, not at
    // the old (and wrong) .git/hooks assumption.
    const hooksDir = new PreCommitHook().getEffectiveHooksDir(testDir).hooksDir;
    fs.mkdirSync(hooksDir, { recursive: true });
    fs.writeFileSync(path.join(hooksDir, 'pre-commit.cmd'), '@echo off\necho other\n');
    const plan = planInit({
      cwd: testDir,
      manager: 'native',
      skipConfig: true,
      skipWorkflow: true,
      skipAgentRules: true,
    });
    expect(plan.ok).toBe(false);
    expect(plan.conflicts.some(c => c.path.endsWith('pre-commit.cmd') && c.reason === 'foreign_hook')).toBe(
      true,
    );
  });

});
