import * as fs from 'fs';
import * as path from 'path';
import { PreCommitHook, type HookManager } from '@vaultcompass/vault-guard-core';
import chalk from 'chalk';
import {
  MANAGED_FILE_PATHS,
  MANIFEST_RELATIVE_PATH,
  INIT_TEMPLATE_VERSION,
  buildManifestContent,
  templateContentForPath,
  type InitManifest,
  type ManagedFilePath,
} from '../init/templates';

export interface InitOptions {
  cwd?: string;
  dryRun?: boolean;
  revert?: boolean;
  json?: boolean;
  manager?: HookManager;
  skipHook?: boolean;
  skipWorkflow?: boolean;
  skipConfig?: boolean;
  skipAgentRules?: boolean;
}

export interface InitConflict {
  path: string;
  reason:
    | 'exists'
    | 'foreign_manifest'
    | 'manifest_mismatch'
    | 'not_a_git_repository'
    | 'foreign_hook';
}

export interface InitPlannedAction {
  kind: 'create' | 'hook-install' | 'skip';
  path: string;
  detail?: string;
}

export interface InitResult {
  ok: boolean;
  dryRun: boolean;
  reverted: boolean;
  alreadyInitialized: boolean;
  actions: InitPlannedAction[];
  conflicts: InitConflict[];
  hook?: { manager: string; path?: string; installed: boolean };
  manifestPath: string;
  mcpMergeHint: string;
}

const MCP_MERGE_HINT =
  'Merge .vault-guard/mcp-snippet.json into your editor MCP config (~/.cursor/mcp.json or Claude Desktop).';

function isGitRepo(cwd: string): boolean {
  return fs.existsSync(path.join(cwd, '.git'));
}

function readFileIfExists(filePath: string): string | undefined {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return undefined;
  }
}

function parseManifest(content: string): InitManifest | undefined {
  try {
    const parsed = JSON.parse(content) as InitManifest;
    if (parsed.initVersion !== '1' || !Array.isArray(parsed.files)) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

function managedContentPaths(options: InitOptions): ManagedFilePath[] {
  const skip = new Set<string>();
  if (options.skipConfig) skip.add('.vault-guard.json');
  if (options.skipWorkflow) skip.add('.github/workflows/vault-guard.yml');
  if (options.skipAgentRules) {
    skip.add('.vault-guard/mcp-snippet.json');
    skip.add('.vault-guard/agent-rules.md');
  }
  return MANAGED_FILE_PATHS.filter(
    (p): p is ManagedFilePath => p !== MANIFEST_RELATIVE_PATH && !skip.has(p),
  );
}

function hookRelativePath(cwd: string, hookPath: string): string {
  return path.relative(cwd, hookPath).split(path.sep).join('/');
}

function foreignHookConflict(
  cwd: string,
  manager: HookManager,
): InitConflict | undefined {
  const hook = new PreCommitHook();
  const hookPath = hook.getPreCommitHookPath(cwd, manager);
  if (!fs.existsSync(hookPath)) return undefined;
  if (hook.isInstalled({ cwd, manager })) return undefined;

  const rel = hookRelativePath(cwd, hookPath);
  if (manager === 'husky') {
    const content = readFileIfExists(hookPath) ?? '';
    if (content.includes('vault-guard')) return undefined;
    return { path: rel, reason: 'foreign_hook' };
  }
  if (manager === 'lefthook') {
    const localPath = path.join(cwd, 'lefthook-local.yml');
    if (!fs.existsSync(localPath)) return undefined;
    const content = readFileIfExists(localPath) ?? '';
    if (content.includes('vault-guard scan --staged')) return undefined;
    return { path: 'lefthook-local.yml', reason: 'foreign_hook' };
  }
  if (manager === 'precommit') {
    const configPath = path.join(cwd, '.pre-commit-config.yaml');
    if (!fs.existsSync(configPath)) return undefined;
    const content = readFileIfExists(configPath) ?? '';
    if (content.includes('vault-guard scan --staged')) return undefined;
    return { path: '.pre-commit-config.yaml', reason: 'foreign_hook' };
  }

  const content = readFileIfExists(hookPath) ?? '';
  if (content.trim().length === 0) return undefined;
  return { path: rel, reason: 'foreign_hook' };
}

function ensureParentDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

export function planInit(options: InitOptions = {}): InitResult {
  const cwd = options.cwd ?? process.cwd();
  const dryRun = Boolean(options.dryRun);
  const manager = options.manager ?? 'native';
  const actions: InitPlannedAction[] = [];
  const conflicts: InitConflict[] = [];
  const trackedFiles: Array<{ path: string; action: 'created' }> = [];

  const manifestAbs = path.join(cwd, MANIFEST_RELATIVE_PATH);
  const manifestRaw = readFileIfExists(manifestAbs);
  const manifestParsed = manifestRaw ? parseManifest(manifestRaw) : undefined;

  if (manifestRaw && !manifestParsed) {
    conflicts.push({ path: MANIFEST_RELATIVE_PATH, reason: 'foreign_manifest' });
  }

  for (const rel of managedContentPaths(options)) {
    const abs = path.join(cwd, rel);
    const expected = templateContentForPath(rel);
    const current = readFileIfExists(abs);

    if (current === undefined) {
      actions.push({ kind: 'create', path: rel });
      trackedFiles.push({ path: rel, action: 'created' });
      continue;
    }

    if (current === expected) {
      actions.push({ kind: 'skip', path: rel, detail: 'content matches template' });
      trackedFiles.push({ path: rel, action: 'created' });
      continue;
    }

    conflicts.push({ path: rel, reason: 'exists' });
  }

  let hookState: InitResult['hook'];
  if (!options.skipHook) {
    if (!isGitRepo(cwd)) {
      conflicts.push({ path: '.git', reason: 'not_a_git_repository' });
    } else {
      const foreignHook = foreignHookConflict(cwd, manager);
      if (foreignHook) {
        conflicts.push(foreignHook);
      } else {
        const hook = new PreCommitHook();
        const hookPath = hook.getPreCommitHookPath(cwd, manager);
        if (hook.isInstalled({ cwd, manager })) {
          hookState = { manager, path: hookPath, installed: true };
          actions.push({ kind: 'skip', path: hookPath, detail: 'hook already installed' });
        } else {
          hookState = { manager, path: hookPath, installed: false };
          actions.push({ kind: 'hook-install', path: hookPath, detail: manager });
        }
      }
    }
  }

  const hookMeta =
    hookState?.path && !options.skipHook
      ? { manager, path: hookRelativePath(cwd, hookState.path) }
      : undefined;

  function manifestMatchesState(manifest: InitManifest): boolean {
    if (manifest.templateVersion !== INIT_TEMPLATE_VERSION) return false;
    const expectedPaths = trackedFiles
      .map(f => f.path)
      .sort()
      .join('\0');
    const actualPaths = manifest.files
      .map(f => f.path)
      .sort()
      .join('\0');
    if (expectedPaths !== actualPaths) return false;
    if (hookMeta) {
      return manifest.hookManager === hookMeta.manager && manifest.hookPath === hookMeta.path;
    }
    return manifest.hookManager === undefined && manifest.hookPath === undefined;
  }

  if (manifestRaw === undefined && conflicts.length === 0) {
    actions.push({ kind: 'create', path: MANIFEST_RELATIVE_PATH });
  } else if (manifestParsed) {
    if (manifestMatchesState(manifestParsed)) {
      actions.push({ kind: 'skip', path: MANIFEST_RELATIVE_PATH, detail: 'manifest current' });
    } else if (conflicts.length === 0) {
      conflicts.push({ path: MANIFEST_RELATIVE_PATH, reason: 'manifest_mismatch' });
    }
  }

  const alreadyInitialized =
    conflicts.length === 0 &&
    actions.length > 0 &&
    actions.every(a => a.kind === 'skip');

  return {
    ok: conflicts.length === 0,
    dryRun,
    reverted: false,
    alreadyInitialized,
    actions,
    conflicts,
    hook: hookState,
    manifestPath: MANIFEST_RELATIVE_PATH,
    mcpMergeHint: MCP_MERGE_HINT,
  };
}

export function applyInit(plan: InitResult, options: InitOptions = {}): InitResult {
  if (!plan.ok || plan.dryRun || plan.alreadyInitialized) {
    return plan;
  }

  const cwd = options.cwd ?? process.cwd();
  const manager = options.manager ?? 'native';
  const trackedFiles: Array<{ path: string; action: 'created' }> = [];
  const createdPaths: string[] = [];

  const rollbackCreatedFiles = (): void => {
    for (const rel of createdPaths.reverse()) {
      const abs = path.join(cwd, rel);
      try {
        if (fs.existsSync(abs)) fs.unlinkSync(abs);
      } catch {
        /* best effort */
      }
    }
  };

  if (plan.hook && !plan.hook.installed && !options.skipHook) {
    const hook = new PreCommitHook();
    const result = hook.install({ cwd, manager });
    if (!result.success) {
      return {
        ...plan,
        ok: false,
        actions: [
          ...plan.actions,
          {
            kind: 'skip',
            path: plan.hook.path ?? 'pre-commit',
            detail: `hook install failed: ${result.message}`,
          },
        ],
      };
    }
    plan.hook = {
      manager,
      path: result.hookPath ?? plan.hook.path,
      installed: true,
    };
  }

  try {
    for (const action of plan.actions) {
      if (action.kind !== 'create' || action.path === MANIFEST_RELATIVE_PATH) continue;
      const abs = path.join(cwd, action.path);
      ensureParentDir(abs);
      fs.writeFileSync(abs, templateContentForPath(action.path as ManagedFilePath), {
        encoding: 'utf8',
        flag: 'wx',
      });
      trackedFiles.push({ path: action.path, action: 'created' });
      createdPaths.push(action.path);
    }
  } catch (error) {
    rollbackCreatedFiles();
    if (plan.hook?.installed && !options.skipHook) {
      new PreCommitHook().uninstall({ cwd, manager });
    }
    return {
      ...plan,
      ok: false,
      actions: [
        ...plan.actions,
        {
          kind: 'skip',
          path: 'init',
          detail: `file write failed: ${String(error)}`,
        },
      ],
    };
  }

  const hookMeta =
    plan.hook?.path && !options.skipHook
      ? { manager, path: hookRelativePath(cwd, plan.hook.path) }
      : undefined;

  const allTracked =
    trackedFiles.length > 0
      ? trackedFiles
      : managedContentPaths(options).map(p => ({ path: p, action: 'created' as const }));

  const manifestContent = buildManifestContent(allTracked, hookMeta);
  const manifestAbs = path.join(cwd, MANIFEST_RELATIVE_PATH);
  try {
    if (!fs.existsSync(manifestAbs)) {
      ensureParentDir(manifestAbs);
      fs.writeFileSync(manifestAbs, manifestContent, { encoding: 'utf8', flag: 'wx' });
    }
  } catch (error) {
    rollbackCreatedFiles();
    if (plan.hook?.installed && !options.skipHook) {
      new PreCommitHook().uninstall({ cwd, manager });
    }
    return {
      ...plan,
      ok: false,
      actions: [
        ...plan.actions,
        {
          kind: 'skip',
          path: MANIFEST_RELATIVE_PATH,
          detail: `manifest write failed: ${String(error)}`,
        },
      ],
    };
  }

  return { ...plan, ok: true };
}

export function revertInit(options: InitOptions = {}): InitResult {
  const cwd = options.cwd ?? process.cwd();
  const dryRun = Boolean(options.dryRun);
  const manifestAbs = path.join(cwd, MANIFEST_RELATIVE_PATH);
  const raw = readFileIfExists(manifestAbs);

  if (!raw) {
    return {
      ok: false,
      dryRun,
      reverted: false,
      alreadyInitialized: false,
      actions: [],
      conflicts: [{ path: MANIFEST_RELATIVE_PATH, reason: 'foreign_manifest' }],
      manifestPath: MANIFEST_RELATIVE_PATH,
      mcpMergeHint: MCP_MERGE_HINT,
    };
  }

  const manifest = parseManifest(raw);
  if (!manifest) {
    return {
      ok: false,
      dryRun,
      reverted: false,
      alreadyInitialized: false,
      actions: [],
      conflicts: [{ path: MANIFEST_RELATIVE_PATH, reason: 'foreign_manifest' }],
      manifestPath: MANIFEST_RELATIVE_PATH,
      mcpMergeHint: MCP_MERGE_HINT,
    };
  }

  const actions: InitPlannedAction[] = [];
  const filePaths = [...manifest.files.map(f => f.path)].reverse();

  for (const rel of filePaths) {
    actions.push({
      kind: 'skip',
      path: rel,
      detail: dryRun ? 'would remove file' : 'removed file',
    });
    if (!dryRun) {
      const abs = path.join(cwd, rel);
      if (fs.existsSync(abs)) fs.unlinkSync(abs);
    }
  }

  if (manifest.hookManager) {
    actions.push({
      kind: 'hook-install',
      path: manifest.hookPath ?? 'pre-commit',
      detail: dryRun ? 'would uninstall hook' : 'uninstalled hook',
    });
    if (!dryRun) {
      new PreCommitHook().uninstall({
        cwd,
        manager: manifest.hookManager as HookManager,
      });
    }
  }

  actions.push({
    kind: 'skip',
    path: MANIFEST_RELATIVE_PATH,
    detail: dryRun ? 'would remove manifest' : 'removed manifest',
  });
  if (!dryRun && fs.existsSync(manifestAbs)) {
    fs.unlinkSync(manifestAbs);
    const vgDir = path.join(cwd, '.vault-guard');
    try {
      if (fs.existsSync(vgDir) && fs.readdirSync(vgDir).length === 0) {
        fs.rmdirSync(vgDir);
      }
    } catch {
      /* best effort */
    }
  }

  return {
    ok: true,
    dryRun,
    reverted: !dryRun,
    alreadyInitialized: false,
    actions,
    conflicts: [],
    manifestPath: MANIFEST_RELATIVE_PATH,
    mcpMergeHint: MCP_MERGE_HINT,
  };
}

function printHuman(result: InitResult, options: InitOptions): void {
  if (options.revert) {
    if (!result.ok) {
      console.error(chalk.red('❌ Revert failed:'), 'no valid init manifest found');
      return;
    }
    console.log(
      result.dryRun
        ? chalk.blue('🔍 Dry-run revert plan')
        : chalk.green.bold('✅ Reverted Vault Guard init artifacts'),
    );
    for (const a of result.actions) {
      console.log(chalk.gray(`   ${a.detail ?? a.path}`));
    }
    return;
  }

  if (result.conflicts.length > 0) {
    console.error(chalk.red.bold('❌ Init blocked — conflicts (no automatic overwrites):'));
    for (const c of result.conflicts) {
      console.error(chalk.white(`   ${c.path}`), chalk.gray(`(${c.reason})`));
    }
    console.error(chalk.gray('\nResolve manually, then re-run vault-guard init.'));
    return;
  }

  if (result.alreadyInitialized) {
    console.log(chalk.green('✅ Already initialized — no changes needed'));
    return;
  }

  if (result.dryRun) {
    console.log(chalk.blue('🔍 Dry-run — would apply:'));
  } else {
    console.log(chalk.green.bold('✅ Vault Guard initialized'));
  }

  for (const a of result.actions) {
    if (a.kind === 'create') {
      console.log(chalk.white(`   ${result.dryRun ? 'create' : 'created'} ${a.path}`));
    } else if (a.kind === 'hook-install') {
      console.log(
        chalk.white(`   ${result.dryRun ? 'install' : 'installed'} hook (${a.detail})`),
      );
    }
  }

  console.log(chalk.gray(`\n${result.mcpMergeHint}`));
  console.log(chalk.gray(`Manifest: ${result.manifestPath}`));
}

export async function initCommand(options: InitOptions = {}): Promise<number> {
  if (options.revert) {
    const result = revertInit(options);
    if (options.json) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    } else {
      printHuman(result, options);
    }
    return result.ok ? 0 : 1;
  }

  const plan = planInit(options);
  const result = plan.dryRun || plan.alreadyInitialized ? plan : applyInit(plan, options);

  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    printHuman(result, options);
  }

  if (result.conflicts.length > 0) return 2;
  if (!result.ok) return 1;
  return 0;
}
