import path from 'path';
import chalk from 'chalk';
import {
  ControlFileReadError,
  configParseFailure,
  controlFileRefusal,
  readRegularFileNoFollow,
  findVaultGuardConfigPath,
  validateVaultGuardConfig,
  SecretScanner,
} from '@vaultcompass/vault-guard-core';

/**
 * Validate the nearest `.vault-guard.json` / `.vault-guard.local.json`.
 * Exits 0 when missing (nothing to validate) or when structurally valid.
 */
export async function configValidateCommand(cwd: string = process.cwd()): Promise<number> {
  const configPath = findVaultGuardConfigPath(cwd);
  if (!configPath) {
    console.log(chalk.green('✓'), chalk.white('No Vault Guard config file in search path -- nothing to validate.'));
    return 0;
  }

  // Read without following a link: a linked config is one more config this
  // command cannot accept (exit 1), and nothing of its target is printed.
  let raw: string;
  try {
    const r = readRegularFileNoFollow(configPath);
    if (r.kind === 'refused') {
      console.error(chalk.red('❌'), chalk.white(controlFileRefusal(path.basename(configPath), configPath, r.what)));
      return 1;
    }
    if (r.kind === 'absent') {
      console.error(chalk.red('❌'), chalk.white(`Failed to read ${configPath}: it disappeared while being read`));
      return 1;
    }
    raw = r.text;
  } catch (e) {
    const code = e instanceof ControlFileReadError ? e.code : 'EUNKNOWN';
    console.error(chalk.red('❌'), chalk.white(`Failed to read ${configPath} (${code})`));
    return 1;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    // Never the engine's message, which quotes the start of the file.
    console.error(chalk.red('❌'), chalk.white(`${configPath}: ${configParseFailure(raw, e)}`));
    return 1;
  }

  const v = validateVaultGuardConfig(parsed);
  if (!v.ok) {
    console.error(chalk.red('❌'), chalk.white(configPath));
    for (const err of v.errors) {
      console.error(chalk.gray('  ·'), chalk.white(err));
    }
    return 1;
  }

  const scanner = new SecretScanner(v.config);
  if (scanner.extraPatternRejections.length > 0) {
    console.error(chalk.yellow('⚠'), chalk.white('Some extra_patterns were rejected and are not active:'));
    for (const r of scanner.extraPatternRejections) {
      console.error(chalk.gray('  ·'), chalk.white(`${r.id}: ${r.reason} -- ${r.detail}`));
    }
    return 1;
  }

  console.log(chalk.green('✓'), chalk.white(`${configPath} is valid.`));
  return 0;
}
