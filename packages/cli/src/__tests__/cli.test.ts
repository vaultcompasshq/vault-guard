import { Command } from 'commander';
import { buildCli } from '../cli';

const COMMAND_NAMES = [
  'scan',
  'init',
  'install-hook',
  'tokens',
  'fix',
  'check',
  'statusline',
  'suggest-model',
  'proxy',
] as const;

describe('CLI', () => {
  let program: Command;

  beforeEach(() => {
    program = buildCli();
  });

  it.each(COMMAND_NAMES)('registers %s command', name => {
    const command = program.commands.find(cmd => cmd.name() === name);
    expect(command).toBeDefined();
  });

  it('scan declares path argument and format option', () => {
    const command = program.commands.find(cmd => cmd.name() === 'scan');
    expect(command).toBeDefined();
    expect(command!.registeredArguments.map(a => a.name())).toContain('path');
    expect(command!.options.some(opt => opt.long === '--format')).toBe(true);
  });
});
