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

  it('puts --verbose only on scan, not on the root program or another command', () => {
    expect(program.options.some(opt => opt.long === '--verbose')).toBe(false);
    const owners: string[] = [];
    const walk = (cmd: Command, name: string): void => {
      if (cmd.options.some(opt => opt.long === '--verbose')) owners.push(name);
      for (const sub of cmd.commands) walk(sub, `${name} ${sub.name()}`);
    };
    for (const cmd of program.commands) walk(cmd, cmd.name());
    expect(owners).toEqual(['scan']);
    const scan = program.commands.find(cmd => cmd.name() === 'scan');
    const verbose = scan?.options.filter(opt => opt.long === '--verbose') ?? [];
    expect(verbose).toHaveLength(1);
    expect(verbose[0]?.short).toBeUndefined();
  });
});
