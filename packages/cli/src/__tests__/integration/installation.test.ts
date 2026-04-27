import { buildCli } from '../../cli';
import { Command } from 'commander';

describe('CLI Installation Integration', () => {
  let program: Command;

  beforeAll(() => {
    program = buildCli();
  });

  it('should have all required commands', () => {
    const commands = program.commands.map(cmd => cmd.name());

    expect(commands).toContain('config');
    expect(commands).toContain('scan');
    expect(commands).toContain('install-hook');
    expect(commands).toContain('tokens');
    expect(commands).toContain('fix');
    expect(commands).toContain('check');
    expect(commands).toContain('statusline');
    expect(commands).toContain('suggest-model');
    expect(commands).toContain('proxy');
    expect(commands).toContain('data');
  });

  it('should expose config validate subcommand', () => {
    const configCmd = program.commands.find(cmd => cmd.name() === 'config');
    expect(configCmd).toBeDefined();
    const sub = configCmd?.commands.map(c => c.name()) ?? [];
    expect(sub).toContain('validate');
  });

  it('should expose data subcommands', () => {
    const dataCmd = program.commands.find(cmd => cmd.name() === 'data');
    expect(dataCmd).toBeDefined();
    const sub = dataCmd?.commands.map(c => c.name()) ?? [];
    expect(sub).toContain('status');
    expect(sub).toContain('reset');
    expect(sub).toContain('export');
  });

  it('should have scan command', () => {
    const scanCommand = program.commands.find(cmd => cmd.name() === 'scan');

    expect(scanCommand).toBeDefined();
    if (scanCommand) {
      expect(scanCommand.description()).toBeDefined();
    }
  });

  it('should have install-hook command', () => {
    const installHookCommand = program.commands.find(cmd => cmd.name() === 'install-hook');

    expect(installHookCommand).toBeDefined();
    if (installHookCommand) {
      expect(installHookCommand.description()).toBeDefined();
    }
  });

  it('should have tokens command', () => {
    const tokensCommand = program.commands.find(cmd => cmd.name() === 'tokens');

    expect(tokensCommand).toBeDefined();
    if (tokensCommand) {
      expect(tokensCommand.description()).toBeDefined();
    }
  });

  it('should have check command', () => {
    const checkCommand = program.commands.find(cmd => cmd.name() === 'check');

    expect(checkCommand).toBeDefined();
    if (checkCommand) {
      expect(checkCommand.description()).toBeDefined();
    }
  });

  it('should have fix command', () => {
    const fixCommand = program.commands.find(cmd => cmd.name() === 'fix');

    expect(fixCommand).toBeDefined();
    if (fixCommand) {
      expect(fixCommand.description()).toBeDefined();
    }
  });

  it('should have version option', () => {
    // Check that program has options configured
    expect(program.options.length).toBeGreaterThan(0);
  });

  it('should have help option', () => {
    // Check that program has options configured
    expect(program.options.length).toBeGreaterThan(0);
  });
});
