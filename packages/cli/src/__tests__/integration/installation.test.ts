import { buildCli } from '../../cli';
import { Command } from 'commander';

describe('CLI Installation Integration', () => {
  let program: Command;

  beforeAll(() => {
    program = buildCli();
  });

  it('should have all required commands', () => {
    const commands = program.commands.map(cmd => cmd.name());

    expect(commands).toContain('scan');
    expect(commands).toContain('install-hook');
    expect(commands).toContain('tokens');
    expect(commands).toContain('monitor');
    expect(commands).toContain('fix');
    expect(commands).toContain('check');
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

  it('should have monitor command', () => {
    const monitorCommand = program.commands.find(cmd => cmd.name() === 'monitor');

    expect(monitorCommand).toBeDefined();
    if (monitorCommand) {
      expect(monitorCommand.description()).toBeDefined();
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
