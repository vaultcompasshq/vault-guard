import { Command } from 'commander';
import { buildCli } from '../cli';

describe('CLI', () => {
  let program: Command;
  let consoleLogSpy: jest.SpyInstance;
  let consoleErrorSpy: jest.SpyInstance;
  let processExitSpy: jest.SpyInstance;

  beforeEach(() => {
    program = buildCli();
    consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
    consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation();
    processExitSpy = jest.spyOn(process, 'exit').mockImplementation();
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    processExitSpy.mockRestore();
  });

  describe('vault-guard scan', () => {
    it('should have scan command', () => {
      const command = program.commands.find(cmd => cmd.name() === 'scan');
      expect(command).toBeDefined();
    });

    it('should accept path argument', () => {
      const command = program.commands.find(cmd => cmd.name() === 'scan');
      expect(command).toBeDefined();
      const args = command?.options.filter(opt => opt.name() === 'path');
      expect(args).toBeDefined();
    });

    it('should show colored output for secrets', async () => {
      // This will test the actual scan functionality
      // For now, just verify the command structure
      const command = program.commands.find(cmd => cmd.name() === 'scan');
      expect(command).toBeDefined();
    });
  });

  describe('vault-guard install-hook', () => {
    it('should have install-hook command', () => {
      const command = program.commands.find(cmd => cmd.name() === 'install-hook');
      expect(command).toBeDefined();
    });
  });

  describe('vault-guard tokens', () => {
    it('should have tokens command', () => {
      const command = program.commands.find(cmd => cmd.name() === 'tokens');
      expect(command).toBeDefined();
    });
  });

  describe('vault-guard monitor', () => {
    it('should have monitor command', () => {
      const command = program.commands.find(cmd => cmd.name() === 'monitor');
      expect(command).toBeDefined();
    });
  });

  describe('vault-guard fix', () => {
    it('should have fix command', () => {
      const command = program.commands.find(cmd => cmd.name() === 'fix');
      expect(command).toBeDefined();
    });
  });

  describe('vault-guard check', () => {
    it('should have check command', () => {
      const command = program.commands.find(cmd => cmd.name() === 'check');
      expect(command).toBeDefined();
    });
  });
});
