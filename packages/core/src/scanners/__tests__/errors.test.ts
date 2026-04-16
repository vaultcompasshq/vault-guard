import { VaultGuardError, ScanError, FileAccessError, HookError } from '../../errors';

describe('Custom Error Classes', () => {
  describe('VaultGuardError', () => {
    it('should create VaultGuardError with message and code', () => {
      const error = new VaultGuardError('Test error', 'TEST_CODE');

      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.name).toBe('VaultGuardError');
    });

    it('should have stack trace', () => {
      const error = new VaultGuardError('Test error', 'TEST_CODE');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('VaultGuardError');
    });
  });

  describe('ScanError', () => {
    it('should create ScanError with message and filePath', () => {
      const error = new ScanError('Scan failed', '/path/to/file.ts');

      expect(error.message).toBe('Scan failed');
      expect(error.code).toBe('SCAN_ERROR');
      expect(error.filePath).toBe('/path/to/file.ts');
      expect(error.name).toBe('ScanError');
    });

    it('should work without filePath', () => {
      const error = new ScanError('Scan failed');

      expect(error.message).toBe('Scan failed');
      expect(error.code).toBe('SCAN_ERROR');
      expect(error.filePath).toBeUndefined();
    });
  });

  describe('FileAccessError', () => {
    it('should create FileAccessError with message and filePath', () => {
      const error = new FileAccessError('Cannot read file', '/path/to/file.ts');

      expect(error.message).toBe('Cannot read file');
      expect(error.code).toBe('FILE_ACCESS_ERROR');
      expect(error.filePath).toBe('/path/to/file.ts');
      expect(error.name).toBe('FileAccessError');
    });

    it('should include filePath in error message', () => {
      const filePath = '/path/to/file.ts';
      const error = new FileAccessError('Access denied', filePath);

      expect(error.message).toContain('Access denied');
      expect(error.filePath).toBe(filePath);
    });
  });

  describe('HookError', () => {
    it('should create HookError with message and operation', () => {
      const installError = new HookError('Install failed', 'install');

      expect(installError.message).toBe('Install failed');
      expect(installError.code).toBe('HOOK_ERROR');
      expect(installError.operation).toBe('install');
      expect(installError.name).toBe('HookError');

      const uninstallError = new HookError('Uninstall failed', 'uninstall');

      expect(uninstallError.operation).toBe('uninstall');
    });

    it('should work with different operation types', () => {
      const installError = new HookError('Failed', 'install');
      const uninstallError = new HookError('Failed', 'uninstall');

      expect(installError.operation).toBe('install');
      expect(uninstallError.operation).toBe('uninstall');
    });
  });

  describe('Error inheritance', () => {
    it('should be instanceof VaultGuardError', () => {
      const scanError = new ScanError('Test', '/path/to/file.ts');
      const fileAccessError = new FileAccessError('Test', '/path/to/file.ts');
      const hookError = new HookError('Test', 'install');

      expect(scanError).toBeInstanceOf(VaultGuardError);
      expect(fileAccessError).toBeInstanceOf(VaultGuardError);
      expect(hookError).toBeInstanceOf(VaultGuardError);
    });

    it('should be instanceof Error', () => {
      const scanError = new ScanError('Test', '/path/to/file.ts');

      expect(scanError).toBeInstanceOf(Error);
    });

    it('should be catchable as Error', () => {
      try {
        throw new ScanError('Test error', '/path/to/file.ts');
      } catch (error) {
        expect(error).toBeInstanceOf(ScanError);
        expect(error).toBeInstanceOf(VaultGuardError);
        expect(error).toBeInstanceOf(Error);

        if (error instanceof ScanError) {
          expect(error.code).toBe('SCAN_ERROR');
          expect(error.filePath).toBe('/path/to/file.ts');
        }
      }
    });
  });

  describe('Error integration', () => {
    it('should be catchable by VaultGuardError type', () => {
      try {
        throw new ScanError('Test error', '/path/to/file.ts');
      } catch (error) {
        expect(error).toBeInstanceOf(VaultGuardError);
        expect(error).toBeInstanceOf(Error);
      }
    });

    it('should preserve error properties when caught', () => {
      try {
        throw new ScanError('Test error', '/path/to/file.ts');
      } catch (error) {
        if (error instanceof ScanError) {
          expect(error.code).toBe('SCAN_ERROR');
          expect(error.filePath).toBe('/path/to/file.ts');
          expect(error.message).toBe('Test error');
        }
      }
    });
  });

  describe('Error properties', () => {
    it('should allow error code access', () => {
      const error = new VaultGuardError('Message', 'CUSTOM_CODE');

      expect(error.code).toBe('CUSTOM_CODE');
    });

    it('should have proper stack trace', () => {
      const error = new VaultGuardError('Message', 'CODE');

      expect(error.stack).toBeDefined();
      expect(error.name).toBe('VaultGuardError');
    });
  });
});
