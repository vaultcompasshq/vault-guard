/**
 * Base error class for Vault Guard errors
 */
export class VaultGuardError extends Error {
  constructor(message: string, public code: string) {
    super(message);
    this.name = 'VaultGuardError';
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Error thrown when scanning fails
 */
export class ScanError extends VaultGuardError {
  constructor(message: string, public filePath?: string) {
    super(message, 'SCAN_ERROR');
    this.name = 'ScanError';
  }
}

/**
 * Error thrown when file access fails
 */
export class FileAccessError extends VaultGuardError {
  constructor(message: string, public filePath: string) {
    super(message, 'FILE_ACCESS_ERROR');
    this.name = 'FileAccessError';
  }
}

/**
 * Error thrown when hook installation fails
 */
export class HookError extends VaultGuardError {
  constructor(message: string, public operation: 'install' | 'uninstall') {
    super(message, 'HOOK_ERROR');
    this.name = 'HookError';
  }
}
