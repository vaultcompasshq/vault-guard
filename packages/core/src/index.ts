export * from './types';
export * from './errors';
export * from './scanners';
export * from './utils/file-utils';
export * from './config';
export * from './scan-output';
export * from './diagnostics';
export { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from './utils/entropy';
export { getGitStagedFilePaths, isInsideGitWorkTree } from './utils/git-utils';
export {
  validateRegexSafety,
  validateRegexLength,
  mapRegexSafetyReasonToDiagnosticCode,
  mapPatternRejectionReasonToDiagnosticCode,
  REGEX_REASON_TO_DIAGNOSTIC_CODE,
  REGEX_MAX_LENGTH,
  REGEX_MAX_QUANTIFIERS,
} from './utils/regex-safety';

// Re-export async functions for convenience
export { getAllFilesAsync, getFilesToScanAsync } from './utils/file-utils';
