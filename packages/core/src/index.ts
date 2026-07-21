export * from './types';
export * from './errors';
export * from './scanners';
export * from './utils/file-utils';
export * from './config';
export * from './config-validate';
export * from './baseline';
export { fingerprintForMatch } from './match-fingerprint';
export * from './scan-output';
export * from './diagnostics';
export { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from './utils/entropy';
export { isPlaceholderSecret, isNonSecretConnectionString, isSampleJwt, isRedactedTemplateValue, isEnvVarNameToken } from './utils/placeholder';
export { getGitStagedFilePaths, readGitIndexFile, isInsideGitWorkTree } from './utils/git-utils';
export {
  validateRegexSafety,
  validateRegexLength,
  mapRegexSafetyReasonToDiagnosticCode,
  mapPatternRejectionReasonToDiagnosticCode,
  REGEX_REASON_TO_DIAGNOSTIC_CODE,
  REGEX_MAX_LENGTH,
  REGEX_MAX_QUANTIFIERS,
} from './utils/regex-safety';

export { scanTextFileAsync, scanTextFileSync } from './utils/scan-file';
export { applyPathAwareSeverity, isTestFilePath } from './utils/path-severity';
