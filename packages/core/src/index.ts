export * from './types';
export * from './errors';
export * from './scanners';
export * from './utils/file-utils';
export * from './config';
export * from './config-validate';
export * from './baseline';
export {
  TrustBaseError,
  loadTrustedControls,
  assertTrustBaseResolvable,
  listHeadTreeFiles,
  readFileAtRef,
  isRegularFileMode,
  CONFIG_PROPOSAL_LINE,
  BASELINE_PROPOSAL_LINE,
  CONFIG_ADDED_LINE,
  BASELINE_ADDED_LINE,
  type ControlFile,
  type ControlShapeChange,
  type TrustedControls,
} from './trust-base';
export { fingerprintForMatch } from './match-fingerprint';
export * from './scan-output';
export * from './diagnostics';
export { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from './utils/entropy';
export { isPlaceholderSecret, isNonSecretConnectionString, isSampleJwt, isRedactedTemplateValue, isEnvVarNameToken, isCodeIdentifierReference, isPasswordHash, isPemHeaderWithoutBody, isSequentialRunPlaceholder, SEQUENTIAL_RUN_COVERAGE_THRESHOLD } from './utils/placeholder';
export {
  getGitStagedFilePaths,
  readGitIndexFile,
  isInsideGitWorkTree,
  getGitWorkTreeRoot,
} from './utils/git-utils';
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
export { applyPathAwareSeverity, isTestFilePath, isLocalePath } from './utils/path-severity';
export { findInlineTestRegions, isInsideInlineTestRegion } from './utils/inline-test-context';
export type { InlineTestRegion, InlineTestRegionFinder } from './utils/inline-test-context';
export {
  DEFAULT_FAIL_ON,
  FAIL_ON_VALUES,
  isFailOnThreshold,
  meetsFailThreshold,
  countBlockingMatches,
  resolveFailOn,
  type FailOnThreshold,
} from './utils/fail-on';
