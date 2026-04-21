export * from './types';
export * from './errors';
export * from './scanners';
export * from './utils/file-utils';
export * from './config';
export * from './scan-output';
export { shannonEntropy, DEFAULT_ENTROPY_THRESHOLD } from './utils/entropy';
export { getGitStagedFilePaths, isInsideGitWorkTree } from './utils/git-utils';

// Re-export async functions for convenience
export { getAllFilesAsync, getFilesToScanAsync } from './utils/file-utils';
