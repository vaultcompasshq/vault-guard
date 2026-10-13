import fs from 'fs';
import path from 'path';
import {
  getFilesToScanAsync,
  newPlainFileSetInfo,
  FileTooLargeError,
  GitContentSource,
  GitError,
  MAX_SCAN_FILE_BYTES,
  dropHeaderOnlyTwins,
  fileSetGitEnv,
  scanFileContent,
  SecretScanner,
  type FileScanResult,
} from '@vaultcompass/vault-guard-core';

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip',
  '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.bin',
]);

function isBinaryFile(filePath: string): boolean {
  return BINARY_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

/**
 * Per-file scan budget (ms) for the MCP surface, matching the CLI default.
 *
 * Like the CLI's, this is a **post-hoc** check, not a wall-clock bound: Node's
 * regex engine is **synchronous** and cannot be interrupted, so a runaway scan
 * still runs to completion and this only notices afterwards. Its job is to stop
 * an agent being handed a silent "clean" for a file whose scan behaved
 * pathologically.
 */
export const MCP_SCAN_BUDGET_MS = 5000;

/** A file that WAS scanned, but whose scan took long enough not to be trusted. */
export interface OverBudgetFile {
  file: string;
  elapsed_ms: number;
  budget_ms: number;
}

export interface WorkspaceScanOutcome {
  results: FileScanResult[];
  filesScanned: number;
  bytesScanned: number;
  /** Files whose scan exceeded the budget; their result is reported but not trusted. */
  overBudget: OverBudgetFile[];
  /** Files that were not scanned at all (over the size limit, or unreadable). */
  unscannable: UnscannableFile[];
}

export interface UnscannableFile {
  file: string;
  /** Over the size limit, or could not be read: the same kinds the CLI reports. */
  kind: 'too_large' | 'read_error';
  reason: string;
}

export async function scanWorkspaceDirectory(
  root: string,
  scanner: SecretScanner,
  concurrency = 10,
  configIgnorePatterns: string[] = [],
  scanBudgetMs: number = MCP_SCAN_BUDGET_MS,
): Promise<WorkspaceScanOutcome> {
  // Inside git the file set comes from git (tracked plus untracked files that
  // are not ignored), the same set the CLI scans, so an editor and CI agree.
  // A git failure there throws rather than falling back to the walk.
  const info = newPlainFileSetInfo();
  const files = await getFilesToScanAsync(root, false, undefined, configIgnorePatterns, undefined, info);
  const results: FileScanResult[] = [];
  const overBudget: OverBudgetFile[] = [];
  // A tracked file that could not be examined on disk was not scanned: never a clean.
  const unscannable: UnscannableFile[] = info.unreadable.map(u => ({
    file: u.file,
    kind: 'read_error' as const,
    reason: u.reason,
  }));
  let filesScanned = 0;
  let bytesScanned = 0;

  // Tracked content is read from the index blob, exactly as a plain CLI scan
  // reads it (design 2026-10-12, 2.8), so an editor and CI agree. A git
  // failure while reading it throws, as the file-set failures do.
  const content = new GitContentSource('index', fileSetGitEnv(), info.blobs);
  content.prepare(files.filter(f => !isBinaryFile(f)));

  const scanOne = async (file: string): Promise<void> => {
    try {
      if (isBinaryFile(file)) return;
      const entry = content.entryFor(file);
      if (!entry) {
        const st = await fs.promises.stat(file);
        if (!st.isFile()) return;
      }
      const outcome = await scanFileContent(scanner, file, entry, entry ? content : undefined, {
        pathRoot: root,
        maxBytes: MAX_SCAN_FILE_BYTES,
      });
      if (outcome.failure) {
        unscannable.push({
          file,
          kind: outcome.failure.kind,
          reason:
            outcome.failure.kind === 'too_large'
              ? new FileTooLargeError(outcome.failure.bytes, MAX_SCAN_FILE_BYTES).message
              : outcome.failure.reason,
        });
        return;
      }
      // Counted only once the scan has run: a file refused for its size is in
      // `unscannable`, not in the scanned totals.
      filesScanned += 1;
      bytesScanned += outcome.bytesRead;
      if (outcome.matches.length > 0) {
        results.push({ file, matches: outcome.matches });
      }
      if (outcome.elapsedMs > scanBudgetMs) {
        overBudget.push({ file, elapsed_ms: outcome.elapsedMs, budget_ms: scanBudgetMs });
      }
    } catch (error) {
      if (error instanceof GitError) throw error;
      // A file above the scan limit, or one that cannot be read, was NOT
      // scanned; say so instead of letting it pass as clean.
      const tooLarge = error instanceof FileTooLargeError;
      unscannable.push({
        file,
        kind: tooLarge ? 'too_large' : 'read_error',
        reason: tooLarge ? error.message : String(error),
      });
    }
  };

  try {
    for (let i = 0; i < files.length; i += concurrency) {
      const batch = files.slice(i, i + concurrency);
      await Promise.all(batch.map(scanOne));
    }
  } finally {
    content.close();
  }

  return { results: dropHeaderOnlyTwins(results), filesScanned, bytesScanned, overBudget, unscannable };
}
