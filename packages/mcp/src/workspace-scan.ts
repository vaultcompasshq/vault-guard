import fs from 'fs';
import path from 'path';
import {
  getFilesToScanAsync,
  scanTextFileAsync,
  FileTooLargeError,
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
  const files = await getFilesToScanAsync(root, false, undefined, configIgnorePatterns);
  const results: FileScanResult[] = [];
  const overBudget: OverBudgetFile[] = [];
  const unscannable: UnscannableFile[] = [];
  let filesScanned = 0;
  let bytesScanned = 0;

  const scanOne = async (file: string): Promise<void> => {
    try {
      if (isBinaryFile(file)) return;
      const st = await fs.promises.stat(file);
      if (!st.isFile()) return;
      const t0 = Date.now();
      const matches = await scanTextFileAsync(scanner, file, { pathRoot: root });
      const elapsed = Date.now() - t0;
      // Counted only once the scan has run: a file refused for its size is in
      // `unscannable`, not in the scanned totals.
      filesScanned += 1;
      bytesScanned += st.size;
      if (matches.length > 0) {
        results.push({ file, matches });
      }
      if (elapsed > scanBudgetMs) {
        overBudget.push({ file, elapsed_ms: elapsed, budget_ms: scanBudgetMs });
      }
    } catch (error) {
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

  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    await Promise.all(batch.map(scanOne));
  }

  return { results, filesScanned, bytesScanned, overBudget, unscannable };
}
