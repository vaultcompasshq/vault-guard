import fs from 'fs';
import path from 'path';
import {
  getFilesToScanAsync,
  scanTextFileAsync,
  SecretScanner,
  type FileScanResult,
} from '@vaultcompass/vault-guard-core';

const MAX_FILE_SIZE = 10 * 1024 * 1024;

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
  let filesScanned = 0;
  let bytesScanned = 0;

  const scanOne = async (file: string): Promise<void> => {
    try {
      if (isBinaryFile(file)) return;
      const st = await fs.promises.stat(file);
      if (!st.isFile()) return;
      filesScanned += 1;
      bytesScanned += st.size;
      const t0 = Date.now();
      const matches = await scanTextFileAsync(scanner, file, { maxFileBytes: MAX_FILE_SIZE });
      const elapsed = Date.now() - t0;
      if (matches.length > 0) {
        results.push({ file, matches });
      }
      if (elapsed > scanBudgetMs) {
        overBudget.push({ file, elapsed_ms: elapsed, budget_ms: scanBudgetMs });
      }
    } catch {
      /* skip unreadable */
    }
  };

  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    await Promise.all(batch.map(scanOne));
  }

  return { results, filesScanned, bytesScanned, overBudget };
}
