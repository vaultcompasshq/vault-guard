import fs from 'fs';
import path from 'path';
import { getFilesToScanAsync, SecretScanner, type FileScanResult } from '@vaultcompass/vault-guard-core';

const MAX_FILE_SIZE = 10 * 1024 * 1024;

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip',
  '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.bin',
]);

function isBinaryFile(filePath: string): boolean {
  return BINARY_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

export async function scanWorkspaceDirectory(
  root: string,
  scanner: SecretScanner,
  concurrency = 10,
): Promise<FileScanResult[]> {
  const files = await getFilesToScanAsync(root, false);
  const results: FileScanResult[] = [];

  const scanOne = async (file: string): Promise<void> => {
    try {
      if (isBinaryFile(file)) return;
      const st = await fs.promises.stat(file);
      if (!st.isFile() || st.size > MAX_FILE_SIZE) return;
      const matches = scanner.scan(file);
      if (matches.length > 0) {
        results.push({ file, matches });
      }
    } catch {
      /* skip unreadable */
    }
  };

  for (let i = 0; i < files.length; i += concurrency) {
    const batch = files.slice(i, i + concurrency);
    await Promise.all(batch.map(scanOne));
  }

  return results;
}
