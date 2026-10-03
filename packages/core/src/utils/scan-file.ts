import fs from 'fs';
import { decodeTextBuffer } from './text-decode';

import type { DiagnosticBus } from '../diagnostics';
import { SecretScanner } from '../scanners/secret-scanner';
import { applyPathAwareSeverity } from './path-severity';
import type { SecretMatch } from '../types';

/**
 * The most a single file may weigh and still be scanned: 32 MiB. The same limit
 * `--staged` applies to a blob read from the index. A file is read and scanned
 * WHOLE up to this size, so a multi-line key and a secret on a very long line
 * are found the same as anywhere else; above it the file is refused, never
 * partly scanned.
 */
export const MAX_SCAN_FILE_BYTES = 32 * 1024 * 1024;

/** Thrown for a file above the scan limit. Callers record it as unscannable. */
export class FileTooLargeError extends Error {
  readonly bytes: number;
  readonly maxBytes: number;
  constructor(bytes: number, maxBytes: number) {
    super(`over ${Math.round(maxBytes / 1024 / 1024)} MiB, not scanned`);
    this.name = 'FileTooLargeError';
    this.bytes = bytes;
    this.maxBytes = maxBytes;
  }
}

export interface ScanTextFileOptions {
  /** Refuse (throw {@link FileTooLargeError}) above this size. Defaults to {@link MAX_SCAN_FILE_BYTES}. */
  maxFileBytes?: number;
  bus?: DiagnosticBus;
  /**
   * Directory the scan is rooted at. Test / docs / locale context is judged on
   * the file's path relative to it, so directories above the scanned tree never
   * downgrade findings. See `contextPathFor`.
   */
  pathRoot?: string;
}

/**
 * Read `filePath` as text (UTF-8, or UTF-16 when a BOM says so; see
 * {@link decodeTextBuffer}) and run {@link SecretScanner.scanContent} over the
 * whole of it. A file above `maxFileBytes` throws {@link FileTooLargeError}
 * rather than being partly scanned.
 */
export async function scanTextFileAsync(
  scanner: SecretScanner,
  filePath: string,
  options: ScanTextFileOptions = {},
): Promise<SecretMatch[]> {
  const max = options.maxFileBytes ?? MAX_SCAN_FILE_BYTES;
  const st = await fs.promises.stat(filePath);
  if (st.size > max) throw new FileTooLargeError(st.size, max);
  const content = decodeTextBuffer(await fs.promises.readFile(filePath));
  return applyPathAwareSeverity(
    scanner.scanContent(content, { filePath, pathRoot: options.pathRoot }),
    filePath,
    options.pathRoot,
  );
}

/** Synchronous variant of {@link scanTextFileAsync}, with the same refusal. */
export function scanTextFileSync(
  scanner: SecretScanner,
  filePath: string,
  options: ScanTextFileOptions = {},
): SecretMatch[] {
  const max = options.maxFileBytes ?? MAX_SCAN_FILE_BYTES;
  const st = fs.statSync(filePath);
  if (st.size > max) throw new FileTooLargeError(st.size, max);
  return applyPathAwareSeverity(
    scanner.scanContent(decodeTextBuffer(fs.readFileSync(filePath)), {
      filePath,
      pathRoot: options.pathRoot,
    }),
    filePath,
    options.pathRoot,
  );
}
