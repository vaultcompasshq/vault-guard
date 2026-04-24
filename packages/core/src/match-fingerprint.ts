import path from 'path';
import { createHash } from 'crypto';
import type { SecretMatch } from './types';

function relativeFingerprintKey(file: string, cwd: string | null): string {
  if (cwd === null) return file.split(path.sep).join('/');
  if (!path.isAbsolute(file)) return file.split(path.sep).join('/');
  const rel = path.relative(cwd, file);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return file.split(path.sep).join('/');
  return (rel || '.').split(path.sep).join('/');
}

/**
 * Stable fingerprint for a match location + rule id (no raw secret material).
 * Same inputs always yield the same hex digest (SHA-256).
 */
export function fingerprintForMatch(cwd: string | null, fileAbs: string, m: SecretMatch): string {
  const relKey = relativeFingerprintKey(fileAbs, cwd);
  const payload = `${relKey}|${m.type}|${m.line}|${m.column}|${m.matchLength}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}
