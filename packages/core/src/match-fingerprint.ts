import fs from 'fs';
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
  const payload = `${relKey}|${m.type}|${m.line}|${m.offset}|${m.matchLength}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

/** Symlinks resolved, falling back to the input when that is not possible. */
function canonical(p: string): string {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return p;
  }
}

/**
 * The path a content fingerprint is keyed on: relative to `root` (the
 * repository root inside git, the scan anchor outside it), with symlinks
 * resolved in the root and in the file's PARENT directory, so a file reached
 * through a linked parent directory keys the same as through its physical
 * path.
 *
 * The leaf is never resolved. A key belongs to the path it was found at: a
 * file whose working copy is a link to another file is keyed on its own name,
 * never on the target's (audit 2026-10-18, review of N1). Resolving the leaf
 * let a head file swapped for a link to a baselined file borrow that file's
 * accepted key, which is exactly the "a copy into another file is a new key"
 * rule below, defeated by a working-tree change.
 */
export function contentRelPath(fileAbs: string, root: string): string {
  const abs = path.resolve(fileAbs);
  const file = path.join(canonical(path.dirname(abs)), path.basename(abs));
  return relativeFingerprintKey(file, canonical(path.resolve(root)));
}

/**
 * Content fingerprint for a value-bearing match:
 * `sha256("vg-fp-v2" NUL relpath NUL rule NUL sha256(raw match))`.
 *
 * It does not depend on the line or offset, so moving a finding keeps its key,
 * while a rename, a copy into another file or a different value is a new key.
 * Undefined for a match that carries no value digest (a header-only rule),
 * which never gets a content key: its match text is the same for every key.
 */
export function contentFingerprintForMatch(
  root: string,
  fileAbs: string,
  m: SecretMatch,
): string | undefined {
  if (m.valueDigest === undefined) return undefined;
  return contentFingerprint(contentRelPath(fileAbs, root), m.type, m.valueDigest);
}

/** The content key from its three parts. Exposed for the baseline writer and tests. */
export function contentFingerprint(relPath: string, rule: string, valueDigest: string): string {
  return createHash('sha256')
    .update(`vg-fp-v2\0${relPath}\0${rule}\0${valueDigest}`, 'utf8')
    .digest('hex');
}

/**
 * The positional fingerprint with its path taken relative to the CONTENT
 * root rather than the run's anchor. Used only for baseline entries of
 * header-only rules, which sit in the same `entries` list as content keys and
 * must therefore be anchored the same way, so a run from a subdirectory reads
 * them the same as a run from the root.
 */
export function rootPositionalFingerprint(root: string, fileAbs: string, m: SecretMatch): string {
  const payload = `${contentRelPath(fileAbs, root)}|${m.type}|${m.line}|${m.offset}|${m.matchLength}`;
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}
