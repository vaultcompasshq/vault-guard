import { randomBytes } from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * Control files on disk (`.vault-guard.baseline.json`, `.vault-guard.json`,
 * `.vault-guard.local.json`, the hook files the installer writes) are never
 * read or written through a link (design 2026-10-12, section 4).
 *
 * A committed link can point anywhere on the machine running the scan. A
 * reader that followed one would obey a config, or echo the start of a file,
 * that the repository does not hold; a writer that followed one would
 * overwrite a file outside the repository.
 */

export type NoFollowRead =
  | { kind: 'absent' }
  | { kind: 'file'; text: string }
  | { kind: 'refused'; what: 'symlink' | 'not-a-file' };

/** A control file that exists but could not be read. Carries no file content. */
export class ControlFileReadError extends Error {
  constructor(
    readonly filePath: string,
    readonly code: string,
  ) {
    super(`could not read ${filePath} (${code})`);
    this.name = 'ControlFileReadError';
  }
}

const NOFOLLOW: number | undefined = (fs.constants as Record<string, number | undefined>).O_NOFOLLOW;
const NONBLOCK: number = (fs.constants as Record<string, number | undefined>).O_NONBLOCK ?? 0;

function errnoCode(e: unknown): string {
  return (e as NodeJS.ErrnoException | undefined)?.code ?? 'EUNKNOWN';
}

/**
 * Read a control file without following a link.
 *
 * Where `O_NOFOLLOW` exists the open itself refuses a link (`ELOOP`, or
 * `EMLINK` on some BSDs), and `fstat` on the open descriptor must say regular
 * file; reading from that descriptor closes the gap between a check and a
 * read. `O_NONBLOCK` keeps a FIFO from blocking the open. Elsewhere (Windows)
 * it is `lstat`, open, `fstat`, and the two must agree on `dev` and `ino`.
 *
 * A DANGLING link is a refused link, not an absent file: nothing checks
 * existence first, so a link to nowhere never lets a parent directory's file
 * take over. Only ENOENT for the entry itself is absent; any other error is a
 * {@link ControlFileReadError} naming the path and errno, never the content.
 */
export function readRegularFileNoFollow(filePath: string): NoFollowRead {
  let fd: number;
  let lst: fs.Stats | undefined;
  if (NOFOLLOW === undefined) {
    try {
      lst = fs.lstatSync(filePath);
    } catch (e) {
      if (errnoCode(e) === 'ENOENT') return { kind: 'absent' };
      throw new ControlFileReadError(filePath, errnoCode(e));
    }
    if (lst.isSymbolicLink()) return { kind: 'refused', what: 'symlink' };
    if (!lst.isFile()) return { kind: 'refused', what: 'not-a-file' };
  }
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | (NOFOLLOW ?? 0) | NONBLOCK);
  } catch (e) {
    const code = errnoCode(e);
    if (code === 'ENOENT') return { kind: 'absent' };
    if (code === 'ELOOP' || code === 'EMLINK') return { kind: 'refused', what: 'symlink' };
    throw new ControlFileReadError(filePath, code);
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { kind: 'refused', what: 'not-a-file' };
    if (lst !== undefined && (lst.dev !== st.dev || lst.ino !== st.ino)) {
      return { kind: 'refused', what: 'symlink' };
    }
    return { kind: 'file', text: fs.readFileSync(fd, 'utf-8') };
  } catch (e) {
    throw new ControlFileReadError(filePath, errnoCode(e));
  } finally {
    fs.closeSync(fd);
  }
}

/** What an lstat says about a path that is about to be written. */
export function writeTargetKind(filePath: string): 'absent' | 'file' | 'symlink' | 'not-a-file' {
  let st: fs.Stats;
  try {
    st = fs.lstatSync(filePath);
  } catch (e) {
    if (errnoCode(e) === 'ENOENT') return 'absent';
    throw new ControlFileReadError(filePath, errnoCode(e));
  }
  if (st.isSymbolicLink()) return 'symlink';
  return st.isFile() ? 'file' : 'not-a-file';
}

/** Test seam for {@link writeFileAtomically}; absent in production. */
export interface AtomicWriteHooks {
  /** Runs after the temporary file is written and before the rename. */
  beforeRename?: () => void;
}

/**
 * Write `text` to `outPath` through a temporary file in the same directory,
 * opened with `wx` (`O_CREAT | O_EXCL`, which never follows a link), then
 * `fsync`, close, and `rename` over the destination. A rename replaces the
 * directory entry and never writes through a link at the destination, so a
 * link planted after any earlier check is replaced, not followed. On any
 * failure the temporary file is removed and the error rethrown.
 */
export function writeFileAtomically(
  outPath: string,
  text: string,
  mode = 0o644,
  hooks: AtomicWriteHooks = {},
): void {
  const tmp = path.join(
    path.dirname(outPath),
    `${path.basename(outPath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  let fd: number | undefined;
  try {
    fd = fs.openSync(tmp, 'wx', mode);
    fs.writeSync(fd, text);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    // `wx` honours the umask; set the mode the caller asked for.
    fs.chmodSync(tmp, mode);
    hooks.beforeRename?.();
    fs.renameSync(tmp, outPath);
  } catch (e) {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {
        // Already closed or never opened.
      }
    }
    try {
      fs.unlinkSync(tmp);
    } catch {
      // Never created, or already renamed.
    }
    throw e;
  }
}

/** The sentence a refusal prints after the path, shared by every caller. */
export function refusalWhat(what: 'symlink' | 'not-a-file'): string {
  return what === 'symlink' ? 'is a symlink, not a regular file' : 'is not a regular file';
}
