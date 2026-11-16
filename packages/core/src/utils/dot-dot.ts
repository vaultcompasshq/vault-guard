import path from 'path';

/**
 * Whether a `path.relative` result climbs out of its base: it is `..` or
 * starts with the `..` segment followed by a separator.
 *
 * NOT `rel.startsWith('..')`. That also matches a path whose first segment
 * merely begins with two dots, such as `..env` or `..cfg/creds.txt`, which is
 * inside the base. Every site that used it treated such a file as outside
 * the repository and dropped it without a word, so a committed secret in
 * `..env` was never scanned. An absolute result (another drive on Windows)
 * is the caller's to check with `isAbsolute`, as before.
 *
 * `impl` is `path.win32` where a caller judges a Windows-style path on any
 * host; there both separators count, since Windows accepts either.
 */
export function climbsOut(rel: string, impl: typeof path = path): boolean {
  if (rel === '..') return true;
  if (rel.startsWith('../')) return true;
  return impl.sep === '\\' && rel.startsWith('..\\');
}
