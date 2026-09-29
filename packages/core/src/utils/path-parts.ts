import fs from 'fs';
import path from 'path';

/** Absolute, symlinks resolved when the path exists (macOS /var vs /private/var). */
function canonical(p: string): string {
  const abs = path.resolve(p);
  try {
    return fs.realpathSync.native(abs);
  } catch {
    // A path that does not exist (a staged file deleted from the worktree):
    // resolve its parent instead, so it still lines up with a canonical root.
    try {
      return path.join(fs.realpathSync.native(path.dirname(abs)), path.basename(abs));
    } catch {
      return abs;
    }
  }
}

/**
 * Split a file path into directory/file segments (handles mixed `/` and platform sep).
 */
export function splitPathParts(filePath: string): string[] {
  return filePath.split(/[/\\]/).filter(Boolean);
}

/**
 * The path that test / documentation / locale context is judged on.
 *
 * Context words (`docs`, `tests`, `examples`, anything ending in `test`) must
 * come from the tree being scanned, never from wherever that tree happens to
 * be checked out. The Action scans an absolute root and `--staged` hands over
 * absolute paths, so a checkout under `/home/runner/work/docs/docs` or
 * `/tmp/loadtest/repo` would otherwise make every file in it a "docs" or
 * "test" file and quietly downgrade its findings.
 *
 * With a `root`, this is `filePath` relative to it (resolved against the
 * process cwd when relative, the way the file itself is opened). A file that
 * is not under the root has no trustworthy directory context at all, so only
 * its basename is used. Without a root the path is returned as given, which is
 * the behaviour library callers who pass root-relative paths already rely on.
 */
export function contextPathFor(filePath: string, root?: string): string {
  if (root === undefined) return filePath;
  const rel = path.relative(canonical(root), canonical(filePath));
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return path.basename(filePath);
  }
  return rel;
}
