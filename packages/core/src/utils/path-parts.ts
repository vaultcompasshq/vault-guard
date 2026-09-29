import path from 'path';

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
  const rel = path.relative(path.resolve(root), path.resolve(filePath));
  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return path.basename(filePath);
  }
  return rel;
}
