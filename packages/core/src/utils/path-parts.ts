/**
 * Split a file path into directory/file segments (handles mixed `/` and platform sep).
 */
export function splitPathParts(filePath: string): string[] {
  return filePath.split(/[/\\]/).filter(Boolean);
}
