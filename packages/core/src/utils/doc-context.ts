import path from 'path';

/** Directory segments that indicate static documentation / marketing sites. */
const DOC_SITE_SEGMENTS = new Set(['docs', 'doc', 'website']);

/** Config files that routinely embed public search-only API keys. */
const DOC_CONFIG_BASENAMES = new Set(['algolia.js', 'docusaurus.config.js']);

function splitPathParts(filePath: string): string[] {
  return filePath.split(path.sep).flatMap(p => p.split('/'));
}

/**
 * Return `true` when `filePath` lives in a documentation or doc-site tree
 * (e.g. `docs/extra/algolia.js`, `website/docusaurus.config.js`,
 * `docs/tutorial/foo/index.md`).
 */
export function isDocumentationPath(filePath: string): boolean {
  const parts = splitPathParts(filePath);
  if (parts.some(p => DOC_SITE_SEGMENTS.has(p.toLowerCase()))) return true;

  const base = path.basename(filePath).toLowerCase();
  if (DOC_CONFIG_BASENAMES.has(base)) return true;

  return base.endsWith('.md') && parts.some(p => p.toLowerCase() === 'docs');
}

/** Algolia search-only keys are 32-char hex strings shipped in public doc frontends. */
export function isAlgoliaSearchOnlyKey(value: string): boolean {
  return /^[a-f0-9]{32}$/i.test(value);
}

/**
 * Suppress low-precision generic pattern matches that are expected in public
 * documentation (Algolia search keys, tutorial placeholders, etc.).
 */
export function shouldSuppressDocContextMatch(
  patternId: string,
  filePath: string,
  rawValue: string,
  fullMatch: string,
  lineContent: string,
): boolean {
  if (!isDocumentationPath(filePath)) return false;

  if (patternId === 'api-key-generic') {
    const line = lineContent.toLowerCase();
    if (isAlgoliaSearchOnlyKey(rawValue)) return true;
    if (line.includes('algolia') || line.includes('appid')) return true;
    if (/YOUR[_-]?API[_-]?KEY/i.test(fullMatch)) return true;
    if (/insert[_-]?your/i.test(rawValue)) return true;
  }

  return false;
}
