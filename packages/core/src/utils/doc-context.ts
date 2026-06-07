import path from 'path';
import { isRedactedTemplateValue } from './placeholder';
import { splitPathParts } from './path-parts';

/** Directory segments that indicate static documentation / marketing sites. */
const DOC_SITE_SEGMENTS = new Set(['docs', 'doc', 'website']);

/** Config files that routinely embed public search-only API keys. */
const DOC_CONFIG_BASENAMES = new Set(['algolia.js', 'docusaurus.config.js']);

/** Root-level / guide markdown basenames (case-insensitive). */
const DOC_MARKDOWN_NAME = /\.(md|mdx)$/i;
const DOC_NAMED_MARKDOWN =
  /^(README|CLAUDE|CONTRIBUTING|CHANGELOG|CONFLICTS_README|.*GUIDE.*|.*SETUP.*|.*SUMMARY.*)$/i;

/**
 * Return `true` when `filePath` lives in a documentation or doc-site tree
 * (e.g. `docs/extra/algolia.js`, `website/docusaurus.config.js`, `README.md`,
 * `docs/tutorial/foo/index.md`, `CLAUDE.md`).
 */
export function isDocumentationPath(filePath: string): boolean {
  const parts = splitPathParts(filePath);
  if (parts.some(p => DOC_SITE_SEGMENTS.has(p.toLowerCase()))) return true;

  const base = path.basename(filePath);
  const baseLower = base.toLowerCase();
  if (DOC_CONFIG_BASENAMES.has(baseLower)) return true;

  if (DOC_MARKDOWN_NAME.test(base)) return true;

  const stem = base.replace(/\.(md|mdx)$/i, '');
  if (DOC_NAMED_MARKDOWN.test(stem)) return true;

  return false;
}

/** Algolia search-only keys are 32-char hex strings shipped in public doc frontends. */
export function isAlgoliaSearchOnlyKey(value: string): boolean {
  return /^[a-f0-9]{32}$/i.test(value);
}

/**
 * Return `true` when `byteOffset` falls inside a Python triple-quoted string
 * region (`"""…"""` or `'''…'''`, optional `r` prefix). Used to skip generic
 * assignment patterns inside module docstring examples (e.g. Ansible `EXAMPLES`).
 */
export function isInsidePythonTripleQuoted(content: string, byteOffset: number): boolean {
  const len = content.length;
  let i = 0;
  while (i < len - 2) {
    let quote = '';
    if (content.startsWith('"""', i) || content.startsWith("'''", i)) {
      quote = content.slice(i, i + 3);
    } else if (
      (content[i] === 'r' || content[i] === 'R') &&
      (content.startsWith('"""', i + 1) || content.startsWith("'''", i + 1))
    ) {
      quote = content.slice(i + 1, i + 4);
      i += 1;
    }
    if (quote) {
      const start = i + 3;
      const close = content.indexOf(quote, start);
      if (close === -1) return false;
      if (byteOffset >= start && byteOffset < close) return true;
      i = close + 3;
      continue;
    }
    i++;
  }
  return false;
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

  if (isRedactedTemplateValue(rawValue)) return true;

  if (patternId === 'api-key-generic') {
    const line = lineContent.toLowerCase();
    if (isAlgoliaSearchOnlyKey(rawValue)) return true;
    if (line.includes('algolia') || line.includes('appid')) return true;
    if (/YOUR[_-]?API[_-]?KEY/i.test(fullMatch)) return true;
    if (/insert[_-]?your/i.test(rawValue)) return true;
    if (/your_[a-z0-9_]+_key/i.test(rawValue)) return true;
  }

  if (patternId === 'password-in-code' && /MySekret/i.test(rawValue)) return true;

  return false;
}
