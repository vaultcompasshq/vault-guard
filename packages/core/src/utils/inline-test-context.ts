/**
 * In-file test context.
 *
 * The path heuristics in `path-severity.ts` answer "is this whole file a test
 * file?". Some languages never put unit tests in their own file: Rust's
 * dominant convention is a `#[cfg(test)] mod tests { … }` block at the bottom
 * of the very file that holds the production code, so a throwaway fixture token
 * and a real leaked credential live under the same path and no path rule can
 * separate them.
 *
 * This module locates those in-file test regions from the content itself, so
 * the scanner can grant a match inside one the same severity downgrade a test
 * *path* would grant. The downgrade set is unchanged: only the low-precision
 * rule ids in `LOW_PRECISION_PATH_DOWNGRADE_IDS` are affected, and
 * vendor-anchored provider keys are deliberately left alone under the standing
 * policy that a real provider key is a real key even in a test file.
 *
 * EVERYTHING HERE IS A HEURISTIC. It reads module boundaries line by line
 * rather than parsing Rust, and it does not track brace depth. Three known
 * blind spots remain, and it is worth being precise about which way each one
 * fails, because only the first is safe:
 *
 *   1. An INDENTED `#[cfg(test)]` is ignored, so a test item nested inside an
 *      `impl` or an inner module keeps its full severity. Safe: the finding
 *      survives and the user triages it.
 *   2. A `#[cfg(test)]` written at column 0 inside a raw string or a block
 *      comment opens a region that does not exist. UNSAFE: it demotes real
 *      code that follows.
 *   3. A region runs to end of file unless something closes it, and the
 *      closers are a list of top-level shapes (item keywords, a negated-test
 *      attribute, a macro invocation). Production code resuming in a shape not
 *      on that list leaves the region open over it. UNSAFE, same way.
 *
 * So the module is NOT uniformly tuned toward keeping severity. Cases 2 and 3
 * demote, and the fix for both is the same one this file does not do: parse
 * Rust rather than scan lines. Every closer added to the list narrows case 3
 * without closing it.
 *
 * Adding a language: write a {@link InlineTestRegionFinder} and register it in
 * {@link FINDERS} under its file extensions. Rust is the only one implemented.
 */

/** A half-open `[start, end)` range of content offsets that is test context. */
export interface InlineTestRegion {
  start: number;
  end: number;
}

export interface InlineTestRegionFinder {
  /** Lower-case file extensions (with the dot) this finder claims. */
  readonly extensions: readonly string[];
  /** Locate every in-file test region, in ascending offset order. */
  find(content: string): InlineTestRegion[];
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

/**
 * How a column-0 `#[cfg(…)]` attribute relates to test configuration.
 *
 * - `test`     the predicate is true under `cargo test`: an opener.
 * - `not-test` the predicate negates `test`: an explicit production-only
 *              marker, and therefore a closer.
 * - `other`    the predicate says nothing about `test`.
 */
type RustCfgKind = 'test' | 'not-test' | 'other';

/**
 * Classify the predicate of a column-0 `#[cfg(…)]` attribute.
 *
 * This walks the predicate's structure instead of substring-matching it,
 * because both shortcuts the substring version took were wrong in ways that
 * silently demoted real credentials:
 *
 *   - `#[cfg(all(not(test), feature = "prod"))]` is a production-only marker,
 *     but a "contains the word test" test read it as a test module. `test` now
 *     counts as positive ONLY at not-depth zero: bare `test`, or `test` as a
 *     direct argument of `all(` / `any(`. Any `not(` enclosing it makes the
 *     whole attribute a closer instead.
 *   - `#[cfg(feature = "test-utils")]` matched `\btest\b`, because `-` is a
 *     word boundary, and `test-utils` is an ordinary feature name enabled in
 *     real release builds. String literals are skipped entirely now, so a
 *     feature named `test`, `test-utils` or `testing` can never be read as the
 *     `test` predicate.
 *
 * Column 0 is required by the caller on purpose: rustfmt puts a module-level
 * attribute there, while an *indented* attribute annotates a single item nested
 * inside an `impl` or an inner module, whose extent this line-based scan cannot
 * determine.
 */
export function classifyRustCfgAttribute(line: string): RustCfgKind {
  const open = '#[cfg(';
  if (!line.startsWith(open)) return 'other';

  let depth = 1;             // we are inside the `(` of `cfg(`
  let notFrames = 0;         // how many enclosing `not(` are currently open
  const frameIsNot: boolean[] = [];
  let lastIdent = '';
  let sawPositiveTest = false;
  let sawNegatedTest = false;

  let i = open.length;
  while (i < line.length && depth > 0) {
    const ch = line[i];

    // Skip string literals whole. A feature name is a string, never a
    // predicate, so nothing inside one may contribute a `test` token.
    if (ch === '"') {
      i++;
      while (i < line.length) {
        if (line[i] === '\\') { i += 2; continue; }
        if (line[i] === '"') { i++; break; }
        i++;
      }
      lastIdent = '';
      continue;
    }

    if (/[A-Za-z0-9_]/.test(ch)) {
      let j = i;
      while (j < line.length && /[A-Za-z0-9_]/.test(line[j])) j++;
      const ident = line.slice(i, j);

      // `test` is an atom, never a call. If a `(` follows it is some other
      // predicate function and not the token we are looking for.
      let k = j;
      while (k < line.length && (line[k] === ' ' || line[k] === '\t')) k++;
      const isCall = line[k] === '(';

      if (ident === 'test' && !isCall) {
        if (notFrames > 0) sawNegatedTest = true;
        else sawPositiveTest = true;
      }

      lastIdent = ident;
      i = j;
      continue;
    }

    if (ch === '(') {
      const isNot = lastIdent === 'not';
      frameIsNot.push(isNot);
      if (isNot) notFrames++;
      depth++;
      lastIdent = '';
      i++;
      continue;
    }

    if (ch === ')') {
      depth--;
      if (frameIsNot.pop() === true) notFrames--;
      lastIdent = '';
      i++;
      continue;
    }

    // Whitespace may separate an identifier from its `(`, so it does not clear
    // the pending identifier; anything else does.
    if (ch !== ' ' && ch !== '\t') lastIdent = '';
    i++;
  }

  if (sawPositiveTest) return 'test';
  if (sawNegatedTest) return 'not-test';
  return 'other';
}

/** Any attribute line, so a stack of attributes above an item is skipped. */
const RUST_ATTRIBUTE = /^#!?\[/;

/** Item kinds a `#[cfg(test)]` attribute may introduce for a region to open. */
const RUST_TEST_ITEM =
  /^(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?(?:mod|fn)\b/;

/** Any top-level item start, used to close an open region. */
const RUST_ITEM_START =
  /^(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?(?:mod|fn|impl|struct|enum|union|trait|type|const|static|use|macro_rules!)\b/;

/**
 * A column-0 macro invocation: `lazy_static! {`, `thread_local!(`,
 * `serde_json::json!({`. These declare items at the top level without using an
 * item keyword, so without them the region ran straight past a macro body to
 * end of file and demoted whatever it held. `macro_rules! name {` is a
 * definition, not an invocation, and is already covered by RUST_ITEM_START.
 */
const RUST_MACRO_INVOCATION =
  /^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*!\s*[({[]/;

const rustFinder: InlineTestRegionFinder = {
  extensions: ['.rs'],
  find(content: string): InlineTestRegion[] {
    if (!content.includes('#[cfg(')) return [];

    const lines = content.split('\n');
    const starts: number[] = new Array(lines.length);
    let offset = 0;
    for (let i = 0; i < lines.length; i++) {
      starts[i] = offset;
      offset += lines[i].length + 1; // +1 for the '\n' split consumed
    }

    const regions: InlineTestRegion[] = [];
    let open: number | null = null;
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];

      // Only column-0 constructs are considered. See RUST_CFG_TEST.
      if (line.length === 0 || line[0] === ' ' || line[0] === '\t') {
        i++;
        continue;
      }

      const cfgKind = classifyRustCfgAttribute(line);

      if (cfgKind === 'test') {
        // Find the item this attribute (and any stacked below it) introduces.
        let j = i + 1;
        while (j < lines.length && (lines[j].trim() === '' || RUST_ATTRIBUTE.test(lines[j]))) {
          j++;
        }
        if (j < lines.length && RUST_TEST_ITEM.test(lines[j])) {
          // A run of consecutive cfg(test) items is one region, not several.
          if (open === null) open = starts[i];
          i = j + 1;
          continue;
        }
        // Attribute on something other than a mod/fn: not a test module.
        i++;
        continue;
      }

      if (
        open !== null &&
        (cfgKind === 'not-test' ||
          RUST_ITEM_START.test(line) ||
          RUST_MACRO_INVOCATION.test(line))
      ) {
        // Production code resumed. Rust convention puts the test module last,
        // so in practice a region usually runs to end of file and this closer
        // only fires on the less common mid-file placement.
        regions.push({ start: open, end: starts[i] });
        open = null;
      }

      i++;
    }

    if (open !== null) regions.push({ start: open, end: content.length });
    return regions;
  },
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const FINDERS: readonly InlineTestRegionFinder[] = [rustFinder];

function finderFor(filePath: string): InlineTestRegionFinder | undefined {
  const dot = filePath.lastIndexOf('.');
  if (dot === -1) return undefined;
  const ext = filePath.slice(dot).toLowerCase();
  return FINDERS.find(f => f.extensions.includes(ext));
}

/**
 * Locate in-file test regions for `content`. Returns an empty array when the
 * file's language has no finder registered, or when `filePath` is unknown.
 */
export function findInlineTestRegions(
  content: string,
  filePath: string | undefined,
): InlineTestRegion[] {
  if (!filePath) return [];
  const finder = finderFor(filePath);
  if (!finder) return [];
  return finder.find(content);
}

/** True when `offset` falls inside any of `regions`. */
export function isInsideInlineTestRegion(
  regions: readonly InlineTestRegion[],
  offset: number,
): boolean {
  for (const r of regions) {
    if (offset >= r.start && offset < r.end) return true;
  }
  return false;
}
