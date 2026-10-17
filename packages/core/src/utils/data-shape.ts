import type { ContentDemotion, GroupSlot } from '../types';
import { BINARY_TYPES, FrozenMap, SNIFF_BYTES, confirmsBareRun, confirmsBinary } from './binary-type';

/**
 * Encoded-payload demotion and data-file shape (design 2026-10-17 data
 * files, sections 3, 5 and 6.1).
 *
 * A key-shaped match is demoted to `low` only when all four hold:
 *
 *   C1. every character of the FULL match is in the base64 alphabet
 *       (A-Z, a-z, 0-9, +, /, -, _; never `=`), so it lies in one run;
 *   C2. the run has at least one alphabet character before the match and
 *       one after it;
 *   C3. the run is at least {@link MIN_RUN} characters;
 *   C4. the run's decoded head confirms a binary format: for a `data:`
 *       payload, the row its declared media type maps to in
 *       {@link MEDIA_TYPE_ROWS}, through `confirmsBinary`; for a run with no
 *       `data:` prefix, one of the two headers in `BARE_RUN_SIGNATURES`.
 *
 * Every threshold and table here is a constant of the published package.
 * Nothing reads a file name, a path, a config key, a flag, an environment
 * variable or a file in the scanned tree.
 */

/** C3: a run this long is an encoded object, not a credential. */
export const MIN_RUN = 1024;
/** Characters of a run decoded for C4 (5464 characters are 4098 bytes, cut to {@link SNIFF_BYTES}). */
export const HEAD_CHARS = 5464;
/** How far back from a run start the `data:` prefix is looked for. */
export const DATA_PREFIX_LOOKBACK = 256;
/** Matches of one key needed to form a group. */
export const GROUP_MIN = 5;
/** Member locations a group lists. */
export const GROUP_LISTED = 5;
/** A line this long or longer is a long line. */
export const LONG_LINE = 65536;
/** Non-empty lines a copy needs to be called delimited. */
export const DELIMITED_MIN_LINES = 20;
/** Share of non-empty lines that must split into the same field count. */
export const DELIMITED_SHARE = 0.9;
/** The delimiters tried, in tie-break order. */
export const DELIMITERS: readonly string[] = Object.freeze([',', '\t', ';', '|']);

/** The union of the standard and URL-safe alphabets. Padding `=` is not in it. */
export function isBase64Char(c: number): boolean {
  return (
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) || // a-z
    (c >= 0x30 && c <= 0x39) || // 0-9
    c === 0x2b || // +
    c === 0x2f || // /
    c === 0x2d || // -
    c === 0x5f // _
  );
}

/** Section 3.3: declared media type to its binary-table row. A constant. */
export const MEDIA_TYPE_ROWS: ReadonlyMap<string, string> = new FrozenMap<string, string>(
  [
    ['image/png', '.png'],
    ['image/jpeg', '.jpg'],
    ['image/jpg', '.jpg'],
    ['image/pjpeg', '.jpg'],
    ['image/gif', '.gif'],
    ['image/x-icon', '.ico'],
    ['image/vnd.microsoft.icon', '.ico'],
    ['image/webp', '.webp'],
    ['image/bmp', '.bmp'],
    ['image/tiff', '.tiff'],
    ['image/avif', '.avif'],
    ['image/heic', '.heic'],
    ['image/heif', '.heif'],
    ['application/pdf', '.pdf'],
    ['font/woff', '.woff'],
    ['application/font-woff', '.woff'],
    ['application/x-font-woff', '.woff'],
    ['font/woff2', '.woff2'],
    ['font/ttf', '.ttf'],
    ['application/x-font-ttf', '.ttf'],
    ['application/x-font-truetype', '.ttf'],
    ['font/otf', '.otf'],
    ['application/x-font-opentype', '.otf'],
    ['application/vnd.ms-fontobject', '.eot'],
    ['audio/mpeg', '.mp3'],
    ['audio/wav', '.wav'],
    ['audio/wave', '.wav'],
    ['audio/x-wav', '.wav'],
    ['audio/ogg', '.ogg'],
    ['audio/flac', '.flac'],
    ['audio/mp4', '.m4a'],
    ['audio/webm', '.weba'],
    ['video/mp4', '.mp4'],
    ['video/webm', '.webm'],
    ['video/ogg', '.ogv'],
    ['application/zip', '.zip'],
    ['application/gzip', '.gz'],
  ],
  'the media type table',
);

/** The row a declared media type maps to: lowercased, parameters ignored. */
export function mediaTypeRow(declared: string): string | undefined {
  const type = declared.split(';')[0].trim().toLowerCase();
  return MEDIA_TYPE_ROWS.get(type);
}

/** A run: `[start, end)` in the copy's text. */
export interface RunSpan {
  start: number;
  end: number;
}

type RunVerdict = Omit<ContentDemotion, 'from' | 'run_length'> | null;

interface RunEntry extends RunSpan {
  /** C4 for this run, decided once: undefined until asked. */
  verdict?: RunVerdict;
}

/**
 * Every run of {@link MIN_RUN} characters or more in `text`, in order, from
 * one linear sweep. Exposed through {@link internals} so a test can count
 * the sweeps.
 */
function sweepRuns(text: string): RunEntry[] {
  const out: RunEntry[] = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    if (!isBase64Char(text.charCodeAt(i))) {
      i++;
      continue;
    }
    let j = i + 1;
    while (j < n && isBase64Char(text.charCodeAt(j))) j++;
    if (j - i >= MIN_RUN) out.push({ start: i, end: j });
    i = j;
  }
  return out;
}

/**
 * The run boundaries of one copy, found by ONE linear sweep the first time
 * they are asked for (section 6.1). Each lookup is a binary search, so a run
 * packed with matches costs its length once, not once per match.
 */
export class RunIndex {
  private runs: RunEntry[] | undefined;
  /** How many sweeps this index has made: one at most. */
  sweeps = 0;

  constructor(private readonly text: string) {}

  /** The run of {@link MIN_RUN} or more characters containing `offset`, if any. */
  find(offset: number): RunEntry | undefined {
    if (this.runs === undefined) {
      this.runs = internals.sweepRuns(this.text);
      this.sweeps++;
    }
    const runs = this.runs;
    let lo = 0;
    let hi = runs.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const r = runs[mid];
      if (offset < r.start) hi = mid - 1;
      else if (offset >= r.end) lo = mid + 1;
      else return r;
    }
    return undefined;
  }

  /** C4 for one run, decided once and cached. */
  verdict(run: RunEntry): RunVerdict {
    if (run.verdict === undefined) run.verdict = decideRun(this.text, run);
    return run.verdict;
  }
}

/** C1 on the full match: every character of `[offset, offset + length)` is in the alphabet. */
function allBase64(text: string, offset: number, length: number): boolean {
  if (length <= 0 || offset < 0 || offset + length > text.length) return false;
  for (let i = offset; i < offset + length; i++) if (!isBase64Char(text.charCodeAt(i))) return false;
  return true;
}

/**
 * The run containing a match, or undefined when C1 fails or the run is
 * shorter than {@link MIN_RUN} (the sweep records only runs that long).
 */
export function runAround(text: string, offset: number, length: number, index: RunIndex = new RunIndex(text)): RunSpan | undefined {
  if (!allBase64(text, offset, length)) return undefined;
  const run = index.find(offset);
  return run ? { start: run.start, end: run.end } : undefined;
}

/**
 * The decoded head of a run (U2): its first `min(length, 5464)` characters,
 * cut to a multiple of 4, decoded as standard base64 when the run has no `-`
 * or `_` and as URL-safe when it has no `+` or `/`, then cut to
 * {@link SNIFF_BYTES}. Undefined for a run that mixes the two alphabets.
 */
export function decodeRunHead(text: string, start: number, end: number): Uint8Array | undefined {
  let standard = false;
  let urlSafe = false;
  for (let i = start; i < end; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x2b || c === 0x2f) standard = true;
    else if (c === 0x2d || c === 0x5f) urlSafe = true;
    if (standard && urlSafe) return undefined;
  }
  const n = Math.min(end - start, HEAD_CHARS);
  const chunk = text.slice(start, start + (n - (n % 4)));
  const bytes = Buffer.from(chunk, urlSafe ? 'base64url' : 'base64');
  return bytes.length > SNIFF_BYTES ? bytes.subarray(0, SNIFF_BYTES) : bytes;
}

const DATA_PREFIX_RE = /^data:([^;,\s]*)((?:;[^;,\s]*)*);base64,$/i;

/**
 * Section 3.1: when the run starts right after a case-insensitive
 * `;base64,` that closes `data:<type>/<subtype>[;param=value]*;base64,`
 * within {@link DATA_PREFIX_LOOKBACK} characters, the declared media type,
 * lowercased with parameters dropped. `''` for a `data:` prefix whose type
 * is empty or malformed (it then maps to no row and C4 fails). Undefined for
 * a bare run.
 */
export function dataUriMediaType(text: string, runStart: number): string | undefined {
  const from = Math.max(0, runStart - DATA_PREFIX_LOOKBACK);
  const window = text.slice(from, runStart);
  const lower = window.toLowerCase();
  if (!lower.endsWith(';base64,')) return undefined;
  const at = lower.lastIndexOf('data:');
  if (at < 0) return undefined;
  const m = DATA_PREFIX_RE.exec(window.slice(at));
  if (!m) return '';
  const type = m[1].toLowerCase();
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(type) ? type : '';
}

/** C4 for one run. */
function decideRun(text: string, run: RunSpan): RunVerdict {
  const head = decodeRunHead(text, run.start, run.end);
  if (head === undefined) return null;
  const declared = dataUriMediaType(text, run.start);
  if (declared !== undefined) {
    const row = MEDIA_TYPE_ROWS.get(declared);
    if (row === undefined || !confirmsBinary(row, head)) return null;
    const family = BINARY_TYPES.get(row)?.family;
    if (family === undefined) return null;
    return { reason: 'data-uri-binary-payload', family, format: row, media_type: declared };
  }
  const bare = confirmsBareRun(head);
  if (bare === undefined) return null;
  return { reason: 'base64-binary-run', family: bare.family, format: bare.format };
}

/**
 * C1 to C4 for one match: the demotion record without `from`, or undefined.
 * Pass one {@link RunIndex} per copy so the sweep runs once.
 */
export function encodedPayloadDemotion(
  text: string,
  match: { offset: number; matchLength: number },
  index: RunIndex = new RunIndex(text),
): Omit<ContentDemotion, 'from'> | undefined {
  const start = match.offset;
  const end = start + match.matchLength;
  // The cheap form of C2 first: an alphabet character on each side.
  if (start <= 0 || end >= text.length) return undefined;
  if (!isBase64Char(text.charCodeAt(start - 1)) || !isBase64Char(text.charCodeAt(end))) return undefined;
  if (!allBase64(text, start, match.matchLength)) return undefined;
  const run = index.find(start);
  if (run === undefined) return undefined;
  const verdict = index.verdict(run);
  if (verdict === null) return undefined;
  return { ...verdict, run_length: run.end - run.start };
}

// ---------------------------------------------------------------------------
// Data-file shape (section 5.1)
// ---------------------------------------------------------------------------

export interface DataShape {
  /** Offset of each line's first character; index i is line i + 1. */
  lineStarts: number[];
  /** Set when the copy is a delimited table. */
  delimited?: {
    delimiter: string;
    /** The shared field count `k` of the regular lines. */
    fields: number;
    /** 1 at index i when line i + 1 is regular. */
    regular: Uint8Array;
  };
  /** 1-based numbers of the lines of {@link LONG_LINE} characters or more. */
  longLines: Set<number>;
}

/** End of line `i` (0-based), excluding the newline and a carriage return before it. */
function lineEnd(text: string, starts: number[], i: number): number {
  let end = i + 1 < starts.length ? starts[i + 1] - 1 : text.length;
  if (end > starts[i] && text.charCodeAt(end - 1) === 0x0d) end--;
  return end;
}

/**
 * Split one line into fields with RFC 4180 quoting: a field that opens with
 * a double quote runs to its closing quote (a doubled quote is a literal
 * quote), so a delimiter inside it does not split. Calls `onField` with each
 * field's span and returns the count.
 */
function splitFields(
  text: string,
  start: number,
  end: number,
  delim: number,
  onField?: (s: number, e: number) => void,
): number {
  let count = 0;
  let i = start;
  for (;;) {
    const fieldStart = i;
    if (i < end && text.charCodeAt(i) === 0x22) {
      i++;
      while (i < end) {
        if (text.charCodeAt(i) === 0x22) {
          if (i + 1 < end && text.charCodeAt(i + 1) === 0x22) {
            i += 2;
            continue;
          }
          i++;
          break;
        }
        i++;
      }
    }
    while (i < end && text.charCodeAt(i) !== delim) i++;
    count++;
    onField?.(fieldStart, i);
    if (i >= end) return count;
    i++;
    if (i === end) {
      count++;
      onField?.(end, end);
      return count;
    }
  }
}

/** For each line, how many times `ch` occurs in it, from one native indexOf walk. */
function perLineCounts(text: string, ch: string, starts: number[], ends: Int32Array): Int32Array {
  const counts = new Int32Array(starts.length);
  let li = 0;
  for (let p = text.indexOf(ch); p >= 0; p = text.indexOf(ch, p + 1)) {
    while (li + 1 < starts.length && starts[li + 1] <= p) li++;
    if (p < ends[li]) counts[li]++;
  }
  return counts;
}

/** The 5.1 classification of one copy. Computed once per copy, only when a rule produced {@link GROUP_MIN} matches. */
function classify(text: string): DataShape {
  const lineStarts = [0];
  for (let p = text.indexOf('\n'); p >= 0; p = text.indexOf('\n', p + 1)) lineStarts.push(p + 1);
  // A trailing newline does not start a line.
  if (lineStarts.length > 1 && lineStarts[lineStarts.length - 1] === text.length) lineStarts.pop();
  const ends = new Int32Array(lineStarts.length);
  for (let i = 0; i < lineStarts.length; i++) ends[i] = lineEnd(text, lineStarts, i);

  const longLines = new Set<number>();
  const nonEmpty: number[] = [];
  for (let i = 0; i < lineStarts.length; i++) {
    const len = ends[i] - lineStarts[i];
    if (len > 0) nonEmpty.push(i);
    if (len >= LONG_LINE) longLines.add(i + 1);
  }

  let best: DataShape['delimited'] | undefined;
  let bestRegular = -1;
  if (nonEmpty.length >= DELIMITED_MIN_LINES) {
    const quotes = perLineCounts(text, '"', lineStarts, ends);
    for (const delimiter of DELIMITERS) {
      const code = delimiter.charCodeAt(0);
      const occurrences = perLineCounts(text, delimiter, lineStarts, ends);
      // A regular line has at least two fields, so at least one delimiter:
      // too few lines with any cannot reach the share, and are not split.
      let withAny = 0;
      for (const i of nonEmpty) if (occurrences[i] > 0) withAny++;
      if (withAny * 10 < nonEmpty.length * DELIMITED_SHARE * 10) continue;
      const perLine = new Int32Array(lineStarts.length);
      const tally = new Map<number, number>();
      for (const i of nonEmpty) {
        const s = lineStarts[i];
        const e = ends[i];
        let k: number;
        let firstEmpty: boolean;
        let lastEmpty: boolean;
        if (quotes[i] === 0) {
          // No quote on the line: every delimiter splits.
          k = occurrences[i] + 1;
          firstEmpty = text.charCodeAt(s) === code;
          lastEmpty = text.charCodeAt(e - 1) === code;
        } else {
          let n = 0;
          let fe0 = false;
          let le = false;
          k = splitFields(text, s, e, code, (fs, fe) => {
            if (n === 0) fe0 = fe === fs;
            le = fe === fs;
            n++;
          });
          firstEmpty = fe0;
          lastEmpty = le;
        }
        // Source code, not data: one trailing delimiter (`x = 1;`), and
        // under tab only, indentation.
        if (k === 2 && lastEmpty) continue;
        if (code === 0x09 && firstEmpty) continue;
        if (k < 2) continue;
        perLine[i] = k;
        tally.set(k, (tally.get(k) ?? 0) + 1);
      }
      let k = 0;
      let count = 0;
      for (const [fields, c] of tally) {
        if (c > count || (c === count && fields < k)) {
          k = fields;
          count = c;
        }
      }
      // At least 90 percent, in integers: count / total >= 9 / 10.
      if (k >= 2 && count * 10 >= nonEmpty.length * DELIMITED_SHARE * 10 && count > bestRegular) {
        const regular = new Uint8Array(lineStarts.length);
        for (let i = 0; i < perLine.length; i++) if (perLine[i] === k) regular[i] = 1;
        best = { delimiter, fields: k, regular };
        bestRegular = count;
      }
    }
  }
  return { lineStarts, ...(best ? { delimited: best } : {}), longLines };
}

/** Exposed so tests can count sweeps and classifications. Production code calls through it. */
export const internals = { sweepRuns, classify };

/** Section 5.1 for one copy. */
export function dataShape(text: string): DataShape {
  return internals.classify(text);
}

/** True when the shape can give any match a slot. */
export function hasSlots(shape: DataShape): boolean {
  return shape.delimited !== undefined || shape.longLines.size > 0;
}

/**
 * Section 5.2: the slot of one match. A match that lies entirely within one
 * field of a regular line is in that field's column; otherwise a match on a
 * long line is in `long-line`; otherwise it has no slot.
 */
export function groupSlot(
  shape: DataShape,
  text: string,
  match: { offset: number; matchLength: number; line: number },
): GroupSlot | undefined {
  const i = match.line - 1;
  if (i < 0 || i >= shape.lineStarts.length) return undefined;
  const s = shape.lineStarts[i];
  const e = lineEnd(text, shape.lineStarts, i);
  const mStart = match.offset;
  const mEnd = match.offset + match.matchLength;
  if (mStart < s || mEnd > e) return undefined;
  const d = shape.delimited;
  if (d && d.regular[i] === 1) {
    let column = -1;
    let index = 0;
    splitFields(text, s, e, d.delimiter.charCodeAt(0), (fs, fe) => {
      if (column < 0 && mStart >= fs && mEnd <= fe) column = index;
      index++;
    });
    if (column >= 0) return { basis: 'column', delimiter: d.delimiter, column };
  }
  if (shape.longLines.has(match.line)) return { basis: 'long-line' };
  return undefined;
}
