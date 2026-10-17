/**
 * The one place file and blob bytes become text for scanning.
 *
 * Reading everything as UTF-8 turns a UTF-16 file into garbage with a NUL
 * between every character, so a key inside it never matches and the run passes
 * without saying so. PowerShell 5 redirection (`> out.txt`) writes UTF-16LE
 * with a BOM, so this happens by accident on ordinary Windows machines.
 *
 * Only a BOM is trusted:
 *   - `FF FE`     UTF-16LE
 *   - `FE FF`     UTF-16BE (bytes swapped, then read as UTF-16LE)
 *   - `EF BB BF`  UTF-8 (BOM dropped)
 *   - anything else is UTF-8, as before.
 *
 * BOM-less UTF-16 is NOT detected. Guessing from NUL density would misfire on
 * binary blobs, and this scanner would then report garbage findings on them.
 * That is a known, documented gap (docs/INVARIANTS.md).
 *
 * The BOM is always removed from the returned text so line and column numbers
 * describe the decoded text.
 */

type Encoding = 'utf8' | 'utf16le' | 'utf16be';

interface Sniffed {
  encoding: Encoding;
  bomBytes: number;
}

function sniffBom(head: Uint8Array): Sniffed {
  if (head.length >= 2 && head[0] === 0xff && head[1] === 0xfe) {
    return { encoding: 'utf16le', bomBytes: 2 };
  }
  if (head.length >= 2 && head[0] === 0xfe && head[1] === 0xff) {
    return { encoding: 'utf16be', bomBytes: 2 };
  }
  if (head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf) {
    return { encoding: 'utf8', bomBytes: 3 };
  }
  return { encoding: 'utf8', bomBytes: 0 };
}

/** Swap byte pairs in a copy, dropping a trailing odd byte. */
function swapPairs(buf: Uint8Array): Buffer {
  const even = buf.length - (buf.length % 2);
  return Buffer.from(buf.subarray(0, even)).swap16();
}

/** Decode a whole buffer (file, or git blob) to text for scanning. */
export function decodeTextBuffer(buf: Buffer): string {
  const { encoding, bomBytes } = sniffBom(buf);
  const body = buf.subarray(bomBytes);
  if (encoding === 'utf16le') return body.toString('utf16le');
  if (encoding === 'utf16be') return swapPairs(body).toString('utf16le');
  return body.toString('utf8');
}

/**
 * The labels a `working-tree-encoding` attribute may carry that this scanner
 * decodes, keyed on the upper-cased label git was given, mapped to the WHATWG
 * name `TextDecoder` takes. `null` routes to the BOM sniff: git writes those
 * labels with a BOM, and `TextDecoder('UTF-16')` is little-endian only, so it
 * must never see that label.
 *
 * An explicit map, not the label handed straight to `TextDecoder`:
 * `TextDecoder('UTF-16LE-BOM')` and `TextDecoder('UTF-32')` throw.
 */
const WORKTREE_ENCODING_MAP: ReadonlyMap<string, string | null> = (() => {
  const m = new Map<string, string | null>([
    ['UTF-16LE', 'utf-16le'],
    ['UTF-16BE', 'utf-16be'],
    ['UTF-8', null],
    ['UTF-16', null],
    ['SHIFT_JIS', 'shift_jis'],
    ['SJIS', 'shift_jis'],
    ['CP932', 'shift_jis'],
    ['EUC-JP', 'euc-jp'],
    ['ISO-2022-JP', 'iso-2022-jp'],
    ['EUC-KR', 'euc-kr'],
    ['GBK', 'gbk'],
    ['GB18030', 'gb18030'],
    ['BIG5', 'big5'],
    ['KOI8-R', 'koi8-r'],
    ['KOI8-U', 'koi8-u'],
  ]);
  for (let n = 1250; n <= 1258; n++) m.set(`WINDOWS-${n}`, `windows-${n}`);
  // The ISO-8859 parts the WHATWG Encoding standard defines labels for. There
  // is no part 12. Parts 1, 9 and 11 are labels of windows-1252, windows-1254
  // and windows-874 there; TextDecoder accepts them under these labels. Part
  // 16 is defined by WHATWG but Node 22's TextDecoder rejects it, so it is
  // left out and a copy declared ISO-8859-16 is reported as undecodable.
  for (const n of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15]) {
    m.set(`ISO-8859-${n}`, `iso-8859-${n}`);
  }
  return m;
})();

/**
 * The WHATWG decoder name for an upper-cased `working-tree-encoding` label:
 * a name, `null` for a label routed to the BOM sniff, or undefined for a
 * label outside the map.
 */
export function worktreeEncodingName(upperLabel: string): string | null | undefined {
  return WORKTREE_ENCODING_MAP.get(upperLabel);
}

/** Every label the map decodes, for the test that constructs each decoder. */
export function mappedWorktreeEncodings(): ReadonlyMap<string, string | null> {
  return WORKTREE_ENCODING_MAP;
}

/** One decoded form of a working-tree copy. */
export interface DecodedDiskCopy {
  /** The texts to scan: one, or two for a filtered copy with a declared label. */
  texts: string[];
  /** The declared label, when it could not be honoured (scanned as UTF-8). */
  unsupported?: string;
}

/**
 * Decode the WORKING-TREE copy of a tracked file (design 2026-10-12, 2.4).
 * Blobs never come through here: git stores the canonical bytes, so they go
 * through {@link decodeTextBuffer}.
 *
 *  1. A BOM always wins, whatever the attribute says.
 *  2. No BOM and a label the map knows: that encoding.
 *  3. Anything else (UTF-32, an unknown label, a decoder that throws): the
 *     BOM sniff and UTF-8, and the label is returned as unsupported so the
 *     run can report a coverage gap on this copy. Never a failure: the blob
 *     was scanned whatever happens here.
 *
 * A copy that also carries a `filter` attribute is decoded both ways when a
 * label applies: a smudge filter can write any encoding, and the label
 * describes git's own conversion, not the filter's output.
 */
export function decodeDiskCopy(buf: Buffer, label?: string, filtered = false): DecodedDiskCopy {
  const sniffed = decodeTextBuffer(buf);
  if (label === undefined || label.length === 0) return { texts: [sniffed] };
  if (sniffBom(buf).bomBytes > 0) return { texts: [sniffed] };
  const upper = label.toUpperCase();
  if (upper.endsWith('-BOM')) return { texts: [sniffed] };
  if (!WORKTREE_ENCODING_MAP.has(upper)) return { texts: [sniffed], unsupported: label };
  const name = WORKTREE_ENCODING_MAP.get(upper) ?? null;
  if (name === null) return { texts: [sniffed] };
  let declared: string;
  try {
    declared = new TextDecoder(name).decode(buf);
  } catch {
    return { texts: [sniffed], unsupported: label };
  }
  return { texts: filtered ? [declared, sniffed] : [declared] };
}

