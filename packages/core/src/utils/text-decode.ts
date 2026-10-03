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

