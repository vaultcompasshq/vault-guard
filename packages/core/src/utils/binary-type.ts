import path from 'path';

import { worktreeEncodingName } from './text-decode';

/**
 * Binary skips by content agreement (design 2026-10-17, sections 2 and 3).
 *
 * The name proposes, the bytes must agree. A copy of a file is skipped as
 * binary only when:
 *
 *   R1. its lowercased last extension is in {@link BINARY_TYPES};
 *   R3. its first {@link SNIFF_BYTES} bytes carry one of that extension's
 *       signatures at the stated offset;
 *   R4. those bytes do not start with a byte order mark, and carry the
 *       non-text evidence the matched signature kind requires:
 *         - a binary signature (one with a byte outside printable ASCII):
 *           a NUL, a control byte or invalid UTF-8;
 *         - a printable signature: a NUL or a control byte;
 *         - no signature (`.bin`): a control byte only.
 *       A copy with a declared working-tree-encoding whose head decodes in
 *       that encoding, or whose label is outside the label map, is never
 *       confirmed.
 *
 * A control byte is a C0 byte other than NUL, BEL, BS, tab, LF, VT, FF, CR,
 * SUB and ESC. Content alone never causes a skip: this module only ever
 * vetoes a skip the name proposed. Every constant here is part of the
 * published package; nothing reads it from config, the environment or the
 * scanned tree.
 */

/** How many leading bytes of a copy are judged. The largest offset any signature needs is 262 (tar). */
export const SNIFF_BYTES = 4096;

export type BinaryFamily = 'image' | 'document' | 'video' | 'audio' | 'font' | 'archive' | 'executable' | 'other';

/** The families in table order, for the per-family counts. */
export const BINARY_FAMILIES: readonly BinaryFamily[] = Object.freeze([
  'image',
  'document',
  'video',
  'audio',
  'font',
  'archive',
  'executable',
  'other',
] as BinaryFamily[]);

/** Bytes that must sit at an offset from the start of the copy. */
export interface SignaturePart {
  readonly offset: number;
  readonly bytes: readonly number[];
}

/** One signature: every part must match. */
export type Signature = readonly SignaturePart[];

export interface BinaryTypeRow {
  readonly family: BinaryFamily;
  /** Alternatives; any one matching is enough. Empty for a signature-less row. */
  readonly signatures: readonly Signature[];
}

const b = (...bytes: number[]): number[] => bytes;
const s = (text: string): number[] => [...Buffer.from(text, 'latin1')];
const at = (offset: number, bytes: number[]): SignaturePart => Object.freeze({ offset, bytes: Object.freeze(bytes) });
const one = (offset: number, bytes: number[]): Signature => Object.freeze([at(offset, bytes)]);

const ISO_ATOMS = ['ftyp', 'moov', 'mdat', 'free', 'skip', 'wide', 'pnot'].map(a => one(4, s(a)));
const EBML = [one(0, b(0x1a, 0x45, 0xdf, 0xa3))];
const ASF = [one(0, b(0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11))];
const OGG = [one(0, s('OggS'))];
const ID3 = one(0, s('ID3'));
const FONT_TRUE = one(0, b(0x00, 0x01, 0x00, 0x00));

const ROWS: Array<[BinaryFamily, string[], Signature[]]> = [
  ['image', ['.png'], [one(0, b(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a))]],
  ['image', ['.jpg', '.jpeg'], [one(0, b(0xff, 0xd8, 0xff))]],
  ['image', ['.gif'], [one(0, s('GIF87a')), one(0, s('GIF89a'))]],
  ['image', ['.ico'], [one(0, b(0x00, 0x00, 0x01, 0x00))]],
  ['image', ['.webp'], [Object.freeze([at(0, s('RIFF')), at(8, s('WEBP'))])]],
  ['image', ['.bmp'], [one(0, s('BM'))]],
  ['image', ['.tif', '.tiff'], [one(0, b(0x49, 0x49, 0x2a, 0x00)), one(0, b(0x4d, 0x4d, 0x00, 0x2a))]],
  ['image', ['.avif', '.heic', '.heif'], [one(4, s('ftyp'))]],
  ['document', ['.pdf'], [one(0, s('%PDF-'))]],
  ['video', ['.mp4', '.m4v', '.mov', '.3gp', '.3g2'], ISO_ATOMS],
  ['video', ['.webm', '.mkv'], EBML],
  ['video', ['.avi'], [Object.freeze([at(0, s('RIFF')), at(8, s('AVI '))])]],
  ['video', ['.ogv'], OGG],
  ['video', ['.flv'], [one(0, [...s('FLV'), 0x01])]],
  ['video', ['.wmv', '.asf'], ASF],
  ['video', ['.mpg', '.mpeg'], [one(0, b(0x00, 0x00, 0x01, 0xba)), one(0, b(0x00, 0x00, 0x01, 0xb3))]],
  // Layer III second bytes only, so FF FE (a Layer I header, and a UTF-16LE BOM) is never a signature.
  ['audio', ['.mp3'], [ID3, ...[0xfb, 0xfa, 0xf3, 0xf2, 0xe3, 0xe2].map(x => one(0, b(0xff, x)))]],
  ['audio', ['.wav'], [Object.freeze([at(0, s('RIFF')), at(8, s('WAVE'))])]],
  ['audio', ['.ogg', '.oga', '.opus'], OGG],
  ['audio', ['.flac'], [one(0, s('fLaC'))]],
  ['audio', ['.m4a', '.m4b'], [one(4, s('ftyp'))]],
  ['audio', ['.aac'], [one(0, b(0xff, 0xf1)), one(0, b(0xff, 0xf9)), ID3]],
  [
    'audio',
    ['.aif', '.aiff'],
    [Object.freeze([at(0, s('FORM')), at(8, s('AIFF'))]), Object.freeze([at(0, s('FORM')), at(8, s('AIFC'))])],
  ],
  ['audio', ['.wma'], ASF],
  ['audio', ['.weba'], EBML],
  ['audio', ['.mid', '.midi'], [one(0, s('MThd'))]],
  ['audio', ['.caf'], [one(0, s('caff'))]],
  ['font', ['.woff'], [one(0, s('wOFF'))]],
  ['font', ['.woff2'], [one(0, s('wOF2'))]],
  ['font', ['.ttf'], [FONT_TRUE, one(0, s('true'))]],
  ['font', ['.otf'], [one(0, s('OTTO')), FONT_TRUE]],
  ['font', ['.ttc'], [one(0, s('ttcf'))]],
  ['font', ['.eot'], [one(34, b(0x4c, 0x50))]],
  [
    'archive',
    ['.zip'],
    [one(0, b(0x50, 0x4b, 0x03, 0x04)), one(0, b(0x50, 0x4b, 0x05, 0x06)), one(0, b(0x50, 0x4b, 0x07, 0x08))],
  ],
  ['archive', ['.gz'], [one(0, b(0x1f, 0x8b))]],
  ['archive', ['.tar'], [one(257, s('ustar'))]],
  ['executable', ['.exe', '.dll'], [one(0, s('MZ'))]],
  ['executable', ['.so'], [one(0, b(0x7f, 0x45, 0x4c, 0x46))]],
  [
    'executable',
    ['.dylib'],
    [
      one(0, b(0xfe, 0xed, 0xfa, 0xce)),
      one(0, b(0xfe, 0xed, 0xfa, 0xcf)),
      one(0, b(0xce, 0xfa, 0xed, 0xfe)),
      one(0, b(0xcf, 0xfa, 0xed, 0xfe)),
      one(0, b(0xca, 0xfe, 0xba, 0xbe)),
    ],
  ],
  ['other', ['.bin'], []],
];

/** A map whose mutators throw, so the table cannot be changed at run time. */
class FrozenMap<K, V> extends Map<K, V> {
  private sealed = false;
  constructor(entries: Array<[K, V]>) {
    super(entries);
    this.sealed = true;
  }
  override set(key: K, value: V): this {
    if (this.sealed) throw new TypeError('the binary type table is a constant');
    return super.set(key, value);
  }
  override delete(): boolean {
    throw new TypeError('the binary type table is a constant');
  }
  override clear(): void {
    throw new TypeError('the binary type table is a constant');
  }
}

/** Extension (lowercase, with the dot) to its family and signatures. A constant. */
export const BINARY_TYPES: ReadonlyMap<string, BinaryTypeRow> = new FrozenMap(
  ROWS.flatMap(([family, exts, signatures]) =>
    exts.map((ext): [string, BinaryTypeRow] => [ext, Object.freeze({ family, signatures: Object.freeze(signatures) })]),
  ),
);

/** R1: the row a path's lowercased last extension names, if any. */
export function binaryCandidate(filePath: string): { family: BinaryFamily; ext: string } | undefined {
  const ext = path.extname(path.basename(filePath)).toLowerCase();
  if (ext === '') return undefined;
  const row = BINARY_TYPES.get(ext);
  return row ? { family: row.family, ext } : undefined;
}

function matches(head: Uint8Array, sig: Signature): boolean {
  for (const part of sig) {
    if (head.length < part.offset + part.bytes.length) return false;
    for (let i = 0; i < part.bytes.length; i++) {
      if (head[part.offset + i] !== part.bytes[i]) return false;
    }
  }
  return true;
}

/** A signature is printable when every byte of it is printable ASCII. */
function isPrintableSignature(sig: Signature): boolean {
  return sig.every(p => p.bytes.every(x => x >= 0x20 && x <= 0x7e));
}

/** C0 bytes accidental text carries: NUL is evidence of its own and is handled apart. */
const TEXT_SET_CONTROLS = new Set([0x00, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1a, 0x1b]);

/** A C0 control byte outside the text set. */
export function isControlByte(x: number): boolean {
  return x <= 0x1f && !TEXT_SET_CONTROLS.has(x);
}

function hasControlByte(head: Uint8Array): boolean {
  for (const x of head) if (isControlByte(x)) return true;
  return false;
}

function hasNul(head: Uint8Array): boolean {
  return head.includes(0x00);
}

/** Decode with `fatal` and `stream`, so a character cut by the window end is not an error. */
function decodes(label: string, head: Uint8Array): boolean {
  try {
    new TextDecoder(label, { fatal: true }).decode(head, { stream: true });
    return true;
  } catch {
    return false;
  }
}

function hasBom(head: Uint8Array): boolean {
  if (head.length >= 2 && head[0] === 0xff && head[1] === 0xfe) return true;
  if (head.length >= 2 && head[0] === 0xfe && head[1] === 0xff) return true;
  return head.length >= 3 && head[0] === 0xef && head[1] === 0xbb && head[2] === 0xbf;
}

/**
 * The declared-encoding rule of 2.2: true when the copy is text under its
 * declared label (and so is never confirmed), false when the declared decode
 * failed and the row rule decides.
 */
function declaredTextDecodes(label: string, head: Uint8Array): boolean {
  const upper = label.toUpperCase();
  // Labels the 1.10.0 map routes to the BOM sniff, decoded by what they name.
  if (upper === 'UTF-8' || upper === 'UTF-8-BOM') return decodes('utf-8', head);
  if (upper === 'UTF-16' || upper === 'UTF-16LE-BOM' || upper === 'UTF-16BE-BOM') {
    // Big-endian first: what git assumes for UTF-16 with no BOM.
    return decodes('utf-16be', head) || decodes('utf-16le', head);
  }
  // The 1.10.0 label map, kept in one place with the decoder.
  const name = worktreeEncodingName(upper);
  // Outside the map: git applied a text encoding to this copy, so it is text.
  if (name === undefined || name === null) return true;
  try {
    new TextDecoder(name);
  } catch {
    // A label the map lists but this runtime cannot construct: text, as above.
    return true;
  }
  return decodes(name, head);
}

/**
 * R3 and R4 for one copy's head. `declaredEncoding` is the disk copy's
 * `working-tree-encoding` attribute, when it has one; blobs never pass it.
 */
export function confirmsBinary(ext: string, head: Uint8Array, declaredEncoding?: string): boolean {
  const row = BINARY_TYPES.get(ext.toLowerCase());
  if (!row) return false;
  const window = head.length > SNIFF_BYTES ? head.subarray(0, SNIFF_BYTES) : head;
  if (hasBom(window)) return false;
  if (declaredEncoding !== undefined && declaredEncoding.length > 0) {
    if (declaredTextDecodes(declaredEncoding, window)) return false;
  }
  if (row.signatures.length === 0) return hasControlByte(window);
  let invalidUtf8: boolean | undefined;
  for (const sig of row.signatures) {
    if (!matches(window, sig)) continue;
    if (hasNul(window) || hasControlByte(window)) return true;
    if (!isPrintableSignature(sig)) {
      invalidUtf8 ??= !decodes('utf-8', window);
      if (invalidUtf8) return true;
    }
  }
  return false;
}

const LFS_HEADER = Buffer.from('version https://git-lfs.github.com/spec/v1\n', 'latin1');

/** R6: a Git LFS pointer, which is text and expected for media under LFS. */
export function isLfsPointer(bytes: Uint8Array, size: number): boolean {
  if (size >= 1024 || bytes.length < LFS_HEADER.length) return false;
  for (let i = 0; i < LFS_HEADER.length; i++) if (bytes[i] !== LFS_HEADER[i]) return false;
  return true;
}
