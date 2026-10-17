import {
  BINARY_FAMILIES,
  BINARY_TYPES,
  SNIFF_BYTES,
  binaryCandidate,
  confirmsBinary,
  isLfsPointer,
  type Signature,
} from '../binary-type';

/**
 * The classifier of the 2026-10-17 design (sections 2 and 3): a copy is
 * skipped as binary only when its extension is in the table AND its head
 * carries that extension's signature AND the head carries the non-text
 * evidence the signature kind requires.
 */

/** The smallest head that carries `sig`: zeros in the gaps, then a real-header tail. */
function headFor(sig: Signature): Buffer {
  const end = Math.max(...sig.map(p => p.offset + p.bytes.length));
  const buf = Buffer.alloc(end + 4, 0);
  for (const p of sig) Buffer.from(p.bytes).copy(buf, p.offset);
  // Version, size and reserved fields of a real header: a NUL and a control byte.
  buf[end] = 0x00;
  buf[end + 1] = 0x00;
  buf[end + 2] = 0x00;
  buf[end + 3] = 0x10;
  return buf;
}

const rows: Array<[string, number, Signature]> = [];
for (const [ext, row] of BINARY_TYPES) {
  row.signatures.forEach((sig, i) => rows.push([ext, i, sig]));
}

/**
 * The design's section 3 table, written out independently of the module so a
 * signature typo or an offset off by one in binary-type.ts turns its own row
 * red. Each alternative is `offset:hex`, parts of one signature joined by `+`.
 */
const hex = (t: string): string => Buffer.from(t, 'latin1').toString('hex').toUpperCase();
const ISO = ['ftyp', 'moov', 'mdat', 'free', 'skip', 'wide', 'pnot'].map(a => `4:${hex(a)}`);
const DESIGN: Record<string, string[]> = {
  '.png': ['0:89504E470D0A1A0A'],
  '.jpg': ['0:FFD8FF'],
  '.jpeg': ['0:FFD8FF'],
  '.gif': [`0:${hex('GIF87a')}`, `0:${hex('GIF89a')}`],
  '.ico': ['0:00000100'],
  '.webp': [`0:${hex('RIFF')}+8:${hex('WEBP')}`],
  '.bmp': [`0:${hex('BM')}`],
  '.tif': ['0:49492A00', '0:4D4D002A'],
  '.tiff': ['0:49492A00', '0:4D4D002A'],
  '.avif': [`4:${hex('ftyp')}`],
  '.heic': [`4:${hex('ftyp')}`],
  '.heif': [`4:${hex('ftyp')}`],
  '.pdf': [`0:${hex('%PDF-')}`],
  '.mp4': ISO,
  '.m4v': ISO,
  '.mov': ISO,
  '.3gp': ISO,
  '.3g2': ISO,
  '.webm': ['0:1A45DFA3'],
  '.mkv': ['0:1A45DFA3'],
  '.avi': [`0:${hex('RIFF')}+8:${hex('AVI ')}`],
  '.ogv': [`0:${hex('OggS')}`],
  '.flv': [`0:${hex('FLV')}01`],
  '.wmv': ['0:3026B2758E66CF11'],
  '.asf': ['0:3026B2758E66CF11'],
  '.mpg': ['0:000001BA', '0:000001B3'],
  '.mpeg': ['0:000001BA', '0:000001B3'],
  '.mp3': [`0:${hex('ID3')}`, '0:FFFB', '0:FFFA', '0:FFF3', '0:FFF2', '0:FFE3', '0:FFE2'],
  '.wav': [`0:${hex('RIFF')}+8:${hex('WAVE')}`],
  '.ogg': [`0:${hex('OggS')}`],
  '.oga': [`0:${hex('OggS')}`],
  '.opus': [`0:${hex('OggS')}`],
  '.flac': [`0:${hex('fLaC')}`],
  '.m4a': [`4:${hex('ftyp')}`],
  '.m4b': [`4:${hex('ftyp')}`],
  '.aac': ['0:FFF1', '0:FFF9', `0:${hex('ID3')}`],
  '.aif': [`0:${hex('FORM')}+8:${hex('AIFF')}`, `0:${hex('FORM')}+8:${hex('AIFC')}`],
  '.aiff': [`0:${hex('FORM')}+8:${hex('AIFF')}`, `0:${hex('FORM')}+8:${hex('AIFC')}`],
  '.wma': ['0:3026B2758E66CF11'],
  '.weba': ['0:1A45DFA3'],
  '.mid': [`0:${hex('MThd')}`],
  '.midi': [`0:${hex('MThd')}`],
  '.caf': [`0:${hex('caff')}`],
  '.woff': [`0:${hex('wOFF')}`],
  '.woff2': [`0:${hex('wOF2')}`],
  '.ttf': ['0:00010000', `0:${hex('true')}`],
  '.otf': [`0:${hex('OTTO')}`, '0:00010000'],
  '.ttc': [`0:${hex('ttcf')}`],
  '.eot': ['34:4C50'],
  '.zip': ['0:504B0304', '0:504B0506', '0:504B0708'],
  '.gz': ['0:1F8B'],
  '.tar': [`257:${hex('ustar')}`],
  '.exe': [`0:${hex('MZ')}`],
  '.dll': [`0:${hex('MZ')}`],
  '.so': ['0:7F454C46'],
  '.dylib': ['0:FEEDFACE', '0:FEEDFACF', '0:CEFAEDFE', '0:CFFAEDFE', '0:CAFEBABE'],
  '.bin': [],
};
const serialize = (sig: Signature): string =>
  sig.map(p => `${p.offset}:${Buffer.from(p.bytes).toString('hex').toUpperCase()}`).join('+');
const parseSig = (spec: string): Signature =>
  spec.split('+').map(part => {
    const [off, h] = part.split(':');
    return { offset: Number(off), bytes: [...Buffer.from(h, 'hex')] };
  });

describe('U1: the module table equals the design table, row by row', () => {
  it.each(Object.entries(DESIGN))('%s', (ext, specs) => {
    expect(BINARY_TYPES.get(ext)?.signatures.map(serialize)).toEqual(specs);
  });

  it.each(Object.entries(DESIGN).flatMap(([ext, specs]) => specs.map(sp => [ext, sp] as [string, string])))(
    '%s %s: a header built from the design confirms, and with its first byte flipped does not',
    (ext, spec) => {
      const sig = parseSig(spec);
      expect(confirmsBinary(ext, headFor(sig))).toBe(true);
      const flipped = headFor(sig);
      flipped[sig[0].offset] ^= 0xff;
      expect(confirmsBinary(ext, flipped)).toBe(false);
    },
  );
});

describe('U1: every table row, every signature', () => {
  it.each(rows)('%s signature %i: the minimal valid header confirms', (ext, _i, sig) => {
    expect(confirmsBinary(ext, headFor(sig))).toBe(true);
  });

  it.each(rows)('%s signature %i: its first signature byte flipped does not confirm', (ext, _i, sig) => {
    const head = headFor(sig);
    head[sig[0].offset] ^= 0xff;
    expect(confirmsBinary(ext, head)).toBe(false);
  });

  it.each(rows)('%s signature %i: a 0-byte file does not confirm', (ext) => {
    expect(confirmsBinary(ext, Buffer.alloc(0))).toBe(false);
  });

  it.each(rows)('%s signature %i: one byte shorter than the signature does not confirm', (ext, _i, sig) => {
    const end = Math.max(...sig.map(p => p.offset + p.bytes.length));
    expect(confirmsBinary(ext, headFor(sig).subarray(0, end - 1))).toBe(false);
  });

  it('every extension of the design table is present, and nothing else', () => {
    expect([...BINARY_TYPES.keys()].sort()).toEqual(
      [
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.bmp', '.tif', '.tiff', '.avif', '.heic', '.heif',
        '.pdf',
        '.mp4', '.m4v', '.mov', '.3gp', '.3g2', '.webm', '.mkv', '.avi', '.ogv', '.flv', '.wmv', '.asf',
        '.mpg', '.mpeg',
        '.mp3', '.wav', '.ogg', '.oga', '.opus', '.flac', '.m4a', '.m4b', '.aac', '.aif', '.aiff', '.wma',
        '.weba', '.mid', '.midi', '.caf',
        '.woff', '.woff2', '.ttf', '.otf', '.ttc', '.eot',
        '.zip', '.gz', '.tar',
        '.exe', '.dll', '.so', '.dylib',
        '.bin',
      ].sort(),
    );
    expect(BINARY_FAMILIES).toEqual(['image', 'document', 'video', 'audio', 'font', 'archive', 'executable', 'other']);
    expect(SNIFF_BYTES).toBe(4096);
  });

  it('the table is frozen', () => {
    expect(() => (BINARY_TYPES as Map<string, unknown>).set('.ts', {})).toThrow();
    expect(binaryCandidate('a.ts')).toBeUndefined();
  });
});

describe('U2: the excluded set is never a candidate', () => {
  it.each(['.ts', '.mts', '.m2ts', '.vob', '.svg', '.pfa', '.pfb', '.fnt', '.txt'])('%s', ext => {
    expect(binaryCandidate(`dir/file${ext}`)).toBeUndefined();
    expect(binaryCandidate(`dir/FILE${ext.toUpperCase()}`)).toBeUndefined();
  });
});

describe('R1: candidate by the lowercased last extension', () => {
  it('compares the extension case-insensitively', () => {
    expect(binaryCandidate('config/credentials.PNG')).toEqual({ family: 'image', ext: '.png' });
    expect(binaryCandidate('clip.Mp4')).toEqual({ family: 'video', ext: '.mp4' });
  });

  it('a dotfile with no other dot has no extension', () => {
    expect(binaryCandidate('dir/.mp4')).toBeUndefined();
  });

  it('only the last extension counts', () => {
    expect(binaryCandidate('a.mp4.txt')).toBeUndefined();
    expect(binaryCandidate('a.txt.mp4')).toEqual({ family: 'video', ext: '.mp4' });
  });
});

describe('U4: R6, the LFS pointer', () => {
  const header = 'version https://git-lfs.github.com/spec/v1\n';
  const pointer = `${header}oid sha256:${'a'.repeat(64)}\nsize 12345\n`;

  it('the exact pointer header under 1024 bytes is a pointer', () => {
    const b = Buffer.from(pointer);
    expect(isLfsPointer(b, b.length)).toBe(true);
  });

  it('the same header in a 2048-byte file is not', () => {
    const b = Buffer.concat([Buffer.from(pointer), Buffer.alloc(2048 - pointer.length, 0x61)]);
    expect(isLfsPointer(b.subarray(0, 1024), b.length)).toBe(false);
    expect(isLfsPointer(b, b.length)).toBe(false);
  });

  it('the header without its newline is not', () => {
    const b = Buffer.from(header.trimEnd());
    expect(isLfsPointer(b, b.length)).toBe(false);
  });
});

const ascii = (s: string): Buffer => Buffer.from(s, 'latin1');

describe('U15: R4 per signature kind', () => {
  describe('signature-less (.bin): a control byte only', () => {
    it('printable UTF-8 with NULs is not confirmed', () => {
      expect(confirmsBinary('.bin', ascii('A=1\0B=2\0SECRET=abc\0'))).toBe(false);
    });

    it('one 0x01 byte confirms', () => {
      expect(confirmsBinary('.bin', ascii('A=1\x01B=2'))).toBe(true);
    });

    it.each([
      ['BEL (an OSC title in a terminal capture)', '\x1b]0;title\x07prompt$ ls\n'],
      ['BS (nroff overstrike)', 'N\bNA\bAM\bME\bE\n'],
      ['SUB (a DOS end-of-file byte)', 'line one\r\nline two\r\n\x1a'],
      ['tab, LF, VT, FF, CR, ESC', 'a\tb\nc\x0bd\x0ce\rf\x1b[0m\n'],
    ])('only text-set controls (%s) are not confirmed', (_n, s) => {
      expect(confirmsBinary('.bin', ascii(s))).toBe(false);
    });

    it.each([0x02, 0x03, 0x04, 0x05, 0x06, 0x0e, 0x0f, 0x10, 0x11, 0x19, 0x1c, 0x1d, 0x1e, 0x1f])(
      'control byte 0x%s confirms',
      b => {
        expect(confirmsBinary('.bin', Buffer.from([0x41, b, 0x42]))).toBe(true);
      },
    );

    it('SO and SI (the ISO-2022-KR shape) confirm, pinning the documented limit', () => {
      expect(confirmsBinary('.bin', ascii('\x1b$)C\x0e!!\x0f text\n'))).toBe(true);
    });

    it('Latin-1 text (invalid UTF-8, no controls) is not confirmed', () => {
      expect(confirmsBinary('.bin', ascii('USERNAME=Ren\xe9\r\nKEY=abc\r\n'))).toBe(false);
    });

    it('Shift-JIS text (invalid UTF-8, no controls) is not confirmed', () => {
      expect(confirmsBinary('.bin', Buffer.from([0x83, 0x65, 0x83, 0x58, 0x83, 0x67, 0x0a, 0x41, 0x3d, 0x31]))).toBe(false);
    });

    it('DEL (0x7f) is not evidence', () => {
      expect(confirmsBinary('.bin', ascii('a\x7fb\n'))).toBe(false);
    });
  });

  describe('printable signature: a NUL or a control byte', () => {
    it.each([
      ['.ogg', 'OggS'],
      ['.mp4', '    ftyp'],
    ])('%s with a NUL confirms', (ext, sig) => {
      expect(confirmsBinary(ext, ascii(`${sig}text\0more`))).toBe(true);
    });

    it.each([
      ['.ogg', 'OggS'],
      ['.mp4', '    ftyp'],
    ])('%s with a control byte confirms', (ext, sig) => {
      expect(confirmsBinary(ext, ascii(`${sig}text\x02more`))).toBe(true);
    });

    it.each([
      ['.ogg', 'OggS'],
      ['.mp4', '    ftyp'],
    ])('%s with only invalid UTF-8 is not confirmed', (ext, sig) => {
      expect(confirmsBinary(ext, ascii(`${sig}caf\xe9 text`))).toBe(false);
    });

    it('a printable signature with only text-set controls is not confirmed', () => {
      expect(confirmsBinary('.ogg', ascii('OggS line\r\n\tnext\x07\x08\x1a\n'))).toBe(false);
    });
  });

  describe('binary signature: a NUL, a control byte or invalid UTF-8', () => {
    it('PNG with only invalid UTF-8 after it confirms (the signature supplies it)', () => {
      expect(confirmsBinary('.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x41, 0x42]))).toBe(true);
    });

    it('ELF followed only by printable text is not confirmed', () => {
      expect(confirmsBinary('.so', ascii('\x7fELF just some text here\n'))).toBe(false);
    });

    it("ELF with a real header's NULs confirms", () => {
      expect(confirmsBinary('.so', Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00]))).toBe(true);
    });

    it('EBML followed only by printable text is not confirmed', () => {
      expect(confirmsBinary('.webm', ascii('\x1aE\xdf\xa3 text after the magic\n'))).toBe(false);
    });

    it('a binary signature followed by invalid UTF-8 outside the signature confirms', () => {
      expect(confirmsBinary('.so', ascii('\x7fELF caf\xe9\n'))).toBe(true);
    });
  });

  describe('a byte order mark means text', () => {
    it.each([
      [[0xff, 0xfe]],
      [[0xfe, 0xff]],
      [[0xef, 0xbb, 0xbf]],
    ])('a .bin beginning with %j and holding control bytes is not confirmed', bom => {
      expect(confirmsBinary('.bin', Buffer.concat([Buffer.from(bom), Buffer.from([0x01, 0x01, 0x41, 0x00])]))).toBe(false);
    });
  });

  describe('a declared working-tree-encoding', () => {
    const u16le = (s: string): Buffer => Buffer.from(s, 'utf16le');
    const u16be = (s: string): Buffer => Buffer.from(s, 'utf16le').swap16();

    it.each(rows)('UTF-16LE that decodes cleanly is never confirmed (%s signature %i)', (ext, _i, sig) => {
      // A real header is valid UTF-16LE only by accident; build text that is.
      const head = headFor(sig);
      const even = head.length % 2 === 0 ? head : Buffer.concat([head, Buffer.from([0x00])]);
      const decodes = (() => {
        try {
          new TextDecoder('utf-16le', { fatal: true }).decode(even);
          return true;
        } catch {
          return false;
        }
      })();
      if (decodes) expect(confirmsBinary(ext, even, 'UTF-16LE')).toBe(false);
      expect(confirmsBinary(ext, u16le('ā key text'), 'UTF-16LE')).toBe(false);
    });

    it('an unmapped label (UTF-32) is never confirmed', () => {
      expect(confirmsBinary('.bin', Buffer.from([0x01, 0x01, 0x00, 0x00]), 'UTF-32')).toBe(false);
      expect(confirmsBinary('.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]), 'UTF-32')).toBe(false);
    });

    it('UTF-16 with big-endian bytes, no BOM, is not confirmed', () => {
      expect(confirmsBinary('.bin', u16be('āé KEY=abc'), 'UTF-16')).toBe(false);
    });

    it('UTF-16 with little-endian bytes holding U+00DF (BE decode fails) is not confirmed', () => {
      const head = u16le('āéß KEY=abc');
      expect(() => new TextDecoder('utf-16be', { fatal: true }).decode(head)).toThrow();
      expect(confirmsBinary('.bin', head, 'UTF-16')).toBe(false);
    });

    it('UTF-16LE-BOM with no BOM present is not confirmed', () => {
      expect(confirmsBinary('.bin', u16le('āéß KEY=abc'), 'UTF-16LE-BOM')).toBe(false);
    });

    it('UTF-16BE-BOM with no BOM present is not confirmed', () => {
      expect(confirmsBinary('.bin', u16be('āé KEY=abc'), 'UTF-16BE-BOM')).toBe(false);
    });

    it('UTF-8 on valid UTF-8 text is not confirmed', () => {
      expect(confirmsBinary('.bin', Buffer.from('āā\x01 KEY=abc', 'utf-8'), 'UTF-8')).toBe(false);
    });

    it('a declared decode that fails falls through to the row rule', () => {
      // A lone low surrogate in both byte orders: neither UTF-16 decode succeeds.
      const head = Buffer.from([0x01, 0xdc, 0xdc, 0x01, 0x01, 0x02]);
      expect(confirmsBinary('.bin', head, 'UTF-16LE')).toBe(true);
      expect(confirmsBinary('.bin', head, 'UTF-16')).toBe(true);
      // UTF-8 declared on bytes that are not UTF-8.
      expect(confirmsBinary('.bin', Buffer.from([0xff, 0x01, 0x02]), 'UTF-8')).toBe(true);
    });

    it('a label is read case-insensitively', () => {
      expect(confirmsBinary('.bin', u16le('ā key'), 'utf-16le')).toBe(false);
    });
  });

  describe('U3 (unit half): the window edge, where stream: true is load-bearing', () => {
    it('UTF-16LE with a surrogate pair cut by the 4096-byte window is not confirmed', () => {
      // 4094 bytes of text holding U+0101 (bytes 01 01), then an emoji at 4094 to 4097.
      const prefix = 'ā' + 'a'.repeat(2046);
      const full = Buffer.from(`${prefix}\u{1F600}rest`, 'utf16le');
      expect(Buffer.from(prefix, 'utf16le').length).toBe(4094);
      const head = full.subarray(0, SNIFF_BYTES);
      expect(confirmsBinary('.bin', head, 'UTF-16LE')).toBe(false);
    });

    it('Shift-JIS with a lead byte at offset 4095 is not confirmed', () => {
      const head = Buffer.alloc(SNIFF_BYTES, 0x61);
      head[0] = 0x01;
      head[4095] = 0x83;
      expect(confirmsBinary('.bin', head, 'SHIFT_JIS')).toBe(false);
    });
  });
});
