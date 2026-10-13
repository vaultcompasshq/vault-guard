import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { decodeDiskCopy, decodeTextBuffer, mappedWorktreeEncodings } from '../text-decode';
import { SecretScanner } from '../../scanners/secret-scanner';
import { scanTextFileAsync, scanTextFileSync } from '../scan-file';

// Assembled at runtime so no provider-shaped key sits in the repository.
const KEY = ['sk-ant-', 'api03-', 'Kq7mZr2xVb9nTd4wHs6yLc3p', 'Jf8gRu5eNa1vBt0iOy7kPd2s', 'Xw4hEj6uCi3q'].join('');
const TEXT = `first line\nconst k = "${KEY}";\n`;

const utf16le = (s: string, bom = true): Buffer =>
  Buffer.concat([bom ? Buffer.from([0xff, 0xfe]) : Buffer.alloc(0), Buffer.from(s, 'utf16le')]);
const utf16be = (s: string, bom = true): Buffer =>
  Buffer.concat([
    bom ? Buffer.from([0xfe, 0xff]) : Buffer.alloc(0),
    Buffer.from(s, 'utf16le').swap16(),
  ]);

describe('decodeTextBuffer', () => {
  it('decodes UTF-16LE with a BOM and drops the BOM', () => {
    expect(decodeTextBuffer(utf16le(TEXT))).toBe(TEXT);
  });

  it('decodes UTF-16BE with a BOM and drops the BOM', () => {
    expect(decodeTextBuffer(utf16be(TEXT))).toBe(TEXT);
  });

  it('strips a UTF-8 BOM', () => {
    const buf = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(TEXT, 'utf-8')]);
    expect(decodeTextBuffer(buf)).toBe(TEXT);
  });

  it('leaves plain UTF-8 alone', () => {
    expect(decodeTextBuffer(Buffer.from(TEXT, 'utf-8'))).toBe(TEXT);
  });

  it('does not guess at BOM-less UTF-16 (documented gap)', () => {
    expect(decodeTextBuffer(utf16le(TEXT, false))).not.toContain(KEY);
  });
});

describe('CRLF line endings after BOM decoding (a Windows-authored UTF-16 file)', () => {
  const crlf = `first line\r\nsecond line\r\nconst k = "${KEY}";\r\n`;
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-utf16-crlf-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it.each([
    ['UTF-16LE', utf16le],
    ['UTF-16BE', utf16be],
  ] as Array<[string, (s: string) => Buffer]>)(
    'reports line 3 and the right column for a key after two CRLF lines in %s',
    (_n, enc) => {
      const f = path.join(dir, 'w.txt');
      fs.writeFileSync(f, enc(crlf));
      const [m] = new SecretScanner().scan(f);
      expect(m.line).toBe(3);
      expect(m.column).toBe('const k = "'.length);
    },
  );

  it('scanTextFileAsync agrees on the line number with CRLF', async () => {
    const f = path.join(dir, 'w-big.txt');
    fs.writeFileSync(f, utf16le(crlf));
    const [m] = await scanTextFileAsync(new SecretScanner(), f);
    expect(m.line).toBe(3);
  });
});

describe('a key in a BOM-marked UTF-16 file is found, with sensible positions', () => {
  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-utf16-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const cases: Array<[string, (s: string) => Buffer]> = [
    ['UTF-16LE', utf16le],
    ['UTF-16BE', utf16be],
  ];

  it.each(cases)('SecretScanner.scan finds it in %s and reports line 2', (_n, enc) => {
    const f = path.join(dir, 'a.txt');
    fs.writeFileSync(f, enc(TEXT));
    const matches = new SecretScanner().scan(f);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].line).toBe(2);
    expect(matches[0].column).toBe('const k = "'.length);
  });

  it.each(cases)('scanTextFileSync finds it in %s', (_n, enc) => {
    const f = path.join(dir, 'a.ts');
    fs.writeFileSync(f, enc(TEXT));
    const matches = scanTextFileSync(new SecretScanner(), f, { maxFileBytes: 1024 * 1024 });
    expect(matches.length).toBeGreaterThan(0);
  });

  it.each(cases)('scanTextFileAsync finds it in %s at line 2', async (_n, enc) => {
    const f = path.join(dir, 'big.txt');
    fs.writeFileSync(f, enc(TEXT));
    const matches = await scanTextFileAsync(new SecretScanner(), f);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].line).toBe(2);
  });
});

/**
 * Decoding the WORKING-TREE copy of a tracked file (design 2026-10-12, 2.4):
 * a BOM first, then a declared working-tree-encoding through an explicit
 * label map, and anything else is scanned as UTF-8 and reported.
 */
describe('decodeDiskCopy (U21)', () => {
  it('U21: every mapped label constructs a TextDecoder on this Node', () => {
    for (const [label, name] of mappedWorktreeEncodings()) {
      if (name === null) continue;
      expect(() => new TextDecoder(name)).not.toThrow();
      expect(label).toBe(label.toUpperCase());
    }
  });

  it('U21: a BOM overrides a contrary label', () => {
    expect(decodeDiskCopy(utf16be(TEXT), 'UTF-16LE').texts).toEqual([TEXT]);
    expect(decodeDiskCopy(utf16le(TEXT), 'UTF-16BE').texts).toEqual([TEXT]);
    expect(decodeDiskCopy(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(TEXT)]), 'SHIFT_JIS').texts).toEqual([TEXT]);
  });

  it('U21: a mapped label decodes a BOM-less copy', () => {
    expect(decodeDiskCopy(utf16le(TEXT, false), 'UTF-16LE').texts).toEqual([TEXT]);
    expect(decodeDiskCopy(utf16be(TEXT, false), 'utf-16be').texts).toEqual([TEXT]);
    const cafe = String.fromCodePoint(0x63, 0x61, 0x66, 0xe9);
    expect(decodeDiskCopy(Buffer.from([0x63, 0x61, 0x66, 0xe9]), 'ISO-8859-1').texts).toEqual([cafe]);
  });

  it('U21: UTF-16, UTF-16LE-BOM and UTF-8-BOM route to the BOM sniff', () => {
    // git writes these with a BOM; TextDecoder('UTF-16') is little-endian
    // only and TextDecoder('UTF-16LE-BOM') throws, so neither label is passed on.
    for (const label of ['UTF-16', 'UTF-16LE-BOM', 'UTF-16BE-BOM', 'UTF-8-BOM', 'UTF-8']) {
      const r = decodeDiskCopy(utf16be(TEXT), label);
      expect({ label, texts: r.texts, unsupported: r.unsupported }).toEqual({ label, texts: [TEXT], unsupported: undefined });
    }
    expect(decodeDiskCopy(Buffer.from(TEXT), 'UTF-16').texts).toEqual([TEXT]);
  });

  it('U21: UTF-32 and an unknown label are a coverage entry and a UTF-8 decode', () => {
    for (const label of ['UTF-32', 'UTF-32LE', 'X-NOT-A-CHARSET']) {
      const r = decodeDiskCopy(Buffer.from(TEXT), label);
      expect({ label, texts: r.texts, unsupported: r.unsupported }).toEqual({ label, texts: [TEXT], unsupported: label });
    }
  });

  it('U21: a filter-attributed copy with a declared encoding is decoded both ways', () => {
    const bytes = utf16le(TEXT, false);
    const r = decodeDiskCopy(bytes, 'UTF-16LE', true);
    expect(r.texts).toEqual([TEXT, bytes.toString('utf8')]);
    expect(decodeDiskCopy(bytes, 'UTF-16LE', false).texts).toEqual([TEXT]);
  });
});
