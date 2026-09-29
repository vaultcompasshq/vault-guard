import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { decodeTextBuffer } from '../text-decode';
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

  it('the streaming path agrees on the line number with CRLF', async () => {
    const f = path.join(dir, 'w-big.txt');
    fs.writeFileSync(f, utf16le(crlf));
    const [m] = await scanTextFileAsync(new SecretScanner(), f, { maxFileBytes: 16 });
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

  it.each(cases)('the streaming path (over maxFileBytes) finds it in %s at line 2', async (_n, enc) => {
    const f = path.join(dir, 'big.txt');
    fs.writeFileSync(f, enc(TEXT));
    const matches = await scanTextFileAsync(new SecretScanner(), f, { maxFileBytes: 16 });
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0].line).toBe(2);
  });
});
