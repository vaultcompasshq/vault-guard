import { BARE_RUN_SIGNATURES, BINARY_TYPES, confirmsBareRun, type Signature } from '../binary-type';

/**
 * U4 of the 2026-10-17 data-file design (section 3.2): a base64 run with no
 * data: prefix is demoted only on a PNG header or a JPEG header with one of
 * four marker bytes, never on any other row of the binary table.
 */

/** The smallest head that carries `sig`: zeros in the gaps, then a NUL and a control byte. */
function headFor(sig: Signature): Buffer {
  const end = Math.max(...sig.map(p => p.offset + p.bytes.length));
  const buf = Buffer.alloc(end + 4, 0);
  for (const p of sig) Buffer.from(p.bytes).copy(buf, p.offset);
  buf[end] = 0x00;
  buf[end + 1] = 0x00;
  buf[end + 2] = 0x00;
  buf[end + 3] = 0x10;
  return buf;
}

const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

describe('U4: confirmsBareRun tests only BARE_RUN_SIGNATURES', () => {
  it('the PNG header confirms, as a png image', () => {
    const head = Buffer.from([...PNG, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52]);
    expect(confirmsBareRun(head)).toEqual({ format: '.png', family: 'image' });
  });

  it.each([0xe0, 0xe1, 0xdb, 0xee])('FF D8 FF %d confirms, as a jpg image', marker => {
    const head = Buffer.from([0xff, 0xd8, 0xff, marker, 0x00, 0x10, 0x4a, 0x46]);
    expect(confirmsBareRun(head)).toEqual({ format: '.jpg', family: 'image' });
  });

  it('FF D8 FF C0 does not confirm (the marker byte is part of the signature)', () => {
    expect(confirmsBareRun(Buffer.from([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00]))).toBeUndefined();
  });

  it('a PNG header one byte short does not confirm', () => {
    expect(confirmsBareRun(Buffer.from(PNG.slice(0, 7)))).toBeUndefined();
  });

  const others: Array<[string, number, Signature]> = [];
  for (const [ext, row] of BINARY_TYPES) {
    if (ext === '.png' || ext === '.jpg' || ext === '.jpeg') continue;
    row.signatures.forEach((sig, i) => others.push([ext, i, sig]));
  }

  it.each(others)('%s signature %i: its minimal header does not confirm a bare run', (_ext, _i, sig) => {
    expect(confirmsBareRun(headFor(sig))).toBeUndefined();
  });

  it('the jpg row minimal header (FF D8 FF and no marker) does not confirm', () => {
    expect(confirmsBareRun(Buffer.from([0xff, 0xd8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x10]))).toBeUndefined();
  });

  it('BARE_RUN_SIGNATURES has exactly two entries, PNG and JPEG, and is frozen', () => {
    expect(BARE_RUN_SIGNATURES.map(e => e.format)).toStrictEqual(['.png', '.jpg']);
    expect(BARE_RUN_SIGNATURES[0].signatures).toHaveLength(1);
    expect(BARE_RUN_SIGNATURES[1].signatures).toHaveLength(4);
    for (const sig of BARE_RUN_SIGNATURES[1].signatures) expect([...sig[0].bytes]).toHaveLength(4);
    expect(Object.isFrozen(BARE_RUN_SIGNATURES)).toBe(true);
    for (const e of BARE_RUN_SIGNATURES) {
      expect(Object.isFrozen(e)).toBe(true);
      expect(Object.isFrozen(e.signatures)).toBe(true);
    }
    expect(BARE_RUN_SIGNATURES[1].signatures.map(sig => sig[0].bytes[3])).toStrictEqual([0xe0, 0xe1, 0xdb, 0xee]);
  });

  it('a PNG header followed only by printable ASCII still confirms (the 89 byte is invalid UTF-8)', () => {
    const head = Buffer.concat([Buffer.from(PNG.slice(0, 1)), Buffer.from('PNG\r\n'), Buffer.from([0x1a, 0x0a]), Buffer.from('hello')]);
    expect(confirmsBareRun(head)).toEqual({ format: '.png', family: 'image' });
  });

  it('a head starting with a UTF-8 BOM never confirms', () => {
    expect(confirmsBareRun(Buffer.from([0xef, 0xbb, 0xbf, ...PNG]))).toBeUndefined();
  });
});
