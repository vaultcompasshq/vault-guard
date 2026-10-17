import {
  DELIMITED_MIN_LINES,
  GROUP_MIN,
  HEAD_CHARS,
  LONG_LINE,
  MEDIA_TYPE_ROWS,
  MIN_RUN,
  RunIndex,
  dataShape,
  decodeRunHead,
  encodedPayloadDemotion,
  groupSlot,
  mediaTypeRow,
  runAround,
} from '../data-shape';
import { JPEG_HEAD, PNG_HEAD, gcpKey, payload, runWithKey } from './media-fixtures';

/**
 * Unit tests of the 2026-10-17 data-file design (sections 3, 5 and 10.2):
 * the run boundaries, the head decode, the media type table and the
 * data-file classifier, each against its stated thresholds.
 */

describe('constants', () => {
  it('are the design values', () => {
    expect(MIN_RUN).toBe(1024);
    expect(HEAD_CHARS).toBe(5464);
    expect(GROUP_MIN).toBe(5);
    expect(LONG_LINE).toBe(65536);
    expect(DELIMITED_MIN_LINES).toBe(20);
  });
});

describe('U1: runAround on boundaries', () => {
  const A = 'A'.repeat(1500);

  it.each(['=', '"', "'", ' ', '\t', '\n', '\r', '\\', '.', ',', '%', ':', ';', '@', '<', '>', '(', ')'])(
    'the character %j ends a run',
    ch => {
      const text = A + ch + A;
      expect(runAround(text, 10, 5)).toEqual({ start: 0, end: 1500 });
      expect(runAround(text, 1600, 5)).toEqual({ start: 1501, end: 3001 });
    },
  );

  it.each(['+', '/', '-', '_', 'z', '9'])('the character %j does not end a run', ch => {
    const text = A + ch + A;
    expect(runAround(text, 10, 5)).toEqual({ start: 0, end: 3001 });
  });

  it('a match containing a dot returns undefined (C1)', () => {
    const text = 'A'.repeat(1500) + '.' + 'A'.repeat(1500);
    expect(runAround(text, 1495, 10)).toBeUndefined();
  });

  it('a run shorter than MIN_RUN returns undefined (C3)', () => {
    expect(runAround('"' + 'A'.repeat(1023) + '"', 100, 10)).toBeUndefined();
    expect(runAround('"' + 'A'.repeat(1024) + '"', 100, 10)).toEqual({ start: 1, end: 1025 });
  });

  it('one index answers many lookups with one sweep', () => {
    const text = [A, A, A].join('"');
    const index = new RunIndex(text);
    expect(runAround(text, 5, 5, index)).toEqual({ start: 0, end: 1500 });
    expect(runAround(text, 1505, 5, index)).toEqual({ start: 1501, end: 3001 });
    expect(runAround(text, 3005, 5, index)).toEqual({ start: 3002, end: 4502 });
    expect(index.sweeps).toBe(1);
  });
});

describe('U2: the head decode window', () => {
  const run = payload(PNG_HEAD, 6000);

  it.each([0, 1, 2, 3, 4, 5, 6, 7, 5463, 5464, 5465])('a run of %i characters decodes to the expected head', n => {
    const text = `"${run.slice(0, n)}"`;
    const head = decodeRunHead(text, 1, 1 + n);
    expect(head).toBeDefined();
    expect(head!.length).toBe(Math.min(4096, Math.floor(Math.min(n, 5464) / 4) * 3));
  });

  it('a run with both + or / and - or _ is not decoded', () => {
    const mixed = 'A+'.repeat(600) + '_' + 'B'.repeat(10);
    expect(decodeRunHead(mixed, 0, mixed.length)).toBeUndefined();
  });

  it('a URL-safe run decodes as URL-safe base64', () => {
    const url = Buffer.concat([PNG_HEAD, Buffer.alloc(3000, 0xfb)]).toString('base64url');
    const head = decodeRunHead(url, 0, url.length);
    expect([...head!.subarray(0, 8)]).toEqual([...PNG_HEAD.subarray(0, 8)]);
  });
});

describe('U3: MEDIA_TYPE_ROWS', () => {
  const table: Array<[string, string]> = [
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
  ];

  it.each(table)('%s maps to %s', (type, row) => {
    expect(mediaTypeRow(type)).toBe(row);
  });

  it('holds exactly the design table', () => {
    expect([...MEDIA_TYPE_ROWS.entries()].sort()).toEqual([...table].sort());
  });

  it.each(['image/svg+xml', 'text/plain', 'text/html', 'application/json', 'application/octet-stream', 'application/javascript', 'application/xml', '', 'image/*', 'image/'])(
    '%j maps to no row',
    type => {
      expect(mediaTypeRow(type)).toBeUndefined();
    },
  );

  it('matches lowercased with parameters ignored', () => {
    expect(mediaTypeRow('IMAGE/PNG;name=a')).toBe('.png');
    expect(mediaTypeRow('Image/Png')).toBe('.png');
  });

  it('is frozen', () => {
    expect(() => (MEDIA_TYPE_ROWS as Map<string, string>).set('text/plain', '.png')).toThrow(TypeError);
    expect(() => (MEDIA_TYPE_ROWS as Map<string, string>).delete('image/png')).toThrow(TypeError);
  });
});

describe('encodedPayloadDemotion: the four conditions on one match', () => {
  const key = gcpKey(3);
  const at = (text: string): { offset: number; matchLength: number } => ({ offset: text.indexOf(key), matchLength: key.length });

  it('a key inside a PNG data: payload is demoted with the full record', () => {
    const run = runWithKey(PNG_HEAD, 4096, key);
    const text = `<img src="data:image/png;base64,${run}">`;
    expect(encodedPayloadDemotion(text, at(text))).toEqual({
      reason: 'data-uri-binary-payload',
      family: 'image',
      format: '.png',
      media_type: 'image/png',
      run_length: 4096,
    });
  });

  it('a key inside a bare JPEG run is demoted without a media type', () => {
    const run = runWithKey(JPEG_HEAD, 4096, key);
    const text = `{"thumb": "${run}"}`;
    expect(encodedPayloadDemotion(text, at(text))).toEqual({
      reason: 'base64-binary-run',
      family: 'image',
      format: '.jpg',
      run_length: 4096,
    });
  });

  it('a key flush against the start or the end of the run is not interior (C2)', () => {
    const body = payload(PNG_HEAD, 4096);
    const end = `"data:image/png;base64,${body}${key}"`;
    expect(encodedPayloadDemotion(end, at(end))).toBeUndefined();
    const start = `"${key}${body}"`;
    expect(encodedPayloadDemotion(start, at(start))).toBeUndefined();
  });

  it('a data: payload whose type is outside the table is not demoted even on a PNG head', () => {
    const run = runWithKey(PNG_HEAD, 4096, key);
    const text = `"data:application/octet-stream;base64,${run}"`;
    expect(encodedPayloadDemotion(text, at(text))).toBeUndefined();
  });

  it('a data: payload with an empty type is not demoted', () => {
    const run = runWithKey(PNG_HEAD, 4096, key);
    const text = `"data:;base64,${run}"`;
    expect(encodedPayloadDemotion(text, at(text))).toBeUndefined();
  });

  it('the data: prefix is read at most 256 characters back', () => {
    const run = runWithKey(PNG_HEAD, 4096, key);
    const near = `"data:image/png;${'p=v;'.repeat(55)}base64,${run}"`;
    expect(encodedPayloadDemotion(near, at(near))?.reason).toBe('data-uri-binary-payload');
    // Too far back: read as a bare run, which a PNG head still confirms.
    const far = `"data:image/png;${'p=v;'.repeat(70)}base64,${run}"`;
    expect(encodedPayloadDemotion(far, at(far))?.reason).toBe('base64-binary-run');
  });
});

/** `n` lines of a k-field table, `fill(i)` giving line i's fields. */
function table(n: number, fill: (i: number) => string[], delim = ','): string {
  return Array.from({ length: n }, (_, i) => fill(i).join(delim)).join('\n') + '\n';
}

describe('U5: dataShape thresholds', () => {
  const row = (i: number): string[] => [`r${i}`, 'b', 'c'];

  it('19 lines are not delimited, 20 are', () => {
    expect(dataShape(table(19, row)).delimited).toBeUndefined();
    expect(dataShape(table(20, row)).delimited).toMatchObject({ delimiter: ',', fields: 3 });
  });

  it('89 percent regular is not delimited, 90 percent is', () => {
    const mk = (regular: number): string => table(100, i => (i < regular ? row(i) : [`only${i}`]));
    expect(dataShape(mk(89)).delimited).toBeUndefined();
    expect(dataShape(mk(90)).delimited).toMatchObject({ delimiter: ',', fields: 3 });
  });

  it('k = 1 is never delimited', () => {
    expect(dataShape(table(40, i => [`word${i}`])).delimited).toBeUndefined();
  });

  it.each([
    ['\t', 'tab'],
    ['|', 'pipe'],
    [';', 'semicolon'],
  ])('a %j table (%s) is delimited under its delimiter', delim => {
    expect(dataShape(table(30, row, delim)).delimited).toMatchObject({ delimiter: delim, fields: 3 });
  });

  it('a Markdown table is delimited under the pipe', () => {
    const md = ['| a | b |', '|---|---|', ...Array.from({ length: 25 }, (_, i) => `| x${i} | y${i} |`)].join('\n');
    expect(dataShape(md).delimited).toMatchObject({ delimiter: '|', fields: 4 });
  });

  it('a 65,535 character line is not long, a 65,536 character line is', () => {
    expect(dataShape('x'.repeat(65535) + '\nshort\n').longLines.size).toBe(0);
    const s = dataShape('short\n' + 'x'.repeat(65536) + '\n');
    expect([...s.longLines]).toEqual([2]);
  });

  it('RFC 4180 quoting: a delimiter inside quotes does not split, a doubled quote is literal', () => {
    const csv = table(25, i => [`${i}`, '"a, ""b"", c"', 'z']);
    expect(dataShape(csv).delimited).toMatchObject({ delimiter: ',', fields: 3 });
  });

  it('under every delimiter, two fields with an empty last are never regular', () => {
    const code = table(30, i => [`x${i} = ${i}`, ''], ';');
    expect(dataShape(code).delimited).toBeUndefined();
  });

  it('three fields with an empty last still count', () => {
    expect(dataShape(table(30, i => [`a${i}`, 'b', ''])).delimited).toMatchObject({ fields: 3 });
  });

  it('under the tab delimiter only, an empty first field is never regular', () => {
    const tabbed = table(30, i => ['', `cmd${i}`, 'arg'], '\t');
    expect(dataShape(tabbed).delimited).toBeUndefined();
    const commas = table(30, i => ['', `cat${i}`, 'arg'], ',');
    expect(dataShape(commas).delimited).toMatchObject({ delimiter: ',', fields: 3 });
  });

  it('the highest share wins, ties in the listed order', () => {
    // Every line splits into 2 under both comma and semicolon: comma wins the tie.
    const tie = table(30, i => [`a${i};b`, 'c;d']);
    expect(dataShape(tie).delimited?.delimiter).toBe(',');
  });
});

describe('groupSlot', () => {
  it('names the column of a match that lies within one field of a regular line', () => {
    const text = table(25, i => [`${i}`, 'name', `tok${i}value`, 'x']);
    const shape = dataShape(text);
    const offset = text.indexOf('tok7value');
    const line = text.slice(0, offset).split('\n').length;
    expect(groupSlot(shape, text, { offset, matchLength: 9, line })).toEqual({ basis: 'column', delimiter: ',', column: 2 });
    // Spanning a delimiter: no slot.
    expect(groupSlot(shape, text, { offset: offset - 2, matchLength: 9, line })).toBeUndefined();
  });

  it('names long-line for a match on a long line', () => {
    const text = 'head\n' + '{"a":"' + 'v'.repeat(70000) + '"}\n';
    const shape = dataShape(text);
    expect(groupSlot(shape, text, { offset: 20, matchLength: 5, line: 2 })).toEqual({ basis: 'long-line' });
    expect(groupSlot(shape, text, { offset: 0, matchLength: 4, line: 1 })).toBeUndefined();
  });
});
