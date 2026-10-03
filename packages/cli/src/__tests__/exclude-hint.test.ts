import * as path from 'path';
import { buildConfigIgnoreFilter } from '@vaultcompass/vault-guard-core';
import { excludePatternFor, excludeEntryNote, formatExcludeEntry } from '../utils/scan-utils';

/**
 * The exclude the message tells a person to add has to work when pasted. It is
 * printed as a JSON string, so it is valid inside ignore.paths as written, and
 * the gitignore escaping inside it has to make the pattern match the file it
 * names, and no unrelated sibling. The one exception is a question mark, which
 * the matcher cannot match literally; see the dedicated case below.
 */
describe('the exclude hint, pasted verbatim into ignore.paths', () => {
  const root = path.resolve('/repo-root-for-hint-test');
  const names = [
    'src/sub dir/a b.txt',
    '-leading-dash.txt',
    'src/[brackets]/f[1].txt',
    'src/star*name.txt',
    '#hash.txt',
    '!bang.txt',
    'trailing space .txt',
    ...(process.platform === 'win32' ? [] : ['src/ends with a space ']),
    ...(process.platform === 'win32' ? [] : ['src/back\\slash.txt']),
  ];

  it.each(names)('%s', name => {
    const file = path.join(root, ...name.split('/'));
    const pattern = excludePatternFor(file, root) as string;
    expect(pattern).toBeDefined();

    // What the person copies from the message is the printed form; what the
    // config loader sees is that JSON string, parsed.
    const printed = formatExcludeEntry(pattern);
    const entry = JSON.parse(printed) as string;
    expect(entry).toBe(pattern);

    expect(buildConfigIgnoreFilter([entry], root)(file)).toBe(true);
    // And it names that file only, not an unrelated sibling.
    const sibling = path.join(path.dirname(file), 'unrelated-sibling.txt');
    expect(buildConfigIgnoreFilter([entry], root)(sibling)).toBe(false);
  });

  it('a question mark matches any single character, so a decoy differing there is excluded too, and the note says so', () => {
    // The gitignore matcher cannot match a literal question mark. The entry is
    // still printed, with one sentence saying what it also covers.
    const file = path.join(root, 'q?mark.ts');
    const decoy = path.join(root, 'qXmark.ts');
    const pattern = excludePatternFor(file, root) as string;
    expect(buildConfigIgnoreFilter([pattern], root)(file)).toBe(true);
    expect(buildConfigIgnoreFilter([pattern], root)(decoy)).toBe(true);
    expect(excludeEntryNote(pattern)).toMatch(/question mark matches any single character/);
    expect(excludeEntryNote('/plain.ts')).toBe('');
  });

  it('is valid JSON when the name needs escaping', () => {
    const pattern = excludePatternFor(path.join(root, 'sub dir', 'a b.txt'), root) as string;
    expect(() => JSON.parse(formatExcludeEntry(pattern))).not.toThrow();
  });
});
