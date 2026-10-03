import { SecretScanner } from '../secret-scanner';
import { isPemHeaderWithoutBody } from '../../utils/placeholder';

/**
 * The PEM body heuristic has been rewritten twice and the last rewrite
 * regressed (a Python bytes literal went from found to missed). This file is
 * the corpus: every shape a real private key has been seen in, as a test, and
 * the look-alikes that must NOT be reported. A change to the heuristic has to
 * keep both halves green.
 *
 * Bodies are synthetic 64-character base64 lines, never real key material.
 * Headers are assembled from fragments so this repository's own scan does not
 * flag the file.
 */
describe('PEM body corpus', () => {
  const scanner = new SecretScanner();
  const header = (kind: string): string => ['-----BEGIN ', kind, ' KEY-----'].join('');
  const footer = (kind: string): string => ['-----END ', kind, ' KEY-----'].join('');
  const RSA = 'RSA PRIVATE';
  const HEADER = header(RSA);
  const FOOTER = footer(RSA);

  const L1 = 'MIIEowIBAAKCAQEAtZ3mQpL8vXkR2hN7cWfT9yBd4uJ1aKsGx0eMoPq6RzVnYwHa';
  const L2 = 'c2gtcnNhAAAAAwEAAQAAAYEAtZ3mQpL8vXkR2hN7cWfT9yBd4uJ1aKsGx0eMoPq6';
  const L3 = 'Zk4tUv8Jq2LmNrXs7DfGhY1cWbVeAo9TpIu3SyQ5RkEjHdCaBn6MwPzLgFtXv0Oi';
  const LAST = 'AQABq1w2E3r4==';
  const BODY = [L1, L2, L3, LAST];

  const found = (content: string, file = 'src/app.ts'): boolean =>
    scanner.scanContent(content, { filePath: file }).some(m => m.type === 'ssh-private-key');

  describe('shapes that must be reported', () => {
    const shapes: Array<[string, string]> = [
      ['c01 plain PEM', [HEADER, ...BODY, FOOTER, ''].join('\n')],
      [
        'c02 legacy encrypted PEM with Proc-Type, DEK-Info and a blank line',
        [HEADER, 'Proc-Type: 4,ENCRYPTED', 'DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF', '', ...BODY, FOOTER].join('\n'),
      ],
      ['c03 blockquote', [`> ${HEADER}`, ...BODY.map(l => `> ${l}`), `> ${FOOTER}`].join('\n')],
      ['c04 hash comment lines', [`# ${HEADER}`, ...BODY.map(l => `# ${l}`), `# ${FOOTER}`].join('\n')],
      ['c04b hash comment lines, no space', [`#${HEADER}`, ...BODY.map(l => `#${l}`), `#${FOOTER}`].join('\n')],
      ['c05 Python bytes literal lines', [`key = (b"${HEADER}\\n"`, ...BODY.map(l => `       b"${l}\\n"`), `       b"${FOOTER}\\n")`].join('\n')],
      ['c05b Python raw and unicode string prefixes', [`k = (r'${HEADER}'`, ...BODY.map(l => `     u'${l}'`), `     f'${FOOTER}')`].join('\n')],
      ['c06 JS string concatenation', [`const k = "${HEADER}\\n" +`, ...BODY.map(l => `  "${l}\\n" +`), `  "${FOOTER}\\n";`].join('\n')],
      ['c07 block comment stars', ['/*', ` * ${HEADER}`, ...BODY.map(l => ` * ${l}`), ` * ${FOOTER}`, ' */'].join('\n')],
      ['c07b double slash comments', [`// ${HEADER}`, ...BODY.map(l => `// ${l}`), `// ${FOOTER}`].join('\n')],
      ['c08 GCP service account JSON', `{"type":"service_account","private_key":"${HEADER}\\n${BODY.join('\\n')}\\n${FOOTER}\\n"}`],
      ['c09 XML hex newline entities', `<key>${HEADER}&#xA;${BODY.join('&#xA;')}&#xA;${FOOTER}</key>`],
      ['c09b XML decimal newline entities', `<key>${HEADER}&#10;${BODY.join('&#10;')}&#10;${FOOTER}</key>`],
      ['c10 SQL comment lines', [`-- ${HEADER}`, ...BODY.map(l => `-- ${l}`), `-- ${FOOTER}`].join('\n')],
      ['c12 flattened onto one line with spaces (.env style)', `PRIVATE_KEY="${HEADER} ${BODY.join(' ')} ${FOOTER}"`],
      ['c13 TOML array with trailing commas', [`keys = [`, `  "${HEADER}",`, ...BODY.map(l => `  "${l}",`), `  "${FOOTER}",`, `]`].join('\n')],
      ['c14 semicolon comment lines', [`; ${HEADER}`, ...BODY.map(l => `; ${l}`), `; ${FOOTER}`].join('\n')],
      ['c15 CRLF line endings', [HEADER, ...BODY, FOOTER, ''].join('\r\n')],
      ['c16 indented YAML block', ['key: |', `  ${HEADER}`, ...BODY.map(l => `  ${l}`), `  ${FOOTER}`].join('\n')],
      ['c17 body only one line long (ed25519 PKCS8 size)', [header('PRIVATE'), L1, footer('PRIVATE')].join('\n')],
      ['n4a YAML sequence of key lines', ['keys:', `  - ${HEADER}`, ...BODY.map(l => `  - ${l}`), `  - ${FOOTER}`].join('\n')],
      ['n4b PHP trailing dot concatenation', [`$k = '${HEADER}\\n' .`, ...BODY.map(l => `  '${l}\\n' .`), `  '${FOOTER}\\n';`].join('\n')],
      ['n4b VB trailing ampersand', [`k = "${HEADER}" & _`, ...BODY.map(l => `  "${l}" & _`), `  "${FOOTER}"`].join('\n')],
      ['n4b Lua trailing double dot', [`local k = "${HEADER}\\n" ..`, ...BODY.map(l => `  "${l}\\n" ..`), `  "${FOOTER}"`].join('\n')],
      ['n4b JS trailing double pipe', [`const k = "${HEADER}" ||`, ...BODY.map(l => `  "${l}" ||`), `  "${FOOTER}";`].join('\n')],
      ['n4c br tag line breaks', `<p>${HEADER}<br>${BODY.join('<br>')}<br/>${FOOTER}</p>`],
      ['n4c unicode escaped line breaks (lowercase)', `"${HEADER}\\u000a${BODY.join('\\u000a')}\\u000a${FOOTER}"`],
      ['n4c unicode escaped CR LF (uppercase)', `"${HEADER}\\u000D\\u000A${BODY.join('\\u000D\\u000A')}\\u000D\\u000A${FOOTER}"`],
    ];

    it.each(shapes)('%s', (_name, content) => {
      expect(found(content)).toBe(true);
    });

    it('c11 PGP armor with more than 400 characters of Comment headers', () => {
      const pgp = header('PGP PRIVATE').replace('KEY-----', 'KEY BLOCK-----');
      const comments = Array.from({ length: 12 }, (_, i) => `Comment: ${'generated by a long running export tool, line '.repeat(1)}${i}`);
      const text = [pgp, 'Version: GnuPG v2', ...comments, '', ...BODY, '=AbCd', footer('PGP PRIVATE').replace('KEY-----', 'KEY BLOCK-----')].join('\n');
      expect(comments.join('\n').length).toBeGreaterThan(400);
      expect(found(text)).toBe(true);
    });

    it('c18 a commented-out key in a TypeScript source file blocks', () => {
      const text = [`// ${HEADER}`, ...BODY.map(l => `// ${l}`), `// ${FOOTER}`].join('\n');
      expect(found(text, 'src/legacy.ts')).toBe(true);
    });

    it('c05 pinned as the 1.9.0 regression: a bytes literal body line alone is a body', () => {
      const off = HEADER.length;
      expect(isPemHeaderWithoutBody(`${HEADER}\\n"\n       b"${L1}\\n"\n`, off)).toBe(false);
    });
  });

  describe('look-alikes that must NOT be reported', () => {
    const lookAlikes: Array<[string, string]> = [
      ['header alone as a UI label', `const label = '${HEADER}';\n`],
      ['header and footer with nothing between', `${HEADER}\n${FOOTER}\n`],
      ['ellipsis body', `${HEADER}\n...\n${FOOTER}\n`],
      ['x-mask body', `${HEADER}\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n${FOOTER}\n`],
      ['commented header and footer, no body', `# ${HEADER}\n# ...\n# ${FOOTER}\n`],
      ['placeholder instruction body', `${HEADER}\n<paste your key here>\n${FOOTER}\n`],
      ['lowercase-only long run', `${HEADER}\n${'abcdefghij'.repeat(6)}\n`],
      ['letters-only mixed-case long run', `${HEADER}\n${'AbCdEfGhIj'.repeat(6)}\n`],
      ['prose naming the header, then a sentence', `The file starts with ${HEADER}\nand then the private key file contains the encoded material for you\n`],
      ['a long base64 token inside a prose sentence', `${HEADER}\nsee ${L1} in the guide for more about keys\n`],
      ['an ssh public key line after the header mention', `Paste the key after ${HEADER}\nssh-rsa ${L1} user@example\n`],
      ['a code line with a long camelCase identifier and a trailing statement', `// ${HEADER}\nconst x = someVeryLongIdentifierNameWithADigit2AndMoreMoreMoreWords + 1;\n`],
      ['a certificate block that follows the mention', `Looks like ${HEADER}\n\n-----BEGIN CERTIFICATE-----\n${L1}\n${L2}\n-----END CERTIFICATE-----\n`],
      ['a hex dump', `${HEADER}\n${'3082 0122 300d 0609 2a86 4886 f70d 0101 '.repeat(2)}\n${FOOTER}\n`],
    ];

    it.each(lookAlikes)('%s', (_name, content) => {
      expect(found(content, 'docs/notes.md')).toBe(false);
      expect(found(content, 'src/app.ts')).toBe(false);
    });
  });
});
