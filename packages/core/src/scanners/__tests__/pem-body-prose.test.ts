import { SecretScanner } from '../secret-scanner';
import { applyPathAwareSeverity } from '../../utils/path-severity';
import { isPemHeaderWithoutBody } from '../../utils/placeholder';

/**
 * A PEM header followed by ordinary prose is not a key. The body check used to
 * strip ALL whitespace from the following lines, so any prose line of 32 or
 * more unpunctuated letters looked like a base64 "body". That mattered once a
 * PEM stopped being downgraded on documentation paths.
 */
describe('a PEM body must be base64 on its own terms', () => {
  const scanner = new SecretScanner();
  const HEADER = ['-----BEGIN ', 'OPENSSH PRIVATE', ' KEY-----'].join('');
  const FOOTER = ['-----END ', 'OPENSSH PRIVATE', ' KEY-----'].join('');
  const BODY = [
    'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz',
    'c2gtcnNhAAAAAwEAAQAAAYEAtZ3mQpL8vXkR2hN7cWfT9yBd4uJ1aKsGx0eMoPq6',
  ].join('\n');

  const severities = (content: string, file: string): string[] =>
    applyPathAwareSeverity(scanner.scanContent(content, { filePath: file }), file)
      .filter(m => m.type === 'ssh-private-key')
      .map(m => m.severity);

  const prose = `To generate one, run ssh-keygen. The file starts with ${HEADER}\nand then the private key file contains the encoded material for you\nso keep it somewhere safe and never share it with anyone\n`;

  it.each(['docs/setup.md', 'README.md', 'CLAUDE.md'])(
    'prose that merely names the header in %s is not critical',
    file => {
      expect(severities(prose, file)).not.toContain('critical');
    },
  );

  it('a copy of the CHANGELOG paragraph about the PGP header is not critical', () => {
    const paragraph = [
      '- **OpenPGP private key headers were never detected.** A real header ends',
      '  `-----BEGIN PGP PRIVATE KEY BLOCK-----`, and the rule required',
      '  `PRIVATE KEY-----`, so it matched neither the old nor the newly bounded form.',
      '  The test that claimed coverage manufactured its own pass by deleting',
      '  " BLOCK" from the header before scanning, so the gap was invisible. The rule',
      '  now accepts the optional ` BLOCK` suffix (a fixed literal, measured to add no',
      '  backtracking) and the test asserts the real header.',
      '',
    ].join('\n');
    expect(severities(paragraph, 'CHANGELOG.md')).not.toContain('critical');
    expect(severities(paragraph, 'docs/x.md')).not.toContain('critical');
  });

  it.each(['docs/runbook.md', 'CLAUDE.md'])('a real full-body PEM in %s still blocks', file => {
    expect(severities(`${HEADER}\n${BODY}\n${FOOTER}\n`, file)).toContain('critical');
  });

  it('a key embedded in JSON with escaped newlines still blocks', () => {
    const src = `{"k": "${HEADER}\\n${BODY.split('\n')[0]}\\n${FOOTER}"}`;
    expect(severities(src, 'docs/x.md')).toContain('critical');
  });

  it('a lowercase-only or letters-only 40+ run is not a body', () => {
    const off = HEADER.length;
    expect(isPemHeaderWithoutBody(`${HEADER}\n${'abcdefghij'.repeat(5)}\n`, off)).toBe(true);
    expect(isPemHeaderWithoutBody(`${HEADER}\n${'AbCdEfGhIj'.repeat(5)}\n`, off)).toBe(true);
  });

  it('a whitespace-separated sentence is not a body', () => {
    const off = HEADER.length;
    const line = 'this line is only ordinary english words and has no digits';
    expect(isPemHeaderWithoutBody(`${HEADER}\n${line}\n`, off)).toBe(true);
  });
});
