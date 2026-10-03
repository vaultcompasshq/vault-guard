import { SecretScanner } from '../secret-scanner';
import { isShortDockerPatExample } from '../../utils/placeholder';

/**
 * API reference docs carry a keyboard-mash Docker personal access token as an
 * example value. It is matched by the generic `secret` rule, not by a vendor
 * rule, and it is not the shape Docker issues (a real token carries a long
 * random suffix), so it is documentation, not a credential.
 */
describe('a short dckr_pat_ example value', () => {
  const scanner = new SecretScanner();
  const EXAMPLE = ['dckr_pat_', '124509ugsdjga93'].join('');

  const generic = (content: string, file = 'data/api-reference.json'): string[] =>
    scanner
      .scanContent(content, { filePath: file })
      .filter(m => m.type === 'secret-generic')
      .map(m => m.type);

  it('is recognised by shape', () => {
    expect(isShortDockerPatExample(EXAMPLE)).toBe(true);
    expect(isShortDockerPatExample(['dckr_pat_', 'a'.repeat(27)].join(''))).toBe(false);
    expect(isShortDockerPatExample('not_a_pat_value')).toBe(false);
  });

  it('is not reported by the generic secret rule', () => {
    expect(generic(`{"example": {"secret": "${EXAMPLE}"}}`)).toEqual([]);
    expect(generic(`    examples:\n      secret: ${EXAMPLE}\n`, 'content/reference/latest.yaml')).toEqual([]);
  });

  it('a full-length token under the same key is still reported', () => {
    const real = ['dckr_pat_', 'Zq7Kp2mXv9RtLw4NbYc8Hd3JfGs'].join('');
    expect(generic(`{"secret": "${real}"}`).length).toBeGreaterThan(0);
  });
});
