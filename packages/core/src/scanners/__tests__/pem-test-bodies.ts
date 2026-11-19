import { createHash } from 'crypto';

/**
 * A deterministic body of base64 characters that behaves like key material: a
 * chain of SHA-256 digests, so it has no repeated phrase and no word-like runs
 * beyond what random bytes give. (The linear-congruential bodies these tests used
 * before repeat every few hundred characters, which a real key never does.)
 */
export function randomBody(n: number, seed = 1): string {
  let out = '';
  let h = createHash('sha256').update(`vault-guard-test-body-${seed}`).digest();
  while (out.length < n) {
    out += h.toString('base64').replace(/=/g, '');
    h = createHash('sha256').update(h).digest();
  }
  return out.slice(0, n);
}
