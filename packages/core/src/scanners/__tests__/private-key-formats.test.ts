import { SecretScanner } from '../secret-scanner';
import { isSampleJwt } from '../../utils/placeholder';

/**
 * Found by scanning public repositories: a bare PKCS#8 key file scanned clean
 * and the CLI printed "No secrets found". The rule required an algorithm name
 * between BEGIN and PRIVATE, which PKCS#8 does not have.
 */
describe('private key PEM headers', () => {
  const scanner = new SecretScanner();

  const headers = [
    '-----BEGIN PRIVATE KEY-----', // PKCS#8, the default OpenSSL output
    '-----BEGIN RSA PRIVATE KEY-----',
    '-----BEGIN EC PRIVATE KEY-----',
    '-----BEGIN DSA PRIVATE KEY-----',
    '-----BEGIN OPENSSH PRIVATE KEY-----',
    '-----BEGIN ENCRYPTED PRIVATE KEY-----',
    '-----BEGIN PGP PRIVATE KEY BLOCK-----'.replace(' BLOCK', ''),
  ];

  // A real PEM body wraps base64 at 64 characters per line.
  const body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn';

  it.each(headers)('detects %s', header => {
    const matches = scanner.scanContent(`${header}\n${body}\n`);
    expect(matches.map(m => m.type)).toContain('ssh-private-key');
  });

  it('does not fire on a public key header', () => {
    const matches = scanner.scanContent('-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkq\n');
    expect(matches.map(m => m.type)).not.toContain('ssh-private-key');
  });

  it('does not fire on a certificate header', () => {
    const matches = scanner.scanContent('-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+g\n');
    expect(matches.map(m => m.type)).not.toContain('ssh-private-key');
  });
});

describe('Supabase local-development JWTs', () => {
  const scanner = new SecretScanner();

  // Payload: {"iss":"supabase-demo","role":"anon","exp":1983812996}
  const demoAnonKey =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9' +
    '.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0';

  it('recognises the demo issuer', () => {
    expect(isSampleJwt(demoAnonKey)).toBe(true);
  });

  it('does not report it as a leaked token', () => {
    const matches = scanner.scanContent(`const SUPABASE_ANON_KEY = "${demoAnonKey}";`);
    expect(matches.map(m => m.type)).not.toContain('jwt-token');
  });

  it('still reports a JWT with an ordinary issuer', () => {
    const payload = Buffer.from(
      JSON.stringify({ iss: 'https://auth.acme-corp.io', role: 'service_role', exp: 1983812996 }),
    ).toString('base64url');
    const token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0`;
    const matches = scanner.scanContent(`const KEY = "${token}";`);
    expect(matches.map(m => m.type)).toContain('jwt-token');
  });
});
