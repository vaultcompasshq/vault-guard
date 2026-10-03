import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { SecretScanner } from '@vaultcompass/vault-guard-core';
import { scanFileListAsync } from '../utils/scan-utils';

/**
 * scanFileListAsync used to default its path-context root to the process cwd.
 * A caller that omitted pathRoot while standing in a workspace ABOVE the
 * repository then had every directory between the two (a runner workspace
 * named docs, a temp dir named loadtest) counted as test or documentation
 * context, which downgrades a private key found under it. Only scan.ts calls
 * it today and it passes the root explicitly; the default is the trap.
 */
describe('scanFileListAsync without a pathRoot', () => {
  const originalCwd = process.cwd();
  let base: string;

  const PEM = [
    ['-----BEGIN ', 'RSA PRIVATE', ' KEY-----'].join(''),
    'Zm9vYmFyYmF6cXV4Y29yZ2VncmF1bHRnYXJwbHl3YWxkb2ZyZWRwbHVnaHhkeXp6eQ',
    'a2V5bWF0ZXJpYWxmb3J0ZXN0aW5nb25seW5vdGFyZWFsa2V5YXRhbGxub3Blbm9wZQ',
    ['-----END ', 'RSA PRIVATE', ' KEY-----'].join(''),
    '',
  ].join('\n');

  beforeEach(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-listroot-')));
  });

  afterEach(() => {
    process.chdir(originalCwd);
    fs.rmSync(base, { recursive: true, force: true });
  });

  it('judges context from the repository, not from an ancestor cwd', async () => {
    const repo = path.join(base, 'loadtest', 'docs', 'repo');
    fs.mkdirSync(path.join(repo, 'src'), { recursive: true });
    execSync('git init -q', { cwd: repo, stdio: 'ignore' });
    const file = path.join(repo, 'src', 'config.ts');
    fs.writeFileSync(file, `export const pem = \`${PEM}\`;\n`);
    process.chdir(base);

    const results = await scanFileListAsync([file], new SecretScanner(), {});

    const severities = results.flatMap(r => r.matches.map(m => m.severity));
    expect(severities).toContain('critical');
  });
});
