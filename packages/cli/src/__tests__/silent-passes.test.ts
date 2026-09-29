import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { SecretScanner } from '@vaultcompass/vault-guard-core';
import { scanCommand } from '../commands/scan';

/**
 * Regression pins for the "reports clean on things it did not properly check"
 * audit batch: path context judged on the absolute path, --staged skipping a
 * NUL-bearing blob without a word, live vendor keys downgraded in docs, and
 * exit 1 used for things that are not findings.
 *
 * Every secret-shaped value is assembled from fragments at runtime so no
 * real-looking credential sits in the repository.
 */

const VENDOR_KEY = [
  'sk-ant-',
  'api03-',
  'Kq7mZr2xVb9nTd4wHs6yLc3p',
  'Jf8gRu5eNa1vBt0iOy7kPd2s',
  'Xw4hEj6uCi3q',
].join('');

const PEM = [
  ['-----BEGIN ', 'RSA PRIVATE', ' KEY-----'].join(''),
  'Zm9vYmFyYmF6cXV4Y29yZ2VncmF1bHRnYXJwbHl3YWxkb2ZyZWRwbHVnaHhkeXp6eQ',
  'a2V5bWF0ZXJpYWxmb3J0ZXN0aW5nb25seW5vdGFyZWFsa2V5YXRhbGxub3Blbm9wZQ',
  'dGhpc2lzYWRpZmZlcmVudGxpbmVvZmZha2Vib2R5dGV4dGZvcnRoZXNjYW5uZXJ0bw',
  ['-----END ', 'RSA PRIVATE', ' KEY-----'].join(''),
  '',
].join('\n');

interface Capture {
  out: string[];
  err: string[];
}

describe('silent-pass fixes', () => {
  const originalCwd = process.cwd();
  let base: string;
  let cap: Capture;

  beforeEach(() => {
    base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-silent-')));
    cap = { out: [], err: [] };
    jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => {
      cap.out.push(a.map(String).join(' '));
    });
    jest.spyOn(console, 'warn').mockImplementation((...a: unknown[]) => {
      cap.err.push(a.map(String).join(' '));
    });
    jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
      cap.err.push(a.map(String).join(' '));
    });
    jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      cap.out.push(String(chunk));
      return true;
    });
    jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      cap.err.push(String(chunk));
      return true;
    });
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.chdir(originalCwd);
    fs.rmSync(base, { recursive: true, force: true });
  });

  const write = (root: string, rel: string, content: string | Buffer): void => {
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  };

  /** A checkout whose ABSOLUTE path passes through docs/ and loadtest/. */
  const hostileRoot = (): string => {
    const root = path.join(base, 'loadtest', 'docs', 'repo');
    fs.mkdirSync(root, { recursive: true });
    return root;
  };

  const gitInit = (root: string): void => {
    execSync('git init -q', { cwd: root, stdio: 'ignore' });
    execSync('git config user.email "t@example.com"', { cwd: root, stdio: 'ignore' });
    execSync('git config user.name "T"', { cwd: root, stdio: 'ignore' });
  };

  const stage = (root: string, ...names: string[]): void => {
    for (const n of names) execSync(`git add ${n}`, { cwd: root, stdio: 'ignore' });
  };

  const outText = (): string => cap.out.join('\n');
  const errText = (): string => cap.err.join('\n');

  // ---------------------------------------------------------------- fix 1
  describe('path context is judged relative to the scan root', () => {
    it('directory mode, absolute target: vendor key in src/config.ts blocks under docs/ and loadtest/', async () => {
      const root = hostileRoot();
      write(root, 'src/config.ts', `export const k = "${VENDOR_KEY}";\n`);
      process.chdir(root);

      const code = await scanCommand(root, 'text', false);

      expect(code).toBe(1);
      expect(outText()).toMatch(/BLOCKED/);
    });

    it('directory mode, target ".": vendor key in src/config.ts blocks under docs/ and loadtest/', async () => {
      const root = hostileRoot();
      write(root, 'src/config.ts', `export const k = "${VENDOR_KEY}";\n`);
      process.chdir(root);

      const code = await scanCommand('.', 'text', false);

      expect(code).toBe(1);
    });

    it('directory mode: a PEM private key in src/config.ts blocks under docs/ and loadtest/', async () => {
      const root = hostileRoot();
      write(root, 'src/config.ts', `export const pem = \`${PEM}\`;\n`);
      process.chdir(root);

      const code = await scanCommand(root, 'text', false);

      expect(code).toBe(1);
    });

    it('directory mode, cwd elsewhere: an absolute target outside cwd is judged from the target', async () => {
      const root = hostileRoot();
      write(root, 'src/config.ts', `export const pem = \`${PEM}\`;\n`);
      const elsewhere = path.join(base, 'elsewhere');
      fs.mkdirSync(elsewhere);
      process.chdir(elsewhere);

      const code = await scanCommand(root, 'text', false);

      expect(code).toBe(1);
    });

    it('--staged: vendor key in src/config.ts blocks when the repo path contains docs/ and loadtest/', async () => {
      const root = hostileRoot();
      gitInit(root);
      write(root, 'src/config.ts', `export const k = "${VENDOR_KEY}";\n`);
      stage(root, 'src/config.ts');
      process.chdir(root);

      const code = await scanCommand('.', 'text', true);

      expect(code).toBe(1);
    });

    it('--staged: a PEM private key in src/config.ts blocks when the repo path contains docs/ and loadtest/', async () => {
      const root = hostileRoot();
      gitInit(root);
      write(root, 'src/config.ts', `export const pem = \`${PEM}\`;\n`);
      stage(root, 'src/config.ts');
      process.chdir(root);

      const code = await scanCommand('.', 'text', true);

      expect(code).toBe(1);
    });

    it('a real test directory INSIDE the scan root still downgrades a PEM fixture', async () => {
      const root = hostileRoot();
      write(root, 'tests/fixtures/key.ts', `export const pem = \`${PEM}\`;\n`);
      process.chdir(root);

      const code = await scanCommand(root, 'text', false);

      expect(code).toBe(0);
    });
  });

  // ---------------------------------------------------------------- fix 2
  describe('--staged never silently passes a blob it skipped', () => {
    it('a staged .ts file with a key and one NUL byte exits 2, not 0', async () => {
      gitInit(base);
      write(base, 'src/a.ts', `const k = "${VENDOR_KEY}";\n\0\n`);
      stage(base, 'src/a.ts');
      process.chdir(base);

      const code = await scanCommand('.', 'text', true);

      expect(code).toBe(2);
      expect(outText()).not.toMatch(/SUCCESS/);
      expect(errText()).toContain('src/a.ts');
    });

    it('the NUL-bearing blob is counted in run.unscannable_files in JSON', async () => {
      gitInit(base);
      write(base, 'src/a.ts', `const k = "${VENDOR_KEY}";\n\0\n`);
      stage(base, 'src/a.ts');
      process.chdir(base);

      const code = await scanCommand('.', 'json', true);

      const body = JSON.parse(outText().trim()) as { run?: { unscannable_files?: number } };
      expect(body.run?.unscannable_files).toBe(1);
      expect(code).toBe(2);
    });

    it('a staged binary-extension file (.png) with NUL is still skipped, as in directory mode', async () => {
      gitInit(base);
      write(base, 'img/logo.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01, 0x02]));
      stage(base, 'img/logo.png');
      process.chdir(base);

      const code = await scanCommand('.', 'text', true);

      expect(code).toBe(0);
    });
  });

  // ---------------------------------------------------------------- fix 3
  describe('vendor-anchored keys are not downgraded in docs or markdown', () => {
    const cases: Array<[string, string]> = [
      ['NOTES.md', `Use this key: ${VENDOR_KEY}\n`],
      ['CLAUDE.md', `ANTHROPIC_API_KEY=${VENDOR_KEY}\n`],
      ['docs/x.md', `export ANTHROPIC_API_KEY=${VENDOR_KEY}\n`],
    ];

    it.each(cases)('a vendor key in %s still blocks', async (name, body) => {
      write(base, name, body);
      process.chdir(base);

      const code = await scanCommand('.', 'text', false);

      expect(code).toBe(1);
    });

    it('a generic password assignment in docs still downgrades to low', async () => {
      write(base, 'docs/setup.md', 'Set `api_key = "aB3cD4eF5gH6iJ7kLmNoPqRs"` in your config.\n');
      process.chdir(base);

      const code = await scanCommand('.', 'json', false);

      const body = JSON.parse(outText().trim()) as {
        run: { blocking_matches: number };
        summary: { secrets: number };
      };
      expect(body.summary.secrets).toBeGreaterThan(0);
      expect(body.run.blocking_matches).toBe(0);
      expect(code).toBe(0);
    });
  });

  // ---------------------------------------------------------------- fix 4
  describe('exit 1 means findings only', () => {
    it('an invalid config exits 2', async () => {
      write(base, '.vault-guard.json', '{ not json');
      write(base, 'a.ts', 'const x = 1;\n');
      process.chdir(base);

      expect(await scanCommand('.', 'text', false)).toBe(2);
    });

    it('--staged outside a git repository exits 2', async () => {
      process.chdir(base);

      expect(await scanCommand('.', 'text', true)).toBe(2);
    });

    it('an invalid --fail-on exits 2', async () => {
      write(base, 'a.ts', 'const x = 1;\n');
      process.chdir(base);

      expect(await scanCommand('.', 'text', false, 'bogus')).toBe(2);
    });

    it('a fatal error exits 2', async () => {
      write(base, 'a.ts', 'const x = 1;\n');
      process.chdir(base);
      jest.spyOn(SecretScanner.prototype, 'getActivePatternCount').mockImplementation(() => {
        throw new Error('boom');
      });

      expect(await scanCommand('.', 'text', false)).toBe(2);
    });
  });
});
