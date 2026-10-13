import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Shared helpers for the 2026-10-12 design's fixtures: temporary git
 * repositories built with real commits, and a way to capture what
 * scanCommand and baselineCommand print.
 */

/** An AWS-shaped access key id, built at run time (not the documentation example key). */
export const AWS_KEY = ['AKIA', 'Q7MZR2XVB9', 'NTD4WH'].join('');

/** A second, distinct AWS-shaped key. */
export const AWS_KEY_2 = ['AKIA', 'J3HQ8WZRT5', 'MKX2PB'].join('');

/** A full-body PEM private key (header-only rule), clearly synthetic. */
export function pemKey(variant = 0): string {
  const tail = ['Zq8mW2xRb7nTd4vHs6yLc3pJf8gRu5eNa1vBt0iOy7kPd2sXw4hEj6uCi3qAbCd', 'Yp3nK8vRt2mWq6xLc9bHs4jDf7gTu1eNa5vBz0iOy7kPd2sXw4hEj6uCi3qMnOp'][variant % 2];
  return [
    ['-----BEGIN RSA PRIV', 'ATE KEY-----'].join(''),
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCx32kL3AXuPTjn',
    tail,
    ['-----END RSA PRIV', 'ATE KEY-----'].join(''),
    '',
  ].join('\n');
}

export interface Captured {
  code: number;
  log: string;
  err: string;
  stdout: string;
}

export async function capture(fn: () => Promise<number>): Promise<Captured> {
  const logs: string[] = [];
  const errs: string[] = [];
  const outs: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const origOut = process.stdout.write;
  const origErrW = process.stderr.write;
  console.log = (...a: unknown[]): boolean => {
    logs.push(a.map(String).join(' '));
    return true;
  };
  console.error = (...a: unknown[]): boolean => {
    errs.push(a.map(String).join(' '));
    return true;
  };
  process.stdout.write = ((s: string | Uint8Array): boolean => {
    outs.push(String(s));
    return true;
  }) as typeof process.stdout.write;
  process.stderr.write = ((s: string | Uint8Array): boolean => {
    errs.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  let code: number;
  try {
    code = await fn();
  } finally {
    console.log = origLog;
    console.error = origErr;
    process.stdout.write = origOut;
    process.stderr.write = origErrW;
  }
  return { code, log: logs.join('\n'), err: errs.join('\n'), stdout: outs.join('') };
}

export function git(cwd: string, args: string[], env?: NodeJS.ProcessEnv): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf-8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...(env ? { env } : {}),
  });
}

export function initRepo(dir: string): void {
  git(dir, ['init', '-q', '-b', 'main']);
  git(dir, ['config', 'user.email', 'test@example.invalid']);
  git(dir, ['config', 'user.name', 'Test']);
  git(dir, ['config', 'commit.gpgsign', 'false']);
  git(dir, ['config', 'core.autocrlf', 'false']);
}

export function write(base: string, rel: string, data: string | Buffer): void {
  const abs = path.join(base, rel);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, data);
}

export function commitAll(dir: string, message: string): void {
  git(dir, ['add', '-A', '-f']);
  git(dir, ['commit', '-q', '-m', message]);
}

export function tmpDir(prefix: string): string {
  return fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

export interface JsonMatch {
  type: string;
  severity: string;
  line: number;
  offset: number;
  source?: string;
  fingerprint: string;
  content_fingerprint?: string;
}

export interface JsonDoc {
  run: Record<string, unknown>;
  results: Array<{ file: string; matches: JsonMatch[] }>;
  diagnostics?: Array<{ code: string; severity: string; ctx: Record<string, unknown> }>;
  trustBase?: { proposals: string[]; attributesChanged?: boolean; attributesPaths?: string[] };
}

export function parse(stdout: string): JsonDoc {
  return JSON.parse(stdout) as JsonDoc;
}

/** Every match as `file|rule|source`, sorted. */
export function sources(doc: JsonDoc): string[] {
  return doc.results.flatMap(r => r.matches.map(m => `${r.file}|${m.type}|${m.source ?? ''}`)).sort();
}

/** Absolute path of the built CLI, for subprocess fixtures. */
export const CLI_ENTRY = path.resolve(__dirname, '..', '..', '..', 'dist', 'cli-entry.js');

/** Run the built CLI as a subprocess. */
export function runCli(
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv = process.env,
): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [CLI_ENTRY, ...args], {
    cwd,
    env: { ...env, NO_COLOR: '1', FORCE_COLOR: '0' },
    encoding: 'utf-8',
  });
  return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

/**
 * A directory holding a `git` stub that logs its argv and environment to
 * `log`, one JSON line per call, then either runs the real git or, for the
 * subcommand named in `fail`, exits 128 with a message. `failArg` and
 * `failCwdSuffix` narrow the failure to calls carrying that argument, or run
 * in a directory ending with that suffix.
 */
export function gitStub(
  dir: string,
  log: string,
  opts: { fail?: string; failMessage?: string; failArg?: string; failCwdSuffix?: string } = {},
): string {
  const realGit = execFileSync('/bin/sh', ['-c', 'command -v git'], { encoding: 'utf-8' }).trim();
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin, { recursive: true });
  const script = [
    `#!${process.execPath}`,
    "const { spawnSync } = require('child_process');",
    "const fs = require('fs');",
    'const args = process.argv.slice(2);',
    `fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify({ args, cwd: process.cwd(), ` +
      'indexFile: process.env.GIT_INDEX_FILE ?? null, gitDir: process.env.GIT_DIR ?? null }) + "\\n");',
    "let i = 0; while (args[i] === '-c') i += 2;",
    `const failArg = ${JSON.stringify(opts.failArg ?? '')};`,
    `const failCwd = ${JSON.stringify(opts.failCwdSuffix ?? '')};`,
    "const argMatch = failArg === '' || args.includes(failArg);",
    "const cwdMatch = failCwd === '' || process.cwd().endsWith(failCwd);",
    `if (${JSON.stringify(opts.fail ?? '')} !== '' && args[i] === ${JSON.stringify(opts.fail ?? '')} && argMatch && cwdMatch) {`,
    `  process.stderr.write(${JSON.stringify(opts.failMessage ?? 'fatal: stubbed failure')} + "\\n");`,
    '  process.exit(128);',
    '}',
    `const r = spawnSync(${JSON.stringify(realGit)}, args, { stdio: 'inherit' });`,
    'process.exit(r.status === null ? 1 : r.status);',
    '',
  ].join('\n');
  const p = path.join(bin, 'git');
  fs.writeFileSync(p, script, { mode: 0o755 });
  return bin;
}

/** The logged git calls of a stub. */
export function stubCalls(log: string): Array<{ args: string[]; cwd: string; indexFile: string | null; gitDir: string | null }> {
  if (!fs.existsSync(log)) return [];
  return fs
    .readFileSync(log, 'utf-8')
    .split('\n')
    .filter(Boolean)
    .map(l => JSON.parse(l) as { args: string[]; cwd: string; indexFile: string | null; gitDir: string | null });
}

/** The git subcommand of a logged call, skipping `-c key=value` pairs. */
export function subcommand(args: string[]): string {
  let i = 0;
  while (args[i] === '-c') i += 2;
  return args[i] ?? '';
}
