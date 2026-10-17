import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

import * as fx from './git-fixture';

/**
 * results[].file is repository-relative (relative to the scan root, forward
 * slashes) in JSON and SARIF, and text output prints the same path, in every
 * mode. Before this, a scan whose target sat outside the cwd put the absolute
 * machine path in the JSON document (dogfood finding F28).
 *
 * Fingerprints are NOT derived from the displayed path. The positional
 * fingerprint of a finding inside the cwd is pinned below against its
 * published formula, so a baseline written before this change still matches.
 */
describe('results[].file is repository-relative in every mode', () => {
  const created: string[] = [];

  function tmp(prefix: string): string {
    const d = fx.tmpDir(prefix);
    created.push(d);
    return d;
  }

  afterAll(() => {
    for (const d of created) fs.rmSync(d, { recursive: true, force: true });
  });

  const LINE = `export const k = "${fx.AWS_KEY}";\n`;

  function files(doc: fx.JsonDoc): string[] {
    return doc.results.map(r => r.file).sort();
  }

  it('JSON for a target outside the cwd names the file relative to that target', () => {
    const target = tmp('vg-rel-target-');
    const elsewhere = tmp('vg-rel-cwd-');
    fx.write(target, 'src/leaked.ts', LINE);
    const r = fx.runCli(['scan', target, '--format', 'json'], elsewhere);
    expect(r.code).toBe(1);
    expect(files(fx.parse(r.stdout))).toEqual(['src/leaked.ts']);
    expect(r.stdout).not.toContain(target);
  });

  it('JSON for a single file named outside the cwd names it relative to its directory', () => {
    const target = tmp('vg-rel-file-');
    const elsewhere = tmp('vg-rel-cwd-');
    fx.write(target, 'leaked.ts', LINE);
    const r = fx.runCli(['scan', path.join(target, 'leaked.ts'), '--format', 'json'], elsewhere);
    expect(r.code).toBe(1);
    expect(files(fx.parse(r.stdout))).toEqual(['leaked.ts']);
    expect(r.stdout).not.toContain(target);
  });

  it('JSON for a target inside the cwd stays cwd-relative', () => {
    const root = tmp('vg-rel-in-');
    fx.write(root, 'sub/leaked.ts', LINE);
    const r = fx.runCli(['scan', path.join(root, 'sub'), '--format', 'json'], root);
    expect(files(fx.parse(r.stdout))).toEqual(['sub/leaked.ts']);
  });

  it('JSON for a target that is the parent of the cwd is relative to that target', () => {
    const root = tmp('vg-rel-parent-');
    fx.write(root, 'sub/leaked.ts', LINE);
    const r = fx.runCli(['scan', '..', '--format', 'json'], path.join(root, 'sub'));
    expect(files(fx.parse(r.stdout))).toEqual(['sub/leaked.ts']);
  });

  it('SARIF for a target outside the cwd carries the same relative path', () => {
    const target = tmp('vg-rel-sarif-');
    const elsewhere = tmp('vg-rel-cwd-');
    fx.write(target, 'src/leaked.ts', LINE);
    const r = fx.runCli(['scan', target, '--format', 'sarif'], elsewhere);
    const sarif = JSON.parse(r.stdout) as {
      runs: Array<{ results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }>;
    };
    expect(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('src/leaked.ts');
    expect(r.stdout).not.toContain(target);
  });

  it('text output for a target outside the cwd prints the relative path', () => {
    const target = tmp('vg-rel-text-');
    const elsewhere = tmp('vg-rel-cwd-');
    fx.write(target, 'src/leaked.ts', LINE);
    const r = fx.runCli(['scan', target], elsewhere);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain('src/leaked.ts:1:');
    expect(r.stdout).not.toContain(path.join(target, 'src'));
  });

  it('staged mode from a subdirectory is relative to the repository root', () => {
    const repo = tmp('vg-rel-staged-');
    fx.initRepo(repo);
    fx.write(repo, 'README.md', 'hello\n');
    fx.commitAll(repo, 'base');
    fx.write(repo, 'sub/leaked.ts', LINE);
    fx.git(repo, ['add', 'sub/leaked.ts']);
    const r = fx.runCli(['scan', '--staged', '--format', 'json'], path.join(repo, 'sub'));
    expect(files(fx.parse(r.stdout))).toEqual(['sub/leaked.ts']);
    expect(r.stdout).not.toContain(repo);
  });

  it('pull-request mode is relative to the repository root', () => {
    const repo = tmp('vg-rel-pr-');
    fx.initRepo(repo);
    fx.write(repo, '.vault-guard.json', JSON.stringify({ fail_on: 'medium' }));
    fx.commitAll(repo, 'base');
    fx.git(repo, ['branch', 'base-snapshot']);
    fx.write(repo, 'src/leaked.ts', LINE);
    fx.commitAll(repo, 'feature');
    const r = fx.runCli(['scan', '.', '--trust-base', 'base-snapshot', '--format', 'json'], repo);
    expect(r.code).toBe(1);
    expect(files(fx.parse(r.stdout))).toEqual(['src/leaked.ts']);
    expect(r.stdout).not.toContain(repo);
  });

  it('the positional fingerprint is the published formula over the cwd-relative path', () => {
    const root = tmp('vg-rel-fp-');
    fx.write(root, 'src/leaked.ts', LINE);
    const r = fx.runCli(['scan', '.', '--format', 'json'], root);
    const m = fx.parse(r.stdout).results[0].matches[0];
    const payload = `src/leaked.ts|${m.type}|${m.line}|${m.offset}|${fx.AWS_KEY.length}`;
    expect(m.fingerprint).toBe(createHash('sha256').update(payload, 'utf8').digest('hex'));
  });

  const sha = (payload: string): string => createHash('sha256').update(payload, 'utf8').digest('hex');

  it('the positional fingerprint for an out-of-cwd target is keyed on the original path, not the display path', () => {
    const target = tmp('vg-rel-fp-out-');
    const elsewhere = tmp('vg-rel-cwd-');
    fx.write(target, 'src/leaked.ts', LINE);
    const r = fx.runCli(['scan', target, '--format', 'json'], elsewhere);
    const doc = fx.parse(r.stdout);
    expect(doc.results[0].file).toBe('src/leaked.ts');
    const m = doc.results[0].matches[0];
    // Unchanged by the display root: the key is the absolute path, as before.
    const key = path.join(target, 'src', 'leaked.ts');
    expect(m.fingerprint).toBe(sha(`${key}|${m.type}|${m.line}|${m.offset}|${fx.AWS_KEY.length}`));
  });

  it('the positional fingerprint for a target spelled ".." keeps the "../" spelling relative to the cwd', () => {
    const root = tmp('vg-rel-fp-parent-');
    fx.write(root, 'sub/leaked.ts', LINE);
    const r = fx.runCli(['scan', '..', '--format', 'json'], path.join(root, 'sub'));
    const doc = fx.parse(r.stdout);
    expect(doc.results[0].file).toBe('sub/leaked.ts');
    const m = doc.results[0].matches[0];
    expect(m.fingerprint).toBe(sha(`../sub/leaked.ts|${m.type}|${m.line}|${m.offset}|${fx.AWS_KEY.length}`));
  });
});
