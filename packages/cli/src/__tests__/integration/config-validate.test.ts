import * as fs from 'fs';
import * as path from 'path';

import { configValidateCommand } from '../../commands/config';
import * as fx from './git-fixture';

/**
 * `vault-guard config validate` refuses a linked config and never prints the
 * engine's JSON parse message (design 2026-10-12, 4.1 and 4.2).
 */

const itPosix = process.platform === 'win32' ? it.skip : it;

describe('config validate and control-file links', () => {
  const dirs: string[] = [];

  afterEach(() => {
    for (const d of dirs.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  function repo(): { parent: string; repo: string } {
    const parent = fx.tmpDir('vg-validate-');
    dirs.push(parent);
    const r = path.join(parent, 'repo');
    fs.mkdirSync(r);
    fx.initRepo(r);
    return { parent, repo: r };
  }

  itPosix('F20: config validate refuses a symlinked config and echoes none of it', async () => {
    const { parent, repo: r } = repo();
    fs.writeFileSync(path.join(parent, 'outside.json'), 'aws_secret victim-file-marker-7731 {');
    fs.symlinkSync('../outside.json', path.join(r, '.vault-guard.json'));
    const out = await fx.capture(() => configValidateCommand(r));
    expect(out.code).toBe(1);
    expect(out.err).toContain('is a symlink, not a regular file');
    expect(`${out.log}\n${out.err}`).not.toContain('victim-file-marker');
    expect(`${out.log}\n${out.err}`).not.toContain('aws_secret');
  });

  it('F20: a regular invalid config gives the parse failure and at most a line and column', async () => {
    const { repo: r } = repo();
    fs.writeFileSync(path.join(r, '.vault-guard.json'), '{\n  "fail_on": "high",\n  aws_secret victim-file-marker-7731\n}\n');
    const out = await fx.capture(() => configValidateCommand(r));
    expect(out.code).toBe(1);
    expect(out.err).toContain('could not be parsed as JSON');
    expect(out.err).toMatch(/line 3, column \d+/);
    expect(`${out.log}\n${out.err}`).not.toContain('victim-file-marker');
    expect(`${out.log}\n${out.err}`).not.toContain('aws_secret');
  });

  it('F20: an invalid config whose engine message would quote its content prints none of it', async () => {
    // Node 22 quotes the start of the input for this shape of error.
    const { repo: r } = repo();
    fs.writeFileSync(path.join(r, '.vault-guard.json'), '{"a": victim-file-marker-7731}');
    const out = await fx.capture(() => configValidateCommand(r));
    expect(out.code).toBe(1);
    expect(out.err).toContain('could not be parsed as JSON');
    expect(`${out.log}\n${out.err}`).not.toContain('victim-fil');
  });
});
