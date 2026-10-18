import fs from 'fs';
import os from 'os';
import path from 'path';

import { contentRelPath } from '../index';

/**
 * The path a content key is built from: links in the parent directory are
 * resolved, the leaf never is (review of audit 2026-10-18, N1).
 */
const itPosix = process.platform === 'win32' ? it.skip : it;

describe('contentRelPath', () => {
  let root: string;

  beforeEach(() => {
    root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), 'vg-content-rel-')));
    fs.mkdirSync(path.join(root, 'src'));
    fs.writeFileSync(path.join(root, 'src', 'accepted.ts'), 'x\n');
  });

  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  itPosix('keys a file reached through a linked parent directory on its physical path', () => {
    fs.symlinkSync('src', path.join(root, 'linked'));
    expect(contentRelPath(path.join(root, 'linked', 'accepted.ts'), root)).toBe('src/accepted.ts');
  });

  itPosix('keys a file whose own entry is a link on its own name, never on the target', () => {
    fs.symlinkSync('accepted.ts', path.join(root, 'src', 'new.ts'));
    expect(contentRelPath(path.join(root, 'src', 'new.ts'), root)).toBe('src/new.ts');
  });

  it('keys a plain file on its relative path', () => {
    expect(contentRelPath(path.join(root, 'src', 'accepted.ts'), root)).toBe('src/accepted.ts');
  });
});
