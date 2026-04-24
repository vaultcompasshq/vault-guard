import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { clearGitignoreCache, getFilesToScan } from '../utils/file-utils';

function tmp(name: string): string {
  return path.join(os.tmpdir(), `vg-ignore-${name}-${Date.now()}-${Math.random().toString(16).slice(2)}`);
}

describe('getFilesToScan + ignore package', () => {
  afterEach(() => {
    clearGitignoreCache();
  });

  it('respects root .gitignore patterns', () => {
    const root = tmp('root');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(path.join(root, '.gitignore'), '*.secret\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'ok.ts'), 'export const x = 1\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'nope.secret'), 'data\n', 'utf-8');

    const names = getFilesToScan(root).map(f => path.basename(f));
    expect(names).toContain('ok.ts');
    expect(names).not.toContain('nope.secret');
  });

  it('applies negation patterns', () => {
    const root = tmp('neg');
    fs.mkdirSync(root, { recursive: true });
    fs.writeFileSync(
      path.join(root, '.gitignore'),
      ['*.secret', '!keep.secret', ''].join('\n'),
      'utf-8',
    );
    fs.writeFileSync(path.join(root, 'drop.secret'), 'x\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'keep.secret'), 'y\n', 'utf-8');

    const files = getFilesToScan(root).map(f => path.basename(f)).sort();
    expect(files).toContain('keep.secret');
    expect(files).not.toContain('drop.secret');
  });

  it('loads nested .gitignore relative to git root', () => {
    const root = tmp('nested');
    fs.mkdirSync(path.join(root, 'pkg', 'src'), { recursive: true });
    fs.mkdirSync(path.join(root, '.git'), { recursive: true });
    fs.writeFileSync(path.join(root, '.gitignore'), '*.log\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', '.gitignore'), '*.tmp\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', 'src', 'a.ts'), 'ok\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'pkg', 'src', 'x.tmp'), 'no\n', 'utf-8');
    fs.writeFileSync(path.join(root, 'noise.log'), 'no\n', 'utf-8');

    const files = getFilesToScan(path.join(root, 'pkg', 'src')).map(f => path.basename(f)).sort();
    expect(files).toEqual(['a.ts']);
  });

  it('invalidates cache when .gitignore mtime changes', () => {
    const root = tmp('mtime');
    fs.mkdirSync(root, { recursive: true });
    const gi = path.join(root, '.gitignore');
    fs.writeFileSync(gi, '', 'utf-8');
    fs.writeFileSync(path.join(root, 'f.secret'), 'x\n', 'utf-8');

    let files = getFilesToScan(root).map(f => path.basename(f));
    expect(files).toContain('f.secret');

    fs.writeFileSync(gi, '*.secret\n', 'utf-8');
    files = getFilesToScan(root).map(f => path.basename(f));
    expect(files).not.toContain('f.secret');
  });
});
