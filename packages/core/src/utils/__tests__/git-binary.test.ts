import { GitBinaryError, isInsideDir, resolveGitBinary } from '../git-binary';

/** A fake filesystem: only these absolute paths are regular files. */
const world = (platform: NodeJS.Platform, env: NodeJS.ProcessEnv, files: string[]) => ({
  platform,
  env,
  isFile: (p: string) => files.includes(p),
});

describe('resolveGitBinary', () => {
  it('skips empty and relative PATH entries, which mean "here"', () => {
    const w = world('linux', { PATH: ':bin:./bin:/usr/local/bin:/usr/bin' }, ['/usr/bin/git', 'bin/git', './bin/git']);
    expect(resolveGitBinary(w)).toBe('/usr/bin/git');
  });

  it('returns the first absolute entry that holds a git', () => {
    const w = world('linux', { PATH: '/a:/b:/c' }, ['/b/git', '/c/git']);
    expect(resolveGitBinary(w)).toBe('/b/git');
  });

  it('throws when there is none', () => {
    expect(() => resolveGitBinary(world('linux', { PATH: '/a:relative' }, ['relative/git']))).toThrow(GitBinaryError);
    expect(() => resolveGitBinary(world('linux', {}, []))).toThrow(GitBinaryError);
  });

  it('win32: honours PATHEXT for .exe and .com only, never a script', () => {
    const w = world('win32', { Path: 'C:\\Git\\cmd;C:\\Git\\bin', PATHEXT: '.COM;.EXE;.BAT;.CMD' }, [
      'C:\\Git\\cmd\\git.cmd',
      'C:\\Git\\bin\\git.exe',
    ]);
    expect(resolveGitBinary(w)).toBe('C:\\Git\\bin\\git.exe');
    expect(() => resolveGitBinary(world('win32', { PATH: 'C:\\Git\\cmd', PATHEXT: '.CMD;.BAT' }, ['C:\\Git\\cmd\\git.cmd']))).toThrow(
      GitBinaryError,
    );
  });

  it('win32: skips a relative entry and an unquoted empty one', () => {
    const w = world('win32', { PATH: ';.;bin;"C:\\Real"', PATHEXT: '.EXE' }, ['.\\git.exe', 'bin\\git.exe', 'C:\\Real\\git.exe']);
    expect(resolveGitBinary(w)).toBe('C:\\Real\\git.exe');
  });
});

describe('resolveGitBinary: what a shell would skip', () => {
  it('posix: a git without the execute bit is skipped', () => {
    const w = {
      ...world('linux', { PATH: '/a:/b' }, ['/a/git', '/b/git']),
      isExecutable: (p: string) => p !== '/a/git',
    };
    expect(resolveGitBinary(w)).toBe('/b/git');
    expect(() => resolveGitBinary({ ...w, isExecutable: () => false })).toThrow(GitBinaryError);
  });

  it('win32: a drive-relative rooted entry (\\Tools\\Git) is skipped; a drive letter and a UNC path are kept', () => {
    const files = ['\\Tools\\Git\\git.exe', 'C:\\Git\\git.exe', '\\\\srv\\share\\git.exe'];
    expect(resolveGitBinary(world('win32', { PATH: '\\Tools\\Git;C:\\Git', PATHEXT: '.EXE' }, files))).toBe('C:\\Git\\git.exe');
    expect(resolveGitBinary(world('win32', { PATH: '\\Tools\\Git;\\\\srv\\share', PATHEXT: '.EXE' }, files))).toBe(
      '\\\\srv\\share\\git.exe',
    );
    expect(() => resolveGitBinary(world('win32', { PATH: '\\Tools\\Git', PATHEXT: '.EXE' }, files))).toThrow(GitBinaryError);
  });
});

describe('isInsideDir', () => {
  it('is true for the directory itself and anything under it, false for a sibling with the same prefix', () => {
    expect(isInsideDir('/r/bin/git', '/r')).toBe(true);
    expect(isInsideDir('/r', '/r')).toBe(true);
    expect(isInsideDir('/rr/git', '/r')).toBe(false);
    expect(isInsideDir('/usr/bin/git', '/r')).toBe(false);
  });
});
