import fs from 'fs';
import path from 'path';
import { createHash } from 'crypto';
import { classifyPreCommitHook, isReleasedHookScript, isReleasedHookStanza } from '../pre-commit-hook';

interface ReleasedScript {
  manager: 'native' | 'husky';
  versions: string;
  sha256: string;
  lines: string[];
}

// The whole scripts released versions wrote, as rendered by install-hook from
// the published packages (1.0.0, 1.3.0, 1.4.0, 1.4.4, 1.4.6, 1.9.0 and 1.12.0,
// native and husky). Read from a checked-in fixture so that dropping any
// released hash from the ownership table turns this file red.
const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'released-hook-scripts.json'), 'utf8'),
) as { scripts: ReleasedScript[] };

// The hygiene check allows no em dash in a tracked file; the fixture spells it as a token.
const EM_DASH = String.fromCharCode(0x2014);
const scripts = fixture.scripts.map(s => ({ ...s, text: s.lines.join('\n').replace(/\{EM_DASH\}/g, EM_DASH) }));

describe('hook scripts released versions wrote', () => {
  it('has every released native and husky template', () => {
    expect(scripts.map(s => `${s.manager} ${s.versions}`)).toEqual([
      'native 1.0.0 to 1.3.0',
      'native 1.4.0 to 1.4.5',
      'native 1.4.6 to 1.8.1',
      'native 1.9.0 to 1.13.1',
      'husky 1.0.0 to 1.4.3',
      'husky 1.4.4 to 1.4.5',
      'husky 1.4.6 to 1.13.1',
    ]);
  });

  it.each(scripts.map(s => [`${s.manager} ${s.versions}`, s] as const))(
    'the %s fixture is the published bytes',
    (_label, s) => {
      expect(createHash('sha256').update(s.text, 'utf8').digest('hex')).toBe(s.sha256);
    },
  );

  it.each(scripts.map(s => [`${s.manager} ${s.versions}`, s] as const))(
    'the %s script is in the released table and classifies as owned',
    (_label, s) => {
      expect(isReleasedHookScript(s.text)).toBe(true);
      expect(classifyPreCommitHook(s.text)).toBe('owned');
    },
  );

  it.each(scripts.map(s => [`${s.manager} ${s.versions}`, s] as const))(
    'the %s script stays owned with CRLF line ends, no final newline, or extra trailing blank lines and spaces',
    (_label, s) => {
      for (const variant of [
        s.text.replace(/\n/g, '\r\n'),
        s.text.replace(/\n$/, ''),
        `${s.text}\n`,
        `${s.text}\n\n  \n`,
        `${s.text.replace(/\n$/, '')}   \n`,
      ]) {
        expect(classifyPreCommitHook(variant)).toBe('owned');
      }
    },
  );

  it.each(scripts.map(s => [`${s.manager} ${s.versions}`, s] as const))(
    'the %s script with a line added is not owned',
    (_label, s) => {
      expect(classifyPreCommitHook(`${s.text}npm run lint-staged\n`)).not.toBe('owned');
    },
  );
});

describe('hook stanzas released versions merged', () => {
  const stanzas = (
    JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'released-hook-scripts.json'), 'utf8')) as {
      stanzas: Array<{ versions: string; sha256: string; lines: string[] }>;
    }
  ).stanzas.map(s => ({ ...s, text: s.lines.join('\n') }));

  it('has every released stanza', () => {
    expect(stanzas.map(s => s.versions)).toEqual(['1.13.1 to 1.13.2']);
  });

  it.each(stanzas.map(s => [s.versions, s] as const))('the %s stanza fixture is the released bytes', (_label, s) => {
    expect(createHash('sha256').update(s.text, 'utf8').digest('hex')).toBe(s.sha256);
  });

  it.each(stanzas.map(s => [s.versions, s] as const))(
    'the %s stanza is in the released stanza table, also with CRLF line ends or trailing spaces',
    (_label, s) => {
      expect(isReleasedHookStanza(s.text)).toBe(true);
      expect(isReleasedHookStanza(s.text.replace(/\n/g, '\r\n'))).toBe(true);
      expect(isReleasedHookStanza(s.text.replace(/\n/g, '  \n'))).toBe(true);
    },
  );

  it.each(stanzas.map(s => [s.versions, s] as const))(
    'the %s stanza with a line added inside its markers, or a line changed, is not a released stanza',
    (_label, s) => {
      expect(isReleasedHookStanza(s.text.replace('# --- end vault-guard ---', 'echo keep-me\n# --- end vault-guard ---'))).toBe(
        false,
      );
      expect(isReleasedHookStanza(s.text.replace('vault_guard_status=0', 'vault_guard_status=0; export X=1'))).toBe(false);
    },
  );
});
