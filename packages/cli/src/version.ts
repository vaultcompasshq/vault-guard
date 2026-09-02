import * as fs from 'fs';
import * as path from 'path';

/**
 * Read the CLI's own package.json `version` at runtime.
 *
 * Resolves relative to *this module's own* compiled location, not the
 * caller's, which is exactly why this lives in its own file rather than
 * being duplicated per call site: `__dirname` here is always
 * `<package root>/dist` once built (this file compiles to
 * `dist/version.js`, directly under `dist/`, same as `dist/cli.js`) and
 * always `<package root>/src` under ts-jest, so `path.join(__dirname, '..',
 * 'package.json')` lands on `<package root>/package.json` either way,
 * regardless of how deep the *caller* (e.g. `src/init/templates.ts`,
 * compiled to `dist/init/templates.js`) sits.
 *
 * A static `import pkg from '../../package.json'` is not viable from
 * `templates.ts`: that path resolves outside this package's
 * `rootDir` (`./src`), which `tsc` rejects.
 */
export function readCliVersion(): string {
  const pkgPath = path.join(__dirname, '..', 'package.json');
  const raw = fs.readFileSync(pkgPath, 'utf-8');
  return (JSON.parse(raw) as { version: string }).version;
}
