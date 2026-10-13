import * as fs from 'fs';

import { scanCommand } from '../../commands/scan';
import * as fx from './git-fixture';

/**
 * F15: the acceptance table of design 2026-10-12, section 5.2. The same
 * production-shaped values under each name, default fail_on.
 */

const DSN = ['postgres://', 'appuser:Xk9mPq2vLw7nRt4s', '@pg-primary.svc.cluster-a.net:5432/orders'].join('');
const JWT = [
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
  'eyJzdWIiOiJ1c3ItODgyMSIsInJvbGUiOiJvcHMifQ',
  'Qm9vZ2llV29vZ2llQmFuZ2xlczEyMzQ1Njc4OTBhYmM',
].join('.');
const PEM_JSON = JSON.stringify({ private_key: fx.pemKey().replace('RSA ', '') });
const PASSWORD = 'password = "Vq7mK2pLx9wRtB4n"';
const LABEL = 'tfa_secret: Zwei-Faktor-Authentifizierung';

const ROWS: Array<{ file: string; content: string; severity: string; code: number }> = [
  { file: 'loc/db.ts', content: `const url = "${DSN}";\n`, severity: 'critical', code: 1 },
  { file: 'loc/database.ts', content: `const url = "${DSN}";\n`, severity: 'critical', code: 1 },
  { file: 'loc/db.js', content: `const url = "${DSN}";\n`, severity: 'critical', code: 1 },
  { file: 'loc/database.js', content: `const url = "${DSN}";\n`, severity: 'critical', code: 1 },
  { file: 'loc/db.yml', content: `url: ${DSN}\n`, severity: 'critical', code: 1 },
  { file: 'loc/database.yml', content: `url: ${DSN}\n`, severity: 'critical', code: 1 },
  { file: 'loc/ci.yml', content: `token: ${JWT}\n`, severity: 'high', code: 1 },
  { file: 'loc/auth.yml', content: `token: ${JWT}\n`, severity: 'high', code: 1 },
  { file: 'loc/sa.json', content: `${PEM_JSON}\n`, severity: 'critical', code: 1 },
  { file: 'loc/key.json', content: `${PEM_JSON}\n`, severity: 'critical', code: 1 },
  { file: 'loc/pg.js', content: `const ${PASSWORD};\n`, severity: 'high', code: 1 },
  { file: 'loc/pgconf.js', content: `const ${PASSWORD};\n`, severity: 'high', code: 1 },
  { file: 'src/locales/de-DE.yaml', content: `${LABEL}\n`, severity: 'low', code: 0 },
  { file: 'src/locales/de.json', content: `{"url": "${DSN}"}\n`, severity: 'critical', code: 1 },
  { file: 'config/locales/en.yml', content: `token: ${JWT}\n`, severity: 'high', code: 1 },
  { file: 'i18n/en.json', content: `${PEM_JSON}\n`, severity: 'critical', code: 1 },
  { file: 'src/en.json', content: `${LABEL}\n`, severity: 'high', code: 1 },
];

describe('F15: the locale rule acceptance table', () => {
  const originalCwd = process.cwd();
  let dir: string;

  beforeAll(() => {
    dir = fx.tmpDir('vg-locale-');
    fx.initRepo(dir);
    for (const r of ROWS) fx.write(dir, r.file, r.content);
    fx.commitAll(dir, 'base');
  });

  afterAll(() => {
    process.chdir(originalCwd);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it.each(ROWS)('F15: $file is $severity, exit $code', async row => {
    process.chdir(dir);
    const r = await fx.capture(() => scanCommand(row.file, 'json', false));
    const doc = fx.parse(r.stdout);
    const severities = doc.results.flatMap(x => x.matches.map(m => m.severity));
    expect({ file: row.file, severities, code: r.code }).toEqual({
      file: row.file,
      severities: [row.severity],
      code: row.code,
    });
  });
});
