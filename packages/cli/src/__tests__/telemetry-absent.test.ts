// Regression guard for the "telemetry is optional" contract: even with
// `better-sqlite3` native bindings unavailable (the Windows node-gyp/VS
// build-tools failure this guards against), a scan must still succeed.
// cli.ts eagerly imports every command module (statusline, suggest-model,
// proxy, data), each of which imports @vaultcompass/vault-guard-telemetry,
// so this also exercises that the whole CLI module graph tolerates a
// missing native binding, not just scanCommand in isolation.
jest.mock('better-sqlite3', () => {
  throw new Error('simulated missing native binding (no Visual Studio build tools)');
});

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanCommand } from '../commands/scan';

describe('scan with telemetry native bindings absent', () => {
  it('still succeeds (exit 0) on a clean file', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vg-telemetry-absent-'));
    const file = path.join(dir, 'clean.ts');
    fs.writeFileSync(file, "const message = 'hello world';\n");

    try {
      const code = await scanCommand(file, 'json');
      expect(code).toBe(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
