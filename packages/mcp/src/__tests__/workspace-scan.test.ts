import fs from 'fs';
import os from 'os';
import path from 'path';
import { SecretScanner } from '@vaultcompass/vault-guard-core';
import { scanWorkspaceDirectory } from '../workspace-scan';

describe('scanWorkspaceDirectory', () => {
  it('returns empty when no secrets in temp workspace', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-'));
    try {
      fs.writeFileSync(path.join(dir, 'readme.txt'), 'hello world\n', 'utf8');
      const scanner = new SecretScanner();
      const { results, filesScanned, bytesScanned } = await scanWorkspaceDirectory(dir, scanner);
      expect(results).toEqual([]);
      expect(filesScanned).toBe(1);
      expect(bytesScanned).toBeGreaterThan(0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
