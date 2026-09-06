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
      const { results, filesScanned, bytesScanned, overBudget } = await scanWorkspaceDirectory(
        dir,
        scanner,
      );
      expect(results).toEqual([]);
      expect(filesScanned).toBe(1);
      expect(bytesScanned).toBeGreaterThan(0);
      expect(overBudget).toEqual([]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  /**
   * The agent-driven MCP surface gets the same post-hoc scan budget the CLI has.
   * It cannot preempt a synchronous runaway scan; it reports that the file's
   * result is not trusted so an agent is not handed a silent "clean".
   */
  it('reports a file whose scan exceeds the budget', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vgmcp-budget-'));
    try {
      fs.writeFileSync(path.join(dir, 'slow.txt'), 'nothing to see\n', 'utf8');
      const busy = (ms: number): void => {
        const end = Date.now() + ms;
        while (Date.now() < end) { /* deliberately synchronous */ }
      };
      const slowScanner = {
        scanContent: () => { busy(60); return []; },
        scan: () => { busy(60); return []; },
      } as unknown as SecretScanner;

      const { overBudget } = await scanWorkspaceDirectory(dir, slowScanner, 10, [], 10);

      expect(overBudget).toHaveLength(1);
      expect(overBudget[0].file).toContain('slow.txt');
      expect(overBudget[0].budget_ms).toBe(10);
      expect(overBudget[0].elapsed_ms).toBeGreaterThanOrEqual(10);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
