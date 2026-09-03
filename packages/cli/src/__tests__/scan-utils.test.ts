import fs from 'fs';
import os from 'os';
import path from 'path';
import { resolveScanRoot } from '../utils/scan-utils';

describe('resolveScanRoot', () => {
  let cwd: string;
  let inTreeTarget: string;
  let outsideTarget: string;

  beforeAll(() => {
    cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-resolve-root-'));
    inTreeTarget = path.join(cwd, 'a');
    fs.mkdirSync(inTreeTarget);
    outsideTarget = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-guard-resolve-root-outside-'));
  });

  afterAll(() => {
    fs.rmSync(cwd, { recursive: true, force: true });
    fs.rmSync(outsideTarget, { recursive: true, force: true });
  });

  it('returns cwd for an in-tree absolute target, not the target itself', () => {
    // Regression: an absolute target inside cwd used to become the SARIF
    // root itself, which narrows %SRCROOT% to a subdirectory. GitHub Code
    // Scanning resolves %SRCROOT% from its own knowledge of the checkout
    // (== cwd), so a uri relative to a narrower root ends up naming a
    // different file.
    expect(resolveScanRoot([inTreeTarget], cwd)).toBe(cwd);
  });

  it('returns cwd when the target equals cwd', () => {
    expect(resolveScanRoot([cwd], cwd)).toBe(cwd);
  });

  it('returns the target when it is genuinely outside cwd', () => {
    expect(resolveScanRoot([outsideTarget], cwd)).toBe(outsideTarget);
  });
});
