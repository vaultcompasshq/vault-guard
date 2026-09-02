// Must be hoisted before imports so proxy.ts gets the mocked modules.
jest.mock('https');
jest.mock('better-sqlite3', () => {
  throw new Error('simulated missing native binding (no Visual Studio build tools)');
});

import * as https from 'https';
import { proxyCommand } from '../../commands/proxy';
import { setupUpstreamMock } from './proxy-test-helpers';

const mockHttps = https as unknown as { request: jest.Mock };

beforeEach(() => {
  mockHttps.request.mockReset();
});

// Regression guard: `proxy` used to be the one command that let a missing
// better-sqlite3 binding propagate as TelemetryUnavailableError (documented
// as intentional: "the primary telemetry writer... should fail loudly").
// Every telemetry entry point now degrades to a no-op store instead, so the
// proxy must start and serve traffic even though usage will not be recorded.
describe('proxy startup with telemetry native bindings absent', () => {
  it('starts and can be shut down without throwing', async () => {
    setupUpstreamMock(mockHttps);
    const handle = await proxyCommand({ listen: '127.0.0.1:0' });
    try {
      expect(handle.server.listening).toBe(true);
      expect(handle.store.isAvailable()).toBe(false);
    } finally {
      await handle.shutdown();
    }
  });

  it('prints exactly one telemetry-unavailable notice and drops the false usage-logging claim from the banner', async () => {
    setupUpstreamMock(mockHttps);
    const stderr = jest.spyOn(process.stderr, 'write').mockReturnValue(true);
    try {
      const handle = await proxyCommand({ listen: '127.0.0.1:0' });
      try {
        const written = stderr.mock.calls.map(c => String(c[0])).join('');

        // Banner must no longer claim usage is being logged when it is not.
        expect(written).not.toMatch(/log usage to/);

        // Exactly one unavailability notice, matching the MCP server's wording style.
        const notices = stderr.mock.calls.filter(c =>
          String(c[0]).includes('telemetry unavailable, usage will NOT be recorded'),
        );
        expect(notices).toHaveLength(1);
        // The reason itself (TelemetryUnavailableError's message) can be
        // multi-line, same as the MCP server's equivalent notice; what must
        // stay singular is the write call, not the line count of the reason.
        expect(String(notices[0][0])).toMatch(
          /^vault-guard proxy: telemetry unavailable, usage will NOT be recorded: [\s\S]+\n$/,
        );
      } finally {
        await handle.shutdown();
      }
    } finally {
      stderr.mockRestore();
    }
  });
});
