module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  maxWorkers: 1,
  moduleNameMapper: {
    '^@vaultcompass/vault-guard-core$': '<rootDir>/../core/src/index.ts',
    '^@vaultcompass/vault-guard-telemetry$': '<rootDir>/../telemetry/src/index.ts',
  },
  // `server.ts` is heavy SDK wiring; Istanbul instrumentation has OOM/SIGTERM'd
  // workers in CI. Only ratchet coverage on the unit-tested scan helper.
  collectCoverageFrom: ['src/workspace-scan.ts'],
  coverageThreshold: {
    global: {
      // `workspace-scan` has a single catch branch; 25% is the measured floor.
      branches: 25,
      functions: 100,
      lines: 93,
      statements: 84,
    },
  },
};
