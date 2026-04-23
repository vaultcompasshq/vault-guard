module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  // Integration proxy tests start real HTTP servers on random ports.
  // Parallel workers cause intermittent ECONNRESET because two suites can
  // race to bind/use the same OS-recycled port. Single worker eliminates
  // the hazard with negligible cost (proxy tests dominate the runtime anyway).
  maxWorkers: 1,
  // Resolve workspace package before core `dist/` exists (CI / local `pnpm test`)
  moduleNameMapper: {
    '^@vaultcompass/vault-guard-core$': '<rootDir>/../core/src/index.ts',
    '^@vaultcompass/vault-guard-telemetry$': '<rootDir>/../telemetry/src/index.ts',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/types.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 27,
      functions: 36,
      lines: 39,
      statements: 38
    }
  }
};
