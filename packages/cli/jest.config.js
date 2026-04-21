module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
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
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};
