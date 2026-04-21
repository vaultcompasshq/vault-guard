module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  moduleNameMapper: {
    '^@vaultcompass/vault-guard-core$': '<rootDir>/../core/src/index.ts',
  },
};
