module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/types.ts'
  ],
  coverageThreshold: {
    global: {
      branches: 45,
      functions: 54,
      lines: 53,
      statements: 54
    }
  }
};
