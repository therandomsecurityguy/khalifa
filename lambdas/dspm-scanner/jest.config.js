module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  rootDir: '.',
  testMatch: ['**/*.test.ts'],
  modulePathIgnorePatterns: ['<rootDir>/dist/', '<rootDir>/node_modules/'],
};