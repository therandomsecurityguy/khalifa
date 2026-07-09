module.exports = {
  globalSetup: '<rootDir>/jest.setup.js',
  projects: [
    {
      displayName: 'risk-engine',
      rootDir: '<rootDir>/packages/risk-engine',
      preset: 'ts-jest',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/**/*.test.ts'],
    },
    {
      displayName: 'integrations',
      rootDir: '<rootDir>/packages/integrations',
      preset: 'ts-jest',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/**/*.test.ts'],
    },
    {
      displayName: 'api-service',
      rootDir: '<rootDir>/api-service',
      preset: 'ts-jest',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/**/*.test.ts'],
    },
    {
      displayName: 'collector',
      rootDir: '<rootDir>/lambdas/collector',
      preset: 'ts-jest',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/**/*.test.ts'],
      modulePathIgnorePatterns: ['<rootDir>/dist/', '<rootDir>/node_modules/'],
    },
    {
      displayName: 'dspm-scanner',
      rootDir: '<rootDir>/lambdas/dspm-scanner',
      preset: 'ts-jest',
      testEnvironment: 'node',
      testMatch: ['<rootDir>/src/**/*.test.ts'],
      modulePathIgnorePatterns: ['<rootDir>/dist/', '<rootDir>/node_modules/'],
    },
  ],
};