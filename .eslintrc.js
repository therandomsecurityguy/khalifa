const path = require('path');

module.exports = {
  root: true,
  env: {
    es2021: true,
    node: true,
    jest: true,
  },
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:prettier/recommended',
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2021,
    sourceType: 'module',
    project: [
      './tsconfig.json',
      './api-service/tsconfig.json',
      './cdk/tsconfig.json',
      './ui/tsconfig.json',
      './packages/risk-engine/tsconfig.json',
      './lambdas/*/tsconfig.json',
    ],
    tsconfigRootDir: __dirname,
  },
  plugins: ['@typescript-eslint', 'prettier'],
  rules: {
    'prettier/prettier': 'error',
    '@typescript-eslint/no-explicit-any': 'off',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    '@typescript-eslint/no-empty-interface': 'off',
    '@typescript-eslint/consistent-type-imports': 'off',
    'no-console': ['warn', { allow: ['warn', 'error', 'log'] }],
    'no-empty': 'off',
    'no-async-promise-executor': 'off',
    'no-constant-condition': 'off',
  },
  ignorePatterns: ['dist/', 'node_modules/', '.next/', '*.js', '*.d.ts'],
  overrides: [
    {
      files: ['*.config.js', '.eslintrc.js', 'prettier.config.js'],
      env: { node: true },
    },
  ],
};