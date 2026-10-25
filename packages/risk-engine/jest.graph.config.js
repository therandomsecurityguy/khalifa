// Queries against a local Gremlin Server; run only by the graph-queries CI job.
const project = (displayName, rootDir) => ({
  displayName,
  rootDir,
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/**/*.graph.test.ts'],
  modulePathIgnorePatterns: ['<rootDir>/dist/', '<rootDir>/node_modules/'],
});

module.exports = {
  projects: [
    project('graph-queries', __dirname),
    project('graph-evaluator', `${__dirname}/../../lambdas/policy-evaluator`),
    project('graph-writer', `${__dirname}/../../lambdas/graph-writer`),
  ],
};
