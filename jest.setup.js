const { execSync } = require('child_process');

module.exports = async () => {
  try {
    execSync('npx tsc -b packages/integrations', { stdio: 'inherit' });
    execSync('npx tsc -b packages/risk-engine', { stdio: 'inherit' });
  } catch (e) {
    console.error('Failed to build packages before tests:', e.message);
    throw e;
  }
};