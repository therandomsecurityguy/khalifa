const path = require('path');

module.exports = {
  output: 'standalone',
  outputFileTracingRoot: path.join(__dirname, '..'),
  turbopack: {
    root: path.join(__dirname, '..'),
  },
  // Keep the build-time advisory check pinned to the security policy: an
  // affected stable Next.js version fails the build instead of only warning.
  experimental: {
    agentUpgrade: 'security',
  },
};
