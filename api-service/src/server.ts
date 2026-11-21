import app from './app';
import { closeApiNeptuneClient } from './services/api-dependencies';
import { closeReadinessDependencies } from './services/readiness';
import { startDomainMetrics, stopDomainMetrics } from './observability/domain-metrics';

const port = Number(process.env.PORT || 8080);

if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error(`Invalid PORT: ${process.env.PORT}`);
}

// Refreshes the domain gauges on an interval; scrapes read the cache.
startDomainMetrics();

const server = app.listen(port, () => {
  console.log(`API service listening on port ${port}`);
});

let shuttingDown = false;

function shutdown(signal: NodeJS.Signals): void {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`Received ${signal}, shutting down`);

  const timeout = setTimeout(() => {
    console.error('Graceful shutdown timed out');
    process.exit(1);
  }, 10_000);
  timeout.unref();

  server.close(async (error) => {
    clearTimeout(timeout);
    if (error) {
      console.error('Server shutdown failed:', error);
      process.exitCode = 1;
    }
    try {
      await closeApiNeptuneClient();
      closeReadinessDependencies();
      stopDomainMetrics();
    } catch (closeError) {
      console.error('Dependency shutdown failed:', closeError);
      process.exitCode = 1;
    }
  });
  server.closeIdleConnections();
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
