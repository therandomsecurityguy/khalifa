import type { NextFunction, Request, Response } from 'express';

interface RequestMetric {
  count: number;
  duration: number;
}

const requests = new Map<string, RequestMetric>();
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

export function metricsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const startedAt = process.hrtime.bigint();
  res.once('finish', () => {
    const key = JSON.stringify([
      METHODS.has(req.method) ? req.method : 'OTHER',
      routeName(req),
      String(res.statusCode),
    ]);
    const metric = requests.get(key) || { count: 0, duration: 0 };
    metric.count += 1;
    metric.duration += Number(process.hrtime.bigint() - startedAt) / 1_000_000_000;
    requests.set(key, metric);
  });
  next();
}

export function renderMetrics(): string {
  const lines = [
    '# HELP khalifa_api_http_requests_total HTTP requests handled by the API.',
    '# TYPE khalifa_api_http_requests_total counter',
    '# HELP khalifa_api_http_request_duration_seconds HTTP request duration in seconds.',
    '# TYPE khalifa_api_http_request_duration_seconds summary',
  ];

  for (const [key, metric] of requests) {
    const [method, route, status] = JSON.parse(key) as string[];
    const labels = formatLabels({ method, route, status_code: status });
    lines.push(
      `khalifa_api_http_requests_total${labels} ${metric.count}`,
      `khalifa_api_http_request_duration_seconds_sum${labels} ${metric.duration}`,
      `khalifa_api_http_request_duration_seconds_count${labels} ${metric.count}`
    );
  }

  return `${lines.join('\n')}\n`;
}

export function resetMetricsForTests(): void {
  requests.clear();
}

function routeName(req: Request): string {
  const path = Array.isArray(req.route?.path) ? req.route.path[0] : req.route?.path;
  return typeof path === 'string' ? `${req.baseUrl || ''}${path}` : 'unmatched';
}

function formatLabels(values: Record<string, string>): string {
  return `{${Object.entries(values)
    .map(
      ([key, value]) =>
        `${key}="${value.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"')}"`
    )
    .join(',')}}`;
}
