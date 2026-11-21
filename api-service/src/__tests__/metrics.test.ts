import { EventEmitter } from 'events';
import type { NextFunction, Request, Response } from 'express';
import { metricsMiddleware, renderMetrics, resetMetricsForTests } from '../observability/metrics';

describe('Prometheus metrics', () => {
  beforeEach(() => resetMetricsForTests());

  it('records HTTP metrics using the bounded route template label', () => {
    const req = {
      method: 'GET',
      route: { path: '/resources/*arn' },
      baseUrl: '',
      originalUrl: '/resources/arn:aws:iam::123456789012:role/team/Admin',
    } as unknown as Request;
    const res = new EventEmitter() as unknown as Response;
    res.statusCode = 200;
    const next = jest.fn() as NextFunction;

    metricsMiddleware(req, res, next);
    (res as unknown as EventEmitter).emit('finish');

    const metrics = renderMetrics();
    expect(next).toHaveBeenCalledTimes(1);
    expect(metrics).toContain(
      'khalifa_api_http_requests_total{method="GET",route="/resources/*arn",status_code="200"} 1'
    );
    expect(metrics).not.toContain('123456789012');
  });

  it('reports the build identity, with local fallbacks', () => {
    const previous = { version: process.env.KHALIFA_VERSION, sha: process.env.KHALIFA_SHA };
    delete process.env.KHALIFA_VERSION;
    delete process.env.KHALIFA_SHA;
    expect(renderMetrics()).toContain('khalifa_build_info{version="dev",sha=""} 1');

    process.env.KHALIFA_VERSION = '1.11.0';
    process.env.KHALIFA_SHA = 'abc123';
    expect(renderMetrics()).toContain('khalifa_build_info{version="1.11.0",sha="abc123"} 1');

    if (previous.version === undefined) delete process.env.KHALIFA_VERSION;
    else process.env.KHALIFA_VERSION = previous.version;
    if (previous.sha === undefined) delete process.env.KHALIFA_SHA;
    else process.env.KHALIFA_SHA = previous.sha;
  });
});
