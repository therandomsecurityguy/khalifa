import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fetchPublishable, parsePublishableResponse } from './fetch-publishable';

type Handler = (request: IncomingMessage, response: ServerResponse) => void;

async function withServer(
  handler: Handler,
  test: (apiUrl: string, requests: IncomingMessage[]) => Promise<void>
): Promise<void> {
  const requests: IncomingMessage[] = [];
  const server = createServer((request, response) => {
    requests.push(request);
    handler(request, response);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address() as AddressInfo;
    await test(`http://127.0.0.1:${port}`, requests);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  }
}

function json(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

const okPayload = {
  status: 'OK',
  generatedAt: '2026-10-16T00:00:00.000Z',
  maxAgeHours: 24,
  requirements: [
    { requirement: '1.5', title: 'Root has MFA', section: '1. Identity', status: 'PASS' },
  ],
};

describe('fetchPublishable', () => {
  it('sends the Access service token headers and returns the payload', async () => {
    await withServer(
      (_request, response) => json(response, 200, okPayload),
      async (apiUrl, requests) => {
        const result = await fetchPublishable({
          apiUrl,
          clientId: 'sync.access',
          clientSecret: 'super-secret',
        });
        expect(result.status).toBe('OK');
        expect(result.requirements).toHaveLength(1);
        expect(requests[0].headers['cf-access-client-id']).toBe('sync.access');
        expect(requests[0].headers['cf-access-client-secret']).toBe('super-secret');
        expect(requests[0].url).toBe('/compliance/reconciliation/publishable');
      }
    );
  });

  it('fails on non-2xx responses', async () => {
    await withServer(
      (_request, response) => json(response, 401, { error: 'unauthorized' }),
      async (apiUrl) => {
        await expect(
          fetchPublishable({ apiUrl, clientId: 'a', clientSecret: 'b' })
        ).rejects.toThrow('HTTP 401');
      }
    );
  });

  it('fails on invalid JSON', async () => {
    await withServer(
      (_request, response) => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end('not-json');
      },
      async (apiUrl) => {
        await expect(
          fetchPublishable({ apiUrl, clientId: 'a', clientSecret: 'b' })
        ).rejects.toThrow();
      }
    );
  });

  it('times out', async () => {
    await withServer(
      (_request, response) => {
        setTimeout(() => json(response, 200, okPayload), 500);
      },
      async (apiUrl) => {
        await expect(
          fetchPublishable({ apiUrl, clientId: 'a', clientSecret: 'b', timeoutMs: 50 })
        ).rejects.toThrow('timed out after 50ms');
      }
    );
  });

  it('requires its configuration', async () => {
    await expect(
      fetchPublishable({ apiUrl: '', clientId: 'a', clientSecret: 'b' })
    ).rejects.toThrow('KHALIFA_API_URL is required');
    await expect(
      fetchPublishable({ apiUrl: 'http://x', clientId: '', clientSecret: 'b' })
    ).rejects.toThrow('CF_ACCESS_CLIENT_ID is required');
    await expect(
      fetchPublishable({ apiUrl: 'http://x', clientId: 'a', clientSecret: ' ' })
    ).rejects.toThrow('CF_ACCESS_CLIENT_SECRET is required');
  });
});

describe('parsePublishableResponse', () => {
  it('re-projects exactly the publishable fields', () => {
    const result = parsePublishableResponse({
      ...okPayload,
      requirements: [
        {
          ...okPayload.requirements[0],
          accountId: '111122223333',
          evidence: { arn: 'arn:aws:s3:::bucket' },
        },
      ],
      extra: 'ignored',
    });
    expect(result.requirements[0]).toEqual({
      requirement: '1.5',
      title: 'Root has MFA',
      section: '1. Identity',
      status: 'PASS',
    });
  });

  it('rejects malformed payloads', () => {
    expect(() => parsePublishableResponse(null)).toThrow('non-object');
    expect(() => parsePublishableResponse({ status: 'UNKNOWN', requirements: [] })).toThrow(
      'unknown status'
    );
    expect(() => parsePublishableResponse({ status: 'OK', requirements: 'nope' })).toThrow(
      'no requirements array'
    );
    expect(() =>
      parsePublishableResponse({
        status: 'OK',
        requirements: [{ requirement: '1.5', title: '', section: 's', status: 'PASS' }],
      })
    ).toThrow('missing title');
    expect(() =>
      parsePublishableResponse({
        status: 'OK',
        requirements: [{ requirement: '1.5', title: 't', section: 's', status: 'MANUAL' }],
      })
    ).toThrow('unknown status');
  });

  it('parses the published staleness window and rejects invalid ones', () => {
    expect(parsePublishableResponse(okPayload).maxAgeHours).toBe(24);
    expect(
      parsePublishableResponse({ status: 'OK', requirements: [] }).maxAgeHours
    ).toBeUndefined();
    expect(() =>
      parsePublishableResponse({ status: 'OK', requirements: [], maxAgeHours: 0 })
    ).toThrow('invalid maxAgeHours');
    expect(() =>
      parsePublishableResponse({ status: 'OK', requirements: [], maxAgeHours: 'soon' })
    ).toThrow('invalid maxAgeHours');
  });

  it('accepts STALE and MISSING records with no requirements', () => {
    expect(parsePublishableResponse({ status: 'STALE', requirements: [] })).toEqual({
      status: 'STALE',
      generatedAt: null,
      requirements: [],
      mappedFrameworks: [],
    });
    expect(parsePublishableResponse({ status: 'MISSING', requirements: [] })).toEqual({
      status: 'MISSING',
      generatedAt: null,
      requirements: [],
      mappedFrameworks: [],
    });
  });

  it('parses mapped-framework requirements and rejects unknown frameworks', () => {
    const parsed = parsePublishableResponse({
      status: 'OK',
      requirements: [],
      mappedFrameworks: [
        {
          framework: 'SOC2',
          requirement: 'CC9.1',
          title: 'Availability',
          section: 'Availability',
          status: 'PASS',
          accountId: '111122223333',
        },
      ],
    });
    expect(parsed.mappedFrameworks).toEqual([
      {
        framework: 'SOC2',
        requirement: 'CC9.1',
        title: 'Availability',
        section: 'Availability',
        status: 'PASS',
      },
    ]);

    expect(() =>
      parsePublishableResponse({
        status: 'OK',
        requirements: [],
        mappedFrameworks: [
          { framework: 'PCI_DSS', requirement: 'x', title: 't', section: 's', status: 'PASS' },
        ],
      })
    ).toThrow('unknown framework');
    expect(() =>
      parsePublishableResponse({ status: 'OK', requirements: [], mappedFrameworks: 'nope' })
    ).toThrow('malformed mappedFrameworks');
  });
});
