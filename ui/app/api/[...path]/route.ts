import type { NextRequest } from 'next/server';

type RouteContext = { params: Promise<{ path: string[] }> };
const UPSTREAM_TIMEOUT_MS = 35_000;

async function proxy(request: NextRequest, context: RouteContext): Promise<Response> {
  const timeout = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
  try {
    const { path } = await context.params;
    const baseUrl = process.env.KHALIFA_API_URL || 'http://localhost:8080';
    const target = new URL(
      `${baseUrl.replace(/\/$/, '')}/${path.map(encodeURIComponent).join('/')}`
    );
    target.search = request.nextUrl.search;

    const headers = new Headers(request.headers);
    for (const name of ['connection', 'content-length', 'host', 'transfer-encoding']) {
      headers.delete(name);
    }

    const init: RequestInit & { duplex?: 'half' } = {
      method: request.method,
      headers,
      redirect: 'manual',
      signal: AbortSignal.any([request.signal, timeout]),
    };
    if (request.body) {
      init.body = request.body;
      init.duplex = 'half';
    }

    return await fetch(target, init);
  } catch (error) {
    console.error('API proxy request failed:', error);
    return Response.json(
      { message: timeout.aborted ? 'API request timed out' : 'API unavailable' },
      { status: timeout.aborted ? 504 : 502 }
    );
  }
}

export { proxy as DELETE, proxy as GET, proxy as PATCH, proxy as POST, proxy as PUT };
