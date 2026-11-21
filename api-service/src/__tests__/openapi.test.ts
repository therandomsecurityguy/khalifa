import app from '../app';
import openapi from '../openapi.json';

type Item = Record<string, { security?: unknown[] }>;

const HTTP_METHODS = new Set(['get', 'post']);

// Express path syntax -> OpenAPI path template: `:id` and `*arn` both become
// `{id}` / `{arn}`.
function oasPath(expressPath: string): string {
  return expressPath.replace(/:([A-Za-z0-9_]+)/g, '{$1}').replace(/\*([A-Za-z0-9_]+)/g, '{$1}');
}

const stack = (app as unknown as { router: { stack: any[] } }).router.stack;

function registeredOperations(): Set<string> {
  const operations = new Set<string>();
  for (const layer of stack) {
    const route = layer.route;
    if (!route) continue;
    for (const method of Object.keys(route.methods)) {
      if (!HTTP_METHODS.has(method)) continue;
      operations.add(`${method} ${oasPath(route.path as string)}`);
    }
  }
  return operations;
}

const SPEC_PUBLIC = new Set([
  'get /health',
  'get /livez',
  'get /readyz',
  'get /metrics',
  'get /openapi.json',
  'get /version',
]);

describe('OpenAPI document', () => {
  const registered = registeredOperations();

  it('documents every registered route', () => {
    const missing = [...registered].filter((operation) => {
      const [method, path] = operation.split(' ');
      const item = (openapi.paths as Record<string, Item>)[path];
      return !item || !item[method];
    });
    expect(missing).toEqual([]);
  });

  it('registers every documented operation', () => {
    const phantom: string[] = [];
    for (const [path, item] of Object.entries(openapi.paths as Record<string, Item>)) {
      for (const method of Object.keys(item)) {
        if (!registered.has(`${method} ${path}`)) phantom.push(`${method} ${path}`);
      }
    }
    expect(phantom).toEqual([]);
  });

  it('keeps exactly the unauthenticated operations public', () => {
    for (const [path, item] of Object.entries(openapi.paths as Record<string, Item>)) {
      for (const [method, operation] of Object.entries(item)) {
        const isPublic = Array.isArray(operation.security) && operation.security.length === 0;
        expect(isPublic).toBe(SPEC_PUBLIC.has(`${method} ${path}`));
      }
    }
  });

  it('serves the document before authentication', () => {
    const authenticationIndex = stack.findIndex((layer) => layer.name === 'authenticate');
    const documentIndex = stack.findIndex((layer) => layer.route?.path === '/openapi.json');
    expect(documentIndex).toBeGreaterThanOrEqual(0);
    expect(documentIndex).toBeLessThan(authenticationIndex);
  });
});
