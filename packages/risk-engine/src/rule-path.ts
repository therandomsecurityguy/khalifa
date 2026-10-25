import type { GraphVertex } from './types';

export interface RulePath {
  vertices: GraphVertex[];
  edges: GraphVertex[];
}

// The driver deserializes each `path().by(valueMap(true, …))` element as a Map
// keyed by the T.id / T.label enum values plus property names, with every
// valueMap() value wrapped in a list. Plain objects are accepted too.
export function toVertex(element: unknown): GraphVertex {
  const vertex: GraphVertex = { id: '', label: '', properties: {} };
  for (const [key, raw] of entries(element)) {
    const name = keyName(key);
    const value = unwrap(raw);
    if (name === 'id') vertex.id = String(value);
    else if (name === 'label') vertex.label = String(value);
    else vertex.properties[name] = value;
  }
  return vertex;
}

// A rule's `path()` projection alternates vertex, edge, vertex, …; a single-hop
// rule yields one vertex. Shared by the rule runner and the simulation API so
// both read the same result shape.
export function extractRulePath(match: unknown): RulePath {
  const objects = Array.isArray(match) ? match : (match as { objects?: unknown } | null)?.objects;
  const elements = Array.isArray(objects) ? objects.map(toVertex) : [];
  const alternating = elements.length % 2 === 1;
  return {
    vertices: alternating ? elements.filter((_, index) => index % 2 === 0) : elements,
    edges: alternating ? elements.filter((_, index) => index % 2 === 1) : [],
  };
}

function entries(value: unknown): Array<[unknown, unknown]> {
  if (value instanceof Map) return [...value.entries()];
  return value && typeof value === 'object' ? Object.entries(value) : [];
}

function keyName(key: unknown): string {
  if (typeof key === 'string') return key;
  if (key && typeof key === 'object' && 'elementName' in key) {
    return String((key as { elementName: unknown }).elementName);
  }
  return String(key);
}

// A single-valued property comes back as a one-element list; multi-valued
// properties stay lists. `{ value }` wrappers from older result shapes unwrap too.
function unwrap(value: unknown): unknown {
  if (Array.isArray(value)) {
    const items = value.map(unwrap);
    return items.length === 1 ? items[0] : items;
  }
  if (value && typeof value === 'object' && !(value instanceof Map) && 'value' in value) {
    return unwrap((value as { value: unknown }).value);
  }
  return value;
}
