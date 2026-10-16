// Appends every item without spreading into a call: `target.push(...items)`
// passes each item as an argument and throws "Maximum call stack size
// exceeded" once items is a few hundred thousand long, which a large account's
// resource list reaches.
export function appendAll<T>(target: T[], items: Iterable<T>): T[] {
  for (const item of items) target.push(item);
  return target;
}

// Graph vertices store list properties (e.g. `allowed_actions`) as a
// serialized JSON string; any other shape is treated as an empty list rather
// than thrown, so a malformed value degrades to "no actions" instead of
// crashing the caller.
export function parseJsonArray(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch {
      return [];
    }
  }
  return [];
}
