/**
 * Runs `operation` over `items` with bounded concurrency and returns the
 * results in input order. Fail-fast: the first rejection stops new work from
 * being scheduled and rejects the whole call (in-flight operations finish).
 *
 * Used to fan out independent AWS API calls (per-resource or per-stage) that
 * would otherwise serialize into thousands of round trips.
 */
export async function mapBounded<T, R>(
  items: readonly T[],
  concurrency: number,
  operation: (item: T, index: number) => Promise<R>
): Promise<R[]> {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1 || concurrency > 64) {
    throw new Error('Concurrency must be an integer between 1 and 64');
  }

  const results: R[] = new Array(items.length) as R[];
  let cursor = 0;
  let failed = false;

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length && !failed) {
      const index = cursor++;
      try {
        results[index] = await operation(items[index], index);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  });

  await Promise.all(workers);
  return results;
}
