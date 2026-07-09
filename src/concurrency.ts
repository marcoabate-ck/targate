/** Default width of the tree-analysis pool. Network-bound work, so > cores. */
export const DEFAULT_CONCURRENCY = 16;

/**
 * Run `fn` over `items` with at most `limit` in flight at once, preserving
 * input order in the result array. Shared by the transitive walker and the
 * OSV batch detail-fetch pool (kept here, not in transitive.ts, so osv.ts can
 * use it without an import cycle).
 */
export async function mapLimit<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(Math.max(1, limit), items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}
