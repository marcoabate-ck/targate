/**
 * Bounded concurrency for local workers.
 *
 * Running several 35B/MoE workers at once can exhaust system memory, so the
 * pool defaults to a small width and refuses to exceed the configured cap.
 * `runPool` preserves input order and never rejects on an individual failure —
 * each task result is captured so one crashed worker cannot abort the batch.
 */

import { totalmem } from "node:os";

export interface PoolResult<R> {
  index: number;
  value?: R;
  error?: unknown;
}

/**
 * Run `fn` over `items` with at most `limit` in flight. Order preserved.
 * A task that throws is captured as `{ error }` rather than rejecting the pool.
 */
export async function runPool<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<PoolResult<R>[]> {
  const width = Math.min(Math.max(1, limit), Math.max(1, items.length));
  const results = new Array<PoolResult<R>>(items.length);
  let next = 0;
  const workers = Array.from({ length: width }, async () => {
    while (next < items.length) {
      const i = next++;
      try {
        results[i] = { index: i, value: await fn(items[i], i) };
      } catch (error) {
        results[i] = { index: i, error };
      }
    }
  });
  await Promise.all(workers);
  return results;
}

/**
 * Suggest a safe concurrency given the configured cap and rough per-worker
 * memory need. Purely advisory — the orchestrator logs when it clamps so the
 * operator understands why fewer workers ran than requested.
 */
export function memoryAwareConcurrency(
  requested: number,
  perWorkerGiB = 24,
  total = totalmem(),
): { concurrency: number; clamped: boolean; reason?: string } {
  const totalGiB = total / 1024 ** 3;
  // Leave headroom for the OS + the Ollama server itself.
  const usableGiB = Math.max(0, totalGiB - 4);
  const byMemory = Math.max(1, Math.floor(usableGiB / perWorkerGiB));
  if (byMemory < requested) {
    return {
      concurrency: byMemory,
      clamped: true,
      reason: `clamped ${requested}→${byMemory}: ~${perWorkerGiB}GiB/worker exceeds ${usableGiB.toFixed(0)}GiB usable RAM`,
    };
  }
  return { concurrency: requested, clamped: false };
}
