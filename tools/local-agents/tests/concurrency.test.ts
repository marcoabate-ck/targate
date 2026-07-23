import { describe, expect, it } from "vitest";
import { memoryAwareConcurrency, runPool } from "../src/concurrency.js";

describe("runPool", () => {
  it("preserves input order", async () => {
    const out = await runPool([3, 1, 2], 2, async (n) => {
      await new Promise((r) => setTimeout(r, n * 5));
      return n * 10;
    });
    expect(out.map((r) => r.value)).toEqual([30, 10, 20]);
  });

  it("captures a thrown task without rejecting the pool", async () => {
    const out = await runPool([1, 2], 2, async (n) => {
      if (n === 2) throw new Error("boom");
      return n;
    });
    expect(out[0].value).toBe(1);
    expect(out[1].error).toBeInstanceOf(Error);
  });

  it("never exceeds the concurrency limit", async () => {
    let inFlight = 0;
    let peak = 0;
    await runPool([1, 2, 3, 4, 5, 6], 2, async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
    });
    expect(peak).toBeLessThanOrEqual(2);
  });
});

describe("memoryAwareConcurrency", () => {
  it("clamps when RAM cannot fit the requested workers", () => {
    const r = memoryAwareConcurrency(4, 24, 32 * 1024 ** 3); // 32GiB, 24GiB/worker
    expect(r.concurrency).toBe(1);
    expect(r.clamped).toBe(true);
    expect(r.reason).toMatch(/clamped/);
  });
  it("allows the request when RAM is ample", () => {
    const r = memoryAwareConcurrency(2, 8, 128 * 1024 ** 3);
    expect(r.concurrency).toBe(2);
    expect(r.clamped).toBe(false);
  });
});
