/**
 * In-flight approval holds for the proxy (phase 4). When a package is rated
 * `require_approval`, the proxy holds the client's HTTP request open (npm waits
 * up to its `fetch-timeout`) and registers a pending here. A human approves or
 * denies out of band (`targate proxy approve|deny` → the proxy's control API),
 * which resolves the hold: approve → serve, deny/timeout → refuse (fail-closed).
 *
 * The PoC (docs/design/proxy.md, N2) confirmed npm fetches tarballs
 * concurrently, so holding one does not stall the others; the hold must resolve
 * within `fetch-timeout`, hence the cap and the bounded number of simultaneous
 * holds (a held connection consumes a socket from npm's pool).
 */

export type ApprovalOutcome = "approve" | "deny" | "timeout";

interface PendingEntry {
  name: string;
  version: string;
  since: number;
  settle: (outcome: ApprovalOutcome) => void;
  timer: ReturnType<typeof setTimeout>;
}

export interface PendingView {
  name: string;
  version: string;
  since: number;
}

export class PendingApprovals {
  private readonly entries = new Map<string, PendingEntry>();

  constructor(
    private readonly maxConcurrent = 16,
    private readonly holdMs = 240_000,
  ) {}

  get size(): number {
    return this.entries.size;
  }

  /** True when another hold would exceed the concurrency cap. */
  get atCapacity(): boolean {
    return this.entries.size >= this.maxConcurrent;
  }

  /**
   * Register a hold keyed by digest. Resolves when a decision arrives or the
   * hold times out. `now` is injected so callers control the timestamp.
   */
  register(digest: string, name: string, version: string, now: number): Promise<ApprovalOutcome> {
    const existing = this.entries.get(digest);
    if (existing) {
      // Deduplicate concurrent requests for the same artifact onto one hold.
      return new Promise((resolve) => {
        const prev = existing.settle;
        existing.settle = (outcome) => {
          prev(outcome);
          resolve(outcome);
        };
      });
    }
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.entries.delete(digest);
        resolve("timeout");
      }, this.holdMs);
      if (typeof timer.unref === "function") timer.unref();
      this.entries.set(digest, { name, version, since: now, settle: resolve, timer });
    });
  }

  /** Resolve every hold matching name@version. Returns how many were resolved. */
  decide(name: string, version: string, outcome: "approve" | "deny"): number {
    let resolved = 0;
    for (const [digest, entry] of this.entries) {
      if (entry.name === name && entry.version === version) {
        clearTimeout(entry.timer);
        this.entries.delete(digest);
        entry.settle(outcome);
        resolved++;
      }
    }
    return resolved;
  }

  list(): PendingView[] {
    return [...this.entries.values()].map((e) => ({ name: e.name, version: e.version, since: e.since }));
  }
}
