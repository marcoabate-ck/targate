import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { proxyStateDir } from "./proxy-daemon.js";
import type { Decision } from "./types.js";

/**
 * Persistent verdict cache for the proxy, keyed by the artifact's SHA-512 SRI
 * digest — the same immutable identity the artifact ledger uses. Keying by
 * bytes (not name@version) means a republished/mutated tarball gets a fresh
 * digest and is re-analyzed rather than served from a stale verdict, and two
 * package managers requesting the same bytes share one verdict. Persisting to
 * disk means each artifact is analyzed once ever — verdicts survive daemon
 * restarts (see docs/design/proxy.md §5.5).
 */

export interface VerdictRecord {
  name: string;
  version: string;
  decision: Decision;
  summary: string;
  /** epoch ms of first analysis; injected by the caller. */
  at: number;
}

/** SRI digest (`sha512-<base64>`) of tarball bytes — matches quarantine.ts. */
export function sha512Sri(bytes: Buffer): string {
  return `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
}

export class ProxyVerdictCache {
  private readonly file: string;
  private readonly entries: Map<string, VerdictRecord>;

  constructor(file = path.join(proxyStateDir(), "proxy-verdicts.json")) {
    this.file = file;
    this.entries = ProxyVerdictCache.load(file);
  }

  private static load(file: string): Map<string, VerdictRecord> {
    if (!existsSync(file)) return new Map();
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, VerdictRecord>;
      return new Map(Object.entries(parsed));
    } catch {
      return new Map();
    }
  }

  get(digest: string): VerdictRecord | undefined {
    return this.entries.get(digest);
  }

  set(digest: string, record: VerdictRecord): void {
    this.entries.set(digest, record);
    this.persist();
  }

  get size(): number {
    return this.entries.size;
  }

  private persist(): void {
    mkdirSync(path.dirname(this.file), { recursive: true });
    writeFileSync(this.file, `${JSON.stringify(Object.fromEntries(this.entries), null, 2)}\n`);
  }
}
