import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { proxyStateDir } from "./proxy-daemon.js";

/**
 * Per-scope upstream routing for the proxy (phase 3). In transparent mode the
 * client points a private scope at the proxy (`@acme:registry=https://proxy/`),
 * and the proxy holds the real destination for that scope here. The client's
 * Authorization header is relayed pass-through to the upstream — the proxy
 * stores the upstream URL, never the credential.
 */
export interface ProxyUplink {
  /** npm scope including the leading "@", e.g. "@acme". */
  scope: string;
  /** Real registry origin that serves this scope, e.g. "https://npm.acme.example". */
  upstream: string;
}

export function proxyUplinksFile(): string {
  return path.join(proxyStateDir(), "proxy-uplinks.json");
}

export function readProxyUplinks(file = proxyUplinksFile()): ProxyUplink[] {
  if (!existsSync(file)) return [];
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(
        (u): u is ProxyUplink =>
          typeof u === "object" &&
          u !== null &&
          typeof (u as ProxyUplink).scope === "string" &&
          (u as ProxyUplink).scope.startsWith("@") &&
          typeof (u as ProxyUplink).upstream === "string",
      )
      .map((u) => ({ scope: u.scope, upstream: u.upstream.replace(/\/+$/, "") }));
  } catch {
    return [];
  }
}

/** The scope of a (possibly scoped) package name, or undefined if unscoped. */
export function scopeOf(name: string): string | undefined {
  if (!name.startsWith("@")) return undefined;
  const slash = name.indexOf("/");
  return slash === -1 ? name : name.slice(0, slash);
}

/** Match a package name to its uplink, if any. */
export function uplinkFor(name: string, uplinks: ProxyUplink[]): ProxyUplink | undefined {
  const scope = scopeOf(name);
  return scope ? uplinks.find((u) => u.scope === scope) : undefined;
}
