import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
  /**
   * Authorization header value used to authenticate to the upstream (e.g.
   * "Bearer …"), captured from the original .npmrc at setup time. When absent,
   * the proxy relays the client's own Authorization header pass-through.
   * This file therefore holds credentials — written 0600, never logged.
   */
  auth?: string;
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
      .map((u) => ({
        scope: u.scope,
        upstream: u.upstream.replace(/\/+$/, ""),
        ...(typeof u.auth === "string" ? { auth: u.auth } : {}),
      }));
  } catch {
    return [];
  }
}

/** Write the uplinks file 0600 (it may contain credentials). */
export function writeProxyUplinks(uplinks: ProxyUplink[], file = proxyUplinksFile()): void {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(uplinks, null, 2)}\n`, { mode: 0o600 });
}

/** Remove the uplinks file (teardown). */
export function removeProxyUplinks(file = proxyUplinksFile()): void {
  rmSync(file, { force: true });
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
