import http from "node:http";
import https from "node:https";
import { Buffer } from "node:buffer";
import { buildPackageSignals } from "./pipeline.js";
import { ProxyVerdictCache, sha512Sri } from "./proxy-cache.js";
import { evaluateRules } from "./rules.js";
import type { Decision } from "./types.js";

/**
 * Phase-2 registry proxy: a transparent, public-only enforcement point.
 *
 * Package managers are pointed at this proxy as their `registry=`. It serves
 * the two npm registry endpoints and vets every tarball with the existing
 * deterministic pipeline (`buildPackageSignals` + `evaluateRules`) before the
 * bytes reach the client — so nothing is cached or executed on the machine
 * until it passes.
 *
 * Two design decisions are settled by the PoC (see docs/design/proxy.md):
 *   - The packument is served WITHOUT rewriting `dist.tarball`. Canonical npmjs
 *     URLs plus the client's `replace-registry-host=npmjs` route both fresh
 *     installs and `npm ci` through the proxy while keeping the lockfile
 *     portable. Rewriting would leak `http://localhost:<port>/…` into the
 *     lockfile.
 *   - Each `name@version` is analyzed at most once; the verdict is cached
 *     (versions are immutable), turning a ~1s cold analysis into a ~0ms hit.
 */

const DEFAULT_UPSTREAM = "https://registry.npmjs.org";

/** Decisions whose bytes may be served. Everything else is refused (fail-closed). */
const ALLOWED: ReadonlySet<Decision> = new Set<Decision>(["allow", "allow_with_warnings"]);

export interface ProxyOptions {
  port: number;
  host?: string;
  /** Upstream registry origin (default registry.npmjs.org). */
  upstream?: string;
  /** Project root the analysis pipeline reads .npmrc / the ledger from. */
  cwd?: string;
  /** When set, the proxy serves HTTPS with this key/cert instead of HTTP. */
  tls?: { key: Buffer | string; cert: Buffer | string };
  /** Called once per decision and lifecycle event for the CLI to print. */
  onEvent?: (event: ProxyEvent) => void;
}

export type ProxyEvent =
  | { kind: "listening"; url: string; upstream: string }
  | { kind: "packument"; name: string }
  | { kind: "decision"; name: string; version: string; decision: Decision; cached: boolean; ms: number; reason?: string }
  | { kind: "error"; detail: string };

export interface ProxyHandle {
  server: http.Server;
  /** digest -> verdict. Persistent; exposed for `proxy status` / tests. */
  cache: ProxyVerdictCache;
}

/** Split a registry request path into a package name and, for tarballs, a version. */
export function parseRegistryPath(rawUrl: string): { name: string; tarballVersion?: string } | null {
  let pathname: string;
  try {
    pathname = new URL(rawUrl, "http://localhost").pathname;
  } catch {
    return null;
  }
  const decoded = decodeURIComponent(pathname).replace(/^\/+/, "");
  if (!decoded) return null;

  const dashIndex = decoded.indexOf("/-/");
  if (dashIndex === -1) {
    // packument request: the whole path is the (possibly scoped) name
    return { name: decoded };
  }
  const name = decoded.slice(0, dashIndex);
  const file = decoded.slice(dashIndex + 3); // after "/-/"
  const unscoped = name.includes("/") ? name.slice(name.lastIndexOf("/") + 1) : name;
  // tarball filename is `<unscoped>-<version>.tgz`; versions may contain hyphens
  if (file.startsWith(`${unscoped}-`) && file.endsWith(".tgz")) {
    const tarballVersion = file.slice(unscoped.length + 1, file.length - ".tgz".length);
    return { name, tarballVersion };
  }
  return { name };
}

function fetchUpstream(target: string, accept: string): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(u, { method: "GET", headers: { accept, "accept-encoding": "identity", "user-agent": "targate-proxy" } }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c as Buffer));
      res.on("end", () => resolve({ status: res.statusCode ?? 502, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function decide(
  name: string,
  version: string,
  cwd: string | undefined,
): Promise<{ decision: Decision; summary: string; analyzedDigest: string }> {
  const { signals } = await buildPackageSignals(name, version, { cwd });
  const verdict = evaluateRules(signals);
  return { decision: verdict.decision, summary: verdict.summary, analyzedDigest: signals.artifact.digest };
}

/**
 * Build (but do not start) the proxy server. Call `.server.listen(port)` — or
 * use `startProxy` which listens and reports the `listening` event.
 */
export function createProxyServer(options: ProxyOptions): ProxyHandle {
  const upstream = (options.upstream ?? DEFAULT_UPSTREAM).replace(/\/+$/, "");
  const cache = new ProxyVerdictCache();
  const emit = (event: ProxyEvent): void => options.onEvent?.(event);

  const onRequest = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    void handleRequest(req, res).catch((error) => {
      const cause = error instanceof Error && error.cause ? ` (${String((error.cause as Error).message ?? error.cause)})` : "";
      const detail = `${error instanceof Error ? error.message : String(error)}${cause}`;
      emit({ kind: "error", detail });
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `targate proxy: ${detail}` }));
    });
  };
  const server = options.tls
    ? https.createServer({ key: options.tls.key, cert: options.tls.cert }, onRequest)
    : http.createServer(onRequest);

  async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const parsed = parseRegistryPath(req.url ?? "");
    if (!parsed || req.method !== "GET") {
      // pass anything we do not vet straight through (e.g. self-update checks)
      const up = await fetchUpstream(`${upstream}${req.url ?? "/"}`, String(req.headers.accept ?? "application/json"));
      res.writeHead(up.status, { "content-type": String(up.headers["content-type"] ?? "application/octet-stream") });
      res.end(up.body);
      return;
    }

    // ---- tarball: fetch the exact bytes we will serve, vet, then serve or refuse ----
    if (parsed.tarballVersion) {
      const { name, tarballVersion: version } = parsed as { name: string; tarballVersion: string };
      const key = `${name}@${version}`;
      const started = Date.now();

      const tar = await fetchUpstream(`${upstream}${req.url}`, "application/octet-stream");
      if (tar.status >= 400) {
        // let the client see the upstream's own error (404 for a bad version, etc.)
        res.writeHead(tar.status, { "content-type": String(tar.headers["content-type"] ?? "application/json") });
        res.end(tar.body);
        return;
      }

      // Key the verdict to the bytes we are about to serve, not to name@version:
      // a mutated/republished tarball has a different digest and is re-analyzed.
      const digest = sha512Sri(tar.body);
      let record = cache.get(digest);
      const cached = record !== undefined;
      if (!record) {
        const verdict = await decide(name, version, options.cwd);
        let { decision, summary } = verdict;
        // TOCTOU guard: the analysis fetched its own copy of the tarball; if the
        // bytes we are about to serve differ from what was vetted, refuse.
        if (verdict.analyzedDigest && verdict.analyzedDigest !== digest) {
          decision = "block";
          summary = `served tarball digest ${digest} does not match the analyzed artifact ${verdict.analyzedDigest}`;
        }
        record = { name, version, decision, summary, at: Date.now() };
        cache.set(digest, record);
      }
      const ms = Date.now() - started;
      emit({ kind: "decision", name, version, decision: record.decision, cached, ms, reason: record.summary });

      if (!ALLOWED.has(record.decision)) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `targate blocked ${key}: ${record.decision}`, reason: record.summary }));
        return;
      }
      res.writeHead(tar.status, { "content-type": String(tar.headers["content-type"] ?? "application/octet-stream") });
      res.end(tar.body);
      return;
    }

    // ---- packument: pass through UNMODIFIED (canonical dist.tarball, see N1) ----
    emit({ kind: "packument", name: parsed.name });
    const pack = await fetchUpstream(`${upstream}${req.url}`, String(req.headers.accept ?? "application/json"));
    res.writeHead(pack.status, { "content-type": String(pack.headers["content-type"] ?? "application/json") });
    res.end(pack.body);
  }

  return { server, cache };
}

/** Create, listen, and resolve once the proxy is accepting connections. */
export function startProxy(options: ProxyOptions): Promise<ProxyHandle> {
  const handle = createProxyServer(options);
  const host = options.host ?? "127.0.0.1";
  const scheme = options.tls ? "https" : "http";
  const upstream = (options.upstream ?? DEFAULT_UPSTREAM).replace(/\/+$/, "");
  return new Promise((resolve, reject) => {
    handle.server.once("error", reject);
    handle.server.listen(options.port, host, () => {
      handle.server.removeListener("error", reject);
      options.onEvent?.({ kind: "listening", url: `${scheme}://${host}:${options.port}`, upstream });
      resolve(handle);
    });
  });
}
