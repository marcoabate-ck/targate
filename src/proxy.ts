import http from "node:http";
import https from "node:https";
import { Buffer } from "node:buffer";
import { timingSafeEqual } from "node:crypto";
import { buildPackageSignals } from "./pipeline.js";
import { fetchArtifactGuarded, readResponseBuffer } from "./network.js";
import { DEFAULT_RESOURCE_LIMITS } from "./resource-limits.js";
import { PendingApprovals } from "./proxy-approvals.js";
import { ProxyVerdictCache, sha512Sri } from "./proxy-cache.js";
import { uplinkFor, type ProxyUplink } from "./proxy-uplinks.js";
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

/** Upstream request timeout and body caps, aligned with the analysis pipeline's limits. */
const UPSTREAM_TIMEOUT_MS = DEFAULT_RESOURCE_LIMITS.networkTimeoutMs;
const MAX_PACKUMENT_BYTES = DEFAULT_RESOURCE_LIMITS.maxResponseBytes;
const MAX_TARBALL_BYTES = DEFAULT_RESOURCE_LIMITS.maxTarballBytes;
/** Cap concurrent tarball fetch+vet operations so buffered bytes stay bounded (≈ cap × MAX_TARBALL_BYTES). */
const MAX_CONCURRENT_VETS = 6;

/** Minimal FIFO semaphore bounding concurrent work. Exported for tests. */
export class Semaphore {
  private available: number;
  private readonly waiters: Array<() => void> = [];
  constructor(max: number) {
    this.available = max;
  }
  acquire(): Promise<void> {
    if (this.available > 0) {
      this.available--;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => this.waiters.push(resolve));
  }
  release(): void {
    const next = this.waiters.shift();
    if (next) next();
    else this.available++;
  }
}

export interface ProxyOptions {
  port: number;
  host?: string;
  /** Upstream registry origin (default registry.npmjs.org). */
  upstream?: string;
  /** Per-scope private-registry routes (phase 3). The client's auth is relayed. */
  uplinks?: ProxyUplink[];
  /** Project root the analysis pipeline reads .npmrc / the ledger from. */
  cwd?: string;
  /** When set, the proxy serves HTTPS with this key/cert instead of HTTP. */
  tls?: { key: Buffer | string; cert: Buffer | string };
  /** Shared secret gating the control API (`/-/targate/*`). Without it, control is disabled. */
  controlToken?: string;
  /** Called once per decision and lifecycle event for the CLI to print. */
  onEvent?: (event: ProxyEvent) => void;
}

export type ProxyEvent =
  | { kind: "listening"; url: string; upstream: string }
  | { kind: "packument"; name: string }
  | { kind: "pending"; name: string; version: string }
  | { kind: "decision"; name: string; version: string; decision: Decision; cached: boolean; ms: number; reason?: string }
  | { kind: "error"; detail: string };

export interface ProxyHandle {
  server: http.Server;
  /** digest -> verdict. Persistent; exposed for `proxy status` / tests. */
  cache: ProxyVerdictCache;
  /** In-flight approval holds; exposed for tests. */
  pending: PendingApprovals;
}

/**
 * True when the client is npm. Only npm rewrites a tarball's host to the
 * configured registry (`replace-registry-host`), so for npm we can leave
 * `dist.tarball` canonical and keep the lockfile portable. Every other manager
 * (bun, pnpm, yarn, …) fetches `dist.tarball` verbatim, so we must rewrite it to
 * the proxy or the tarball fetch would skip vetting.
 *
 * Match npm's UA precisely: it *starts* with `npm/` (e.g. `npm/10.9.2 node/…`).
 * pnpm and yarn embed `npm/?` later in their UA (`pnpm/11 npm/? …`,
 * `yarn/1 npm/? …`), so a loose `npm/` match would misclassify them as npm and
 * skip the rewrite they need — anchor to the start.
 */
export function isNpmClient(userAgent: string | undefined): boolean {
  return /^\s*npm\//i.test(userAgent ?? "");
}

/** Constant-time string equality (avoids timing oracles on the control token). */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** True when a socket's remote address is loopback — control API is loopback-only. */
export function isLoopbackRemote(address: string | undefined): boolean {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

/**
 * Build the upstream URL for a request path, refusing anything that would leave
 * the intended registry's origin. The request-target is client-controlled, so a
 * naive `origin + reqUrl` concat could be steered to another host (absolute or
 * protocol-relative request-targets); resolving against the origin and asserting
 * the origin is unchanged closes that.
 */
export function safeUpstreamUrl(origin: string, reqUrl: string): string {
  const base = new URL(origin);
  const resolved = new URL(reqUrl, base);
  if (resolved.origin !== base.origin) {
    throw new Error(`refusing cross-origin upstream request: ${resolved.origin} != ${base.origin}`);
  }
  return resolved.toString();
}

/**
 * Rewrite every `dist.tarball` in a packument to a canonical proxy path that
 * carries the original tarball URL in a `__u` query param. The canonical path
 * (`/<name>/-/<unscoped>-<version>.tgz`) is what parseRegistryPath understands,
 * while `__u` lets the proxy fetch the real bytes from wherever the upstream put
 * them — GitHub Packages uses `/download/@scope/name/version/<sha>`, not the
 * `/-/` convention, so a plain origin swap misroutes. Returns the original text
 * unchanged if it is not JSON we recognize.
 */
export function rewritePackumentTarballs(text: string, proxyOrigin: string): string {
  let doc: { name?: string; versions?: Record<string, { version?: string; dist?: { tarball?: string } }> };
  try {
    doc = JSON.parse(text);
  } catch {
    return text;
  }
  const name = doc.name;
  if (!name || !doc.versions) return text;
  for (const [ver, meta] of Object.entries(doc.versions)) {
    const tarball = meta?.dist?.tarball;
    if (!tarball) continue;
    const version = meta.version ?? ver;
    const unscoped = name.includes("/") ? name.slice(name.lastIndexOf("/") + 1) : name;
    const encoded = Buffer.from(tarball, "utf8").toString("base64url");
    meta.dist!.tarball = `${proxyOrigin}/${name}/-/${unscoped}-${version}.tgz?__u=${encoded}`;
  }
  return JSON.stringify(doc);
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

function fetchUpstream(
  target: string,
  accept: string,
  auth?: string,
  limits?: { timeoutMs?: number; maxBytes?: number },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const mod = u.protocol === "https:" ? https : http;
    const headers: Record<string, string> = { accept, "accept-encoding": "identity", "user-agent": "targate-proxy" };
    if (auth) headers.authorization = auth;
    const req = mod.request(u, { method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c) => {
        size += (c as Buffer).length;
        if (limits?.maxBytes && size > limits.maxBytes) {
          req.destroy(new Error(`upstream response exceeds ${limits.maxBytes} bytes: ${target}`));
          return;
        }
        chunks.push(c as Buffer);
      });
      res.on("end", () => resolve({ status: res.statusCode ?? 502, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    if (limits?.timeoutMs) {
      req.setTimeout(limits.timeoutMs, () => req.destroy(new Error(`upstream timed out after ${limits.timeoutMs}ms: ${target}`)));
    }
    req.on("error", reject);
    req.end();
  });
}

async function decide(
  name: string,
  version: string,
  cwd: string | undefined,
  prefetchedTarball: Buffer,
  registryOverride?: { url: string; source: "scope"; auth?: string },
): Promise<{ decision: Decision; summary: string; analyzedDigest: string }> {
  const { signals } = await buildPackageSignals(name, version, { cwd, prefetchedTarball, registryOverride });
  const verdict = evaluateRules(signals);
  return { decision: verdict.decision, summary: verdict.summary, analyzedDigest: signals.artifact.digest };
}

/**
 * Build (but do not start) the proxy server. Call `.server.listen(port)` — or
 * use `startProxy` which listens and reports the `listening` event.
 */
export function createProxyServer(options: ProxyOptions): ProxyHandle {
  const upstream = (options.upstream ?? DEFAULT_UPSTREAM).replace(/\/+$/, "");
  const uplinks = options.uplinks ?? [];
  const scheme = options.tls ? "https" : "http";
  const proxyOrigin = `${scheme}://${options.host ?? "127.0.0.1"}:${options.port}`;
  const cache = new ProxyVerdictCache();
  const pending = new PendingApprovals();
  const vetGate = new Semaphore(MAX_CONCURRENT_VETS);
  const emit = (event: ProxyEvent): void => options.onEvent?.(event);

  /** Route a package to its upstream: a matching private-scope uplink, else the default. */
  function targetFor(name: string): { origin: string; isPrivate: boolean; auth?: string } {
    const uplink = uplinkFor(name, uplinks);
    return uplink
      ? { origin: uplink.upstream, isPrivate: true, auth: uplink.auth }
      : { origin: upstream, isPrivate: false };
  }

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

  /** Local control API used by `targate proxy approvals|approve|deny`. */
  async function handleControl(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const json = (status: number, body: unknown): void => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    // Control (approve/deny) is loopback-only, even if the proxy binds a wider
    // interface — a network peer must never be able to release a held package.
    if (!isLoopbackRemote(req.socket.remoteAddress ?? undefined)) {
      json(403, { error: "control API is loopback-only" });
      return;
    }
    const header = req.headers["x-targate-control"];
    if (!options.controlToken || typeof header !== "string" || !safeEqual(header, options.controlToken)) {
      json(403, { error: "forbidden" });
      return;
    }
    const url = new URL(req.url ?? "/", proxyOrigin);
    if (req.method === "GET" && url.pathname === "/-/targate/pending") {
      json(200, { pending: pending.list() });
      return;
    }
    if (req.method === "POST" && url.pathname === "/-/targate/decide") {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const c of req) {
        size += (c as Buffer).length;
        if (size > 64 * 1024) {
          json(413, { error: "control request body too large" });
          return;
        }
        chunks.push(c as Buffer);
      }
      let payload: { name?: string; version?: string; decision?: string };
      try {
        payload = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      } catch {
        json(400, { error: "invalid JSON" });
        return;
      }
      const { name, version, decision } = payload;
      if (!name || !version || (decision !== "approve" && decision !== "deny")) {
        json(400, { error: "name, version, and decision (approve|deny) required" });
        return;
      }
      json(200, { resolved: pending.decide(name, version, decision) });
      return;
    }
    json(404, { error: "not found" });
  }

  async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if ((req.url ?? "").startsWith("/-/targate/")) {
      await handleControl(req, res);
      return;
    }
    const auth = typeof req.headers.authorization === "string" ? req.headers.authorization : undefined;
    const parsed = parseRegistryPath(req.url ?? "");
    if (!parsed || req.method !== "GET") {
      // pass anything we do not vet straight through (e.g. self-update checks)
      const up = await fetchUpstream(safeUpstreamUrl(upstream, req.url ?? "/"), String(req.headers.accept ?? "application/json"), auth, {
        timeoutMs: UPSTREAM_TIMEOUT_MS,
        maxBytes: MAX_PACKUMENT_BYTES,
      });
      res.writeHead(up.status, { "content-type": String(up.headers["content-type"] ?? "application/octet-stream") });
      res.end(up.body);
      return;
    }
    const target = targetFor(parsed.name);
    // Prefer the uplink's stored credential (captured at setup); otherwise relay
    // the client's own Authorization header pass-through.
    const upstreamAuth = target.auth ?? auth;

    // ---- tarball: fetch the exact bytes we will serve, vet, then serve or refuse ----
    if (parsed.tarballVersion) {
      const { name, tarballVersion: version } = parsed as { name: string; tarballVersion: string };
      const key = `${name}@${version}`;
      const started = Date.now();

      // Bound concurrent fetch+analysis so buffered bytes stay within
      // MAX_CONCURRENT_VETS × MAX_TARBALL_BYTES. Released before any approval
      // hold so a queue of held requests cannot starve the gate.
      await vetGate.acquire();
      let gateHeld = true;
      const releaseGate = (): void => {
        if (gateHeld) {
          gateHeld = false;
          vetGate.release();
        }
      };
      try {
      // The rewritten dist.tarball carries the real upstream URL in `__u` (its
      // path may not follow the /-/ convention, e.g. GitHub Packages). Fetch that
      // when present — validated to the same origin as the resolved upstream —
      // otherwise fall back to the path-based URL (npm's canonical /-/ tarball).
      const encodedUpstream = new URL(req.url ?? "/", proxyOrigin).searchParams.get("__u");
      let tarballUrl: string;
      if (encodedUpstream) {
        const decoded = new URL(Buffer.from(encodedUpstream, "base64url").toString("utf8"));
        if (decoded.origin !== new URL(target.origin).origin) {
          throw new Error(`refusing cross-origin tarball: ${decoded.origin} != ${target.origin}`);
        }
        tarballUrl = decoded.toString();
      } else {
        tarballUrl = safeUpstreamUrl(target.origin, req.url ?? "/");
      }
      // Guarded fetch: follows redirects (GitHub Packages 302s to a CDN),
      // re-validates each hop against the SSRF guard, and drops the credential
      // on a cross-origin hop so the upstream token never leaks to a CDN.
      const tarRes = await fetchArtifactGuarded(
        tarballUrl,
        upstreamAuth ? { headers: { authorization: upstreamAuth } } : {},
        { timeoutMs: UPSTREAM_TIMEOUT_MS, maxResponseBytes: MAX_TARBALL_BYTES },
        `${key} tarball`,
      );
      if (!tarRes.ok) {
        // let the client see the upstream's own error (404 for a bad version, etc.)
        res.writeHead(tarRes.status, { "content-type": tarRes.headers.get("content-type") ?? "application/json" });
        res.end(await tarRes.text());
        return;
      }
      const tar = {
        status: tarRes.status,
        body: await readResponseBuffer(tarRes, MAX_TARBALL_BYTES, "package tarball"),
        contentType: tarRes.headers.get("content-type") ?? "application/octet-stream",
      };

      // Key the verdict to the bytes we are about to serve, not to name@version:
      // a mutated/republished tarball has a different digest and is re-analyzed.
      const digest = sha512Sri(tar.body);
      let record = cache.get(digest);
      const cached = record !== undefined;
      if (!record) {
        // Analyze the exact bytes we are about to serve — no second download,
        // and the verdict is structurally bound to the served artifact. For a
        // private scope, the metadata is fetched from the scope's upstream with
        // the relayed credential (the daemon has no .npmrc mapping for it).
        const verdict = await decide(
          name,
          version,
          options.cwd,
          tar.body,
          target.isPrivate ? { url: target.origin, source: "scope", auth: upstreamAuth } : undefined,
        );
        let { decision, summary } = verdict;
        // Invariant guard: the analyzed digest must equal the served bytes'
        // digest (same bytes). If somehow not, fail closed.
        if (verdict.analyzedDigest && verdict.analyzedDigest !== digest) {
          decision = "block";
          summary = `served tarball digest ${digest} does not match the analyzed artifact ${verdict.analyzedDigest}`;
        }
        // require_approval → hold the connection for an out-of-band human
        // decision (targate proxy approve|deny). Timeout/queue-full fail closed.
        let persist = true;
        if (decision === "require_approval") {
          if (pending.atCapacity) {
            decision = "block";
            summary = `approval queue full — retry the install: ${summary}`;
            persist = false;
          } else {
            releaseGate(); // free the analysis slot before the (possibly long) human wait
            emit({ kind: "pending", name, version });
            const outcome = await pending.register(digest, name, version, Date.now());
            if (outcome === "approve") {
              decision = "allow";
              summary = `human-approved — ${summary}`;
            } else if (outcome === "deny") {
              decision = "block";
              summary = `human-denied — ${summary}`;
            } else {
              decision = "block";
              summary = `approval timed out — ${summary}`;
              persist = false;
            }
          }
        }
        record = { name, version, decision, summary, at: Date.now() };
        if (persist) cache.set(digest, record);
      }
      const ms = Date.now() - started;
      emit({ kind: "decision", name, version, decision: record.decision, cached, ms, reason: record.summary });

      if (!ALLOWED.has(record.decision)) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: `targate blocked ${key}: ${record.decision}`, reason: record.summary }));
        return;
      }
      res.writeHead(tar.status, { "content-type": tar.contentType });
      res.end(tar.body);
      } finally {
        releaseGate();
      }
      return;
    }

    // ---- packument ----
    emit({ kind: "packument", name: parsed.name });
    const pack = await fetchUpstream(safeUpstreamUrl(target.origin, req.url ?? "/"), String(req.headers.accept ?? "application/json"), upstreamAuth, {
      timeoutMs: UPSTREAM_TIMEOUT_MS,
      maxBytes: MAX_PACKUMENT_BYTES,
    });
    // Rewrite dist.tarball to this proxy so the tarball fetch comes back for
    // vetting — always for a private scope, and for every non-npm client (only
    // npm rewrites the host itself via replace-registry-host, so npm keeps the
    // canonical URL and a portable lockfile; see N1 and §5.8).
    const rewriteTarball = target.isPrivate || !isNpmClient(req.headers["user-agent"]);
    const body = rewriteTarball
      ? Buffer.from(rewritePackumentTarballs(pack.body.toString("utf8"), proxyOrigin), "utf8")
      : pack.body;
    res.writeHead(pack.status, { "content-type": String(pack.headers["content-type"] ?? "application/json") });
    res.end(body);
  }

  return { server, cache, pending };
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
