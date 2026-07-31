import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { ResourceLimitError } from "./resource-limits.js";

export interface FetchBudget {
  timeoutMs: number;
  maxResponseBytes: number;
}

/**
 * Parse a host as a "loose" IPv4 the way libc `inet_aton` / `getaddrinfo` does:
 * 1–4 dot-separated parts, each decimal, octal (`0…`), or hex (`0x…`), with the
 * final part filling the remaining low bytes (so `127.1` → 127.0.0.1,
 * `2852039166` → 169.254.169.254). Returns the 4 octets, or null if the host is
 * not an all-numeric IPv4 in any of those encodings. This is what closes the
 * SSRF-guard bypass: an attacker can't smuggle a private IP as a decimal/hex
 * literal that the old dotted-quad-only regex ignored.
 */
function parseLooseIpv4(host: string): [number, number, number, number] | null {
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums: number[] = [];
  for (const part of parts) {
    let n: number;
    if (/^0x[0-9a-f]+$/.test(part)) n = parseInt(part, 16);
    else if (/^0[0-7]+$/.test(part)) n = parseInt(part, 8);
    else if (/^(0|[1-9][0-9]*)$/.test(part)) n = parseInt(part, 10);
    else return null; // a non-numeric label → this is a hostname, not an IP
    if (!Number.isSafeInteger(n) || n < 0) return null;
    nums.push(n);
  }
  const last = nums.length - 1;
  // Every part except the last must fit in a byte; the last fills what remains.
  for (let i = 0; i < last; i++) if (nums[i] > 255) return null;
  const maxLast = 2 ** (8 * (4 - last)) - 1;
  if (nums[last] > maxLast) return null;
  let value = nums[last];
  for (let i = 0; i < last; i++) value += nums[i] * 2 ** (8 * (3 - i));
  if (value < 0 || value > 0xffffffff) return null;
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
}

function isPrivateV4([a, b]: [number, number, number, number]): boolean {
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

/** True for literal IPs / names that point at the host or a private network. */
export function isPrivateHost(hostname: string): boolean {
  let host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "") return true;
  host = host.replace(/\.$/, ""); // a trailing dot resolves to the same address
  if (host === "localhost" || host.endsWith(".localhost")) return true;

  // IPv4-mapped (::ffff:…) and deprecated IPv4-compatible (::…) IPv6, in dotted
  // (::ffff:169.254.169.254 / ::169.254.169.254) OR hex (::ffff:a9fe:a9fe) form.
  const mapped = host.match(/^::(?:ffff:)?(.+)$/);
  if (mapped) {
    const inner = mapped[1];
    const hex = inner.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      if (isPrivateV4([(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255])) return true;
    }
    const v4 = parseLooseIpv4(inner);
    if (v4 && isPrivateV4(v4)) return true;
  }

  // Bare IPv4 in any encoding (dotted-quad, decimal, octal, hex, short-form).
  const v4 = parseLooseIpv4(host);
  if (v4) return isPrivateV4(v4);

  // IPv6 loopback / unique-local / link-local.
  if (host === "::1" || host === "::") return true;
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // fe80::/10
  return false;
}

/**
 * Guard a tarball/artifact URL taken from an untrusted packument before we
 * fetch it: the registry controls `dist.tarball`, so a malicious or MITM'd
 * response could point it at `http://169.254.169.254/…` (cloud metadata) or an
 * internal host and turn targate into an SSRF proxy. Require https and refuse
 * loopback/link-local/private-network hosts.
 */
/**
 * Resolve a hostname and reject if ANY resolved address is private/loopback —
 * catches a public-looking name that points at an internal host (DNS
 * rebinding's first half). NOTE: a determined rebinding attacker can still
 * change the record between this lookup and the socket's own resolution
 * (TOCTOU); fully closing that needs connection pinning to the vetted address.
 * See docs/threat-model.md. IP-literal hosts are already covered by
 * assertSafeArtifactUrl and skip the lookup.
 */
export async function assertHostResolvesPublic(hostname: string, label = "artifact URL"): Promise<void> {
  if (insecureRegistryHostAllowed(hostname)) return; // test/dev opt-out
  if (isIP(hostname)) return; // literal — assertSafeArtifactUrl already checked it
  let addrs: { address: string }[];
  try {
    addrs = await lookup(hostname, { all: true });
  } catch {
    return; // resolution failure surfaces at connect time; don't mask it here
  }
  for (const { address } of addrs) {
    if (isPrivateHost(address)) {
      throw new Error(`${label}: host ${hostname} resolves to a private/loopback address (${address})`);
    }
  }
}

let warnedInsecureHosts = false;

/**
 * Hosts explicitly allowed to bypass the https + private-network SSRF checks,
 * from `TARGATE_INSECURE_REGISTRY_HOSTS` (comma-separated hostnames). This is a
 * **test/dev-only** escape hatch for pointing the registry proxy at a local
 * registry (e.g. Verdaccio on localhost, or a private-IP container) — never set
 * it in production; it disables SSRF protection for the listed hosts.
 */
export function insecureRegistryHostAllowed(hostname: string): boolean {
  const raw = process.env.TARGATE_INSECURE_REGISTRY_HOSTS;
  if (!raw) return false;
  const allowed = raw
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (!allowed.includes(hostname.toLowerCase())) return false;
  if (!warnedInsecureHosts) {
    warnedInsecureHosts = true;
    process.stderr.write(
      `WARNING: TARGATE_INSECURE_REGISTRY_HOSTS is set — SSRF/https checks are disabled for: ${allowed.join(", ")}. Test/dev only.\n`,
    );
  }
  return true;
}

export function assertSafeArtifactUrl(url: string, label = "artifact URL"): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${label} is not a valid URL: ${url}`);
  }
  if (insecureRegistryHostAllowed(parsed.hostname)) return;
  if (parsed.protocol !== "https:") {
    throw new Error(`${label} must use https, got ${parsed.protocol}//: ${url}`);
  }
  if (isPrivateHost(parsed.hostname)) {
    throw new Error(`${label} resolves to a private/loopback host (${parsed.hostname}): refusing to fetch`);
  }
}

/** Shared timeout wrapper. The signal remains attached while the body streams. */
/**
 * Retry a network operation that fails with a **transient** timeout
 * (`ResourceLimitError` kind `network-timeout`, thrown by `fetchWithTimeout` and
 * the streaming readers). Any other error — 404, auth failure, a real limit —
 * propagates immediately, so this never masks a deterministic failure nor
 * weakens fail-closed behavior: if every attempt still times out, the last
 * timeout is thrown and the caller degrades to UNKNOWN as before. `delayMs` is
 * injectable so tests run without real waits.
 */
export async function retryOnNetworkTimeout<T>(
  fn: () => Promise<T>,
  attempts = 3,
  delayMs: (attempt: number) => number = (attempt) => 200 * attempt,
): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const transient = err instanceof ResourceLimitError && err.kind === "network-timeout";
      if (!transient || attempt === attempts) throw err;
      await new Promise((resolve) => setTimeout(resolve, delayMs(attempt)));
    }
  }
  throw lastError;
}

export async function fetchWithTimeout(
  input: string | URL,
  init: RequestInit = {},
  budget: FetchBudget,
): Promise<Response> {
  const timeout = AbortSignal.timeout(budget.timeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
  try {
    return await Promise.race([
      fetch(input, { ...init, signal }),
      new Promise<never>((_, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(new ResourceLimitError(
            "network-timeout",
            `network request exceeded ${budget.timeoutMs}ms (${String(input)})`,
          )),
          { once: true },
        );
      }),
    ]);
  } catch (err) {
    if (err instanceof ResourceLimitError) throw err;
    if (signal.aborted || (err instanceof Error && /timeout|aborted/i.test(err.message))) {
      throw new ResourceLimitError(
        "network-timeout",
        `network request exceeded ${budget.timeoutMs}ms (${String(input)})`,
      );
    }
    throw err;
  }
}

/**
 * Fetch an artifact whose URL came from an untrusted packument, following
 * redirects MANUALLY and re-validating every hop with `assertSafeArtifactUrl`.
 * Node's default `redirect: "follow"` would let a registry return a valid
 * public https URL and then 302 to `http://169.254.169.254/…` — an SSRF the
 * one-shot guard on the initial URL cannot catch. The Authorization header is
 * dropped on any cross-origin hop so a redirect can't exfiltrate the registry
 * credential to another host.
 */
export async function fetchArtifactGuarded(
  url: string,
  init: RequestInit,
  budget: FetchBudget,
  label = "artifact URL",
  maxHops = 5,
): Promise<Response> {
  let current = url;
  let currentInit: RequestInit = { ...init, redirect: "manual" };
  let origin = new URL(url).origin;
  for (let hop = 0; ; hop++) {
    assertSafeArtifactUrl(current, label);
    await assertHostResolvesPublic(new URL(current).hostname, label);
    const res = await fetchWithTimeout(current, currentInit, budget);
    if (res.status < 300 || res.status >= 400) return res;
    const location = res.headers.get("location");
    if (!location) return res; // 3xx without Location — let the caller handle it
    if (hop >= maxHops) {
      throw new Error(`${label}: too many redirects (>${maxHops})`);
    }
    const next = new URL(location, current);
    const headers = new Headers(currentInit.headers);
    if (next.origin !== origin) headers.delete("authorization");
    current = next.toString();
    currentInit = { ...currentInit, headers };
    origin = next.origin;
  }
}

/** Stream a response body while enforcing both declared and actual size. */
export async function readResponseBuffer(
  response: Response,
  maxBytes: number,
  label = "response",
): Promise<Buffer> {
  const declared = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ResourceLimitError(
      "response-size",
      `${label} declares ${declared} bytes, above the ${maxBytes}-byte limit`,
    );
  }

  // Test doubles and older fetch implementations may expose only arrayBuffer.
  if (!response.body) {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > maxBytes) {
      throw new ResourceLimitError(
        "response-size",
        `${label} exceeded the ${maxBytes}-byte limit`,
      );
    }
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      total += chunk.length;
      if (total > maxBytes) {
        await reader.cancel("response size limit exceeded").catch(() => {});
        throw new ResourceLimitError(
          "response-size",
          `${label} exceeded the ${maxBytes}-byte limit`,
        );
      }
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof ResourceLimitError) throw err;
    if (err instanceof Error && /timeout|aborted/i.test(err.message)) {
      throw new ResourceLimitError("network-timeout", `${label} timed out while streaming`);
    }
    throw err;
  }
  return Buffer.concat(chunks, total);
}

export async function readResponseJson<T>(
  response: Response,
  maxBytes: number,
  label = "JSON response",
): Promise<T> {
  // Preserve compatibility with small test doubles that implement json()
  // but no byte-bearing body. Real fetch responses always take the bounded path.
  if (!response.body && typeof response.arrayBuffer !== "function") {
    return (await response.json()) as T;
  }
  const bytes = await readResponseBuffer(response, maxBytes, label);
  try {
    return JSON.parse(bytes.toString("utf8")) as T;
  } catch (err) {
    throw new Error(`${label} is not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
}
