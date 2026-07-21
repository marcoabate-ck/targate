import { ResourceLimitError } from "./resource-limits.js";

export interface FetchBudget {
  timeoutMs: number;
  maxResponseBytes: number;
}

/** True for literal IPs / names that point at the host or a private network. */
export function isPrivateHost(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost") || host === "" ) return true;
  // IPv4 (incl. IPv4-mapped IPv6 like ::ffff:169.254.169.254)
  const v4 = host.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata 169.254.169.254
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  }
  // IPv6 loopback / unique-local / link-local
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
export function assertSafeArtifactUrl(url: string, label = "artifact URL"): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${label} is not a valid URL: ${url}`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`${label} must use https, got ${parsed.protocol}//: ${url}`);
  }
  if (isPrivateHost(parsed.hostname)) {
    throw new Error(`${label} resolves to a private/loopback host (${parsed.hostname}): refusing to fetch`);
  }
}

/** Shared timeout wrapper. The signal remains attached while the body streams. */
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
