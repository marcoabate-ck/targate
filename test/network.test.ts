import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  assertHostResolvesPublic,
  assertSafeArtifactUrl,
  fetchArtifactGuarded,
  isPrivateHost,
  retryOnNetworkTimeout,
} from "../src/network.js";
import { ResourceLimitError } from "../src/resource-limits.js";

vi.mock("node:dns/promises", () => ({
  lookup: vi.fn(async (host: string) =>
    host === "rebind.evil"
      ? [{ address: "169.254.169.254", family: 4 }]
      : [{ address: "93.184.216.34", family: 4 }],
  ),
}));

// Regression (P1.2): dist.tarball is registry-controlled; a malicious or MITM'd
// packument could point it at cloud metadata or an internal host, turning
// targate into an SSRF proxy. The guard must reject non-https and private hosts.
describe("isPrivateHost", () => {
  it.each([
    "localhost",
    "app.localhost",
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254", // cloud metadata
    "100.100.0.1", // CGNAT
    "::1",
    "fc00::1",
    "fe80::1",
  ])("flags private/loopback host %s", (host) => {
    expect(isPrivateHost(host)).toBe(true);
  });

  it.each(["registry.npmjs.org", "npm.acme.com", "reg", "8.8.8.8", "172.32.0.1", "192.169.0.1"])(
    "allows public host %s",
    (host) => {
      expect(isPrivateHost(host)).toBe(false);
    },
  );

  // Regression (v2 P1.1/P2.7): the old dotted-quad-only regex let alternate IP
  // encodings smuggle a private address past the SSRF guard.
  it.each([
    ["169.254.169.254.", "trailing dot"],
    ["2852039166", "decimal 169.254.169.254"],
    ["2130706433", "decimal 127.0.0.1"],
    ["0x7f000001", "hex 127.0.0.1"],
    ["0177.0.0.1", "octal-first 127.0.0.1"],
    ["127.1", "short-form 127.0.0.1"],
    ["::ffff:a9fe:a9fe", "IPv4-mapped IPv6 hex 169.254.169.254"],
  ])("flags alternate-encoded private IP %s (%s)", (host) => {
    expect(isPrivateHost(host)).toBe(true);
  });

  it("still allows public IPs given in decimal/short form", () => {
    expect(isPrivateHost("134744072")).toBe(false); // 8.8.8.8 in decimal
    expect(isPrivateHost("8.8.8.8")).toBe(false);
  });
});

describe("assertSafeArtifactUrl", () => {
  it("accepts a normal https public tarball URL", () => {
    expect(() =>
      assertSafeArtifactUrl("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
    ).not.toThrow();
  });

  it("rejects http (cleartext)", () => {
    expect(() => assertSafeArtifactUrl("http://registry.npmjs.org/x.tgz")).toThrow(/https/);
  });

  it("rejects the cloud-metadata endpoint even over https", () => {
    expect(() => assertSafeArtifactUrl("https://169.254.169.254/latest/meta-data/")).toThrow(
      /private\/loopback/,
    );
  });

  it("rejects an internal host tarball", () => {
    expect(() => assertSafeArtifactUrl("https://10.0.0.5/pkg.tgz")).toThrow(/private\/loopback/);
  });
});

// Regression (v3 P1.2): a public-looking hostname that RESOLVES to a private
// address must be rejected (DNS rebinding, first half).
describe("assertHostResolvesPublic", () => {
  it("rejects a hostname resolving to a private address", async () => {
    await expect(assertHostResolvesPublic("rebind.evil")).rejects.toThrow(/private\/loopback/);
  });

  it("allows a hostname resolving to a public address", async () => {
    await expect(assertHostResolvesPublic("example.com")).resolves.toBeUndefined();
  });

  it("skips the lookup for an IP literal", async () => {
    await expect(assertHostResolvesPublic("93.184.216.34")).resolves.toBeUndefined();
  });
});

// Regression (review A1.2): fetchArtifactGuarded follows redirects MANUALLY and
// re-validates every hop. The subtle guarantees — a 3xx to a private/metadata
// host is rejected, the Authorization header is dropped on a cross-origin hop
// (registry-credential exfiltration) but kept same-origin, and a redirect loop
// is bounded — had no coverage. These lock them in.
describe("fetchArtifactGuarded", () => {
  const budget = { timeoutMs: 1000, maxResponseBytes: 4096 };
  let calls: { url: string; auth: string | null }[];

  /** Build a minimal Response; a 3xx carries its Location header. */
  function make(status: number, location?: string): Response {
    const headers = new Headers();
    if (location) headers.set("location", location);
    return new Response(status >= 200 && status < 300 ? "ok" : null, { status, headers });
  }

  /** Stub global fetch with a per-URL router, recording the Authorization sent. */
  function route(router: (url: string) => Response): void {
    calls = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL, init?: RequestInit) => {
        const url = String(input);
        calls.push({ url, auth: new Headers(init?.headers).get("authorization") });
        return router(url);
      }),
    );
  }

  beforeEach(() => {
    calls = [];
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns a terminal 2xx response without following anything", async () => {
    route(() => make(200));
    const res = await fetchArtifactGuarded("https://a.example.com/pkg.tgz", {}, budget);
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(1);
  });

  it("rejects a redirect to the cloud-metadata / private host", async () => {
    route((url) =>
      url.startsWith("https://a.example.com")
        ? make(302, "https://169.254.169.254/latest/meta-data/")
        : make(200),
    );
    await expect(
      fetchArtifactGuarded("https://a.example.com/pkg.tgz", {}, budget),
    ).rejects.toThrow(/private\/loopback/);
    // The metadata host was never actually fetched — rejected at validation.
    expect(calls).toHaveLength(1);
  });

  it("drops the Authorization header on a cross-origin hop", async () => {
    route((url) =>
      url === "https://a.example.com/pkg.tgz"
        ? make(302, "https://b.example.com/pkg.tgz")
        : make(200),
    );
    const res = await fetchArtifactGuarded(
      "https://a.example.com/pkg.tgz",
      { headers: { authorization: "Bearer registry-secret" } },
      budget,
    );
    expect(res.status).toBe(200);
    expect(calls).toHaveLength(2);
    expect(calls[0].auth).toBe("Bearer registry-secret");
    expect(calls[1].auth).toBeNull(); // credential must not leak to another origin
  });

  it("keeps the Authorization header on a same-origin redirect", async () => {
    route((url) =>
      url === "https://a.example.com/pkg.tgz"
        ? make(302, "https://a.example.com/pkg-2.tgz")
        : make(200),
    );
    const res = await fetchArtifactGuarded(
      "https://a.example.com/pkg.tgz",
      { headers: { authorization: "Bearer registry-secret" } },
      budget,
    );
    expect(res.status).toBe(200);
    expect(calls[1].auth).toBe("Bearer registry-secret");
  });

  it("throws once the redirect chain exceeds maxHops", async () => {
    let n = 0;
    route(() => make(302, `https://a.example.com/hop-${n++}.tgz`));
    await expect(
      fetchArtifactGuarded("https://a.example.com/pkg.tgz", {}, budget, "artifact URL", 1),
    ).rejects.toThrow(/too many redirects/);
  });

  it("returns a 3xx that carries no Location for the caller to handle", async () => {
    route(() => make(302));
    const res = await fetchArtifactGuarded("https://a.example.com/pkg.tgz", {}, budget);
    expect(res.status).toBe(302);
    expect(calls).toHaveLength(1);
  });

  it("rejects a non-https initial URL before any fetch", async () => {
    route(() => make(200));
    await expect(
      fetchArtifactGuarded("http://a.example.com/pkg.tgz", {}, budget),
    ).rejects.toThrow(/https/);
    expect(calls).toHaveLength(0);
  });
});

describe("retryOnNetworkTimeout", () => {
  const timeout = () => new ResourceLimitError("network-timeout", "timed out");
  const noDelay = () => 0;

  it("retries a transient timeout and returns the eventual success", async () => {
    let calls = 0;
    const result = await retryOnNetworkTimeout(
      async () => {
        calls++;
        if (calls < 3) throw timeout();
        return "ok";
      },
      3,
      noDelay,
    );
    expect(result).toBe("ok");
    expect(calls).toBe(3);
  });

  it("throws the timeout after exhausting attempts", async () => {
    let calls = 0;
    await expect(
      retryOnNetworkTimeout(async () => {
        calls++;
        throw timeout();
      }, 3, noDelay),
    ).rejects.toBeInstanceOf(ResourceLimitError);
    expect(calls).toBe(3);
  });

  it("does NOT retry a non-timeout error (fails fast on a deterministic failure)", async () => {
    let calls = 0;
    await expect(
      retryOnNetworkTimeout(async () => {
        calls++;
        throw new Error("404 not found");
      }, 3, noDelay),
    ).rejects.toThrow("404 not found");
    expect(calls).toBe(1);
  });

  it("does not retry a non-network ResourceLimitError kind", async () => {
    let calls = 0;
    await expect(
      retryOnNetworkTimeout(async () => {
        calls++;
        throw new ResourceLimitError("max-file-bytes", "too big");
      }, 3, noDelay),
    ).rejects.toBeInstanceOf(ResourceLimitError);
    expect(calls).toBe(1);
  });

  it("applies the default backoff between attempts when no delay function is given", async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      const pending = retryOnNetworkTimeout(async () => {
        calls++;
        if (calls < 2) throw new ResourceLimitError("network-timeout", "timed out");
        return "ok";
      }); // default delayMs (200ms * attempt)
      await vi.advanceTimersByTimeAsync(200);
      await expect(pending).resolves.toBe("ok");
      expect(calls).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });
});
