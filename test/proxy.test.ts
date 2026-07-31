import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { writeFileSync } from "node:fs";
import { insecureRegistryHostAllowed } from "../src/network.js";
import { isLoopbackRemote, isNpmClient, parseRegistryPath, rewritePackumentTarballs, safeUpstreamUrl, Semaphore, singleFlight } from "../src/proxy.js";
import { ProxyVerdictCache, sha512Sri, type VerdictRecord } from "../src/proxy-cache.js";
import { readProxyUplinks, scopeOf, uplinkFor } from "../src/proxy-uplinks.js";
import { PendingApprovals } from "../src/proxy-approvals.js";
import { CA_COMMON_NAME, caInstallCommand, caUninstallCommand } from "../src/proxy-tls.js";
import { isLoopbackBindHost, migrateScopes, parseSpec, proxyCommand, removeNpmrcBlock } from "../src/commands/proxy.js";

const BEGIN = "# >>> targate proxy (managed — `targate proxy teardown` removes this)";
const END = "# <<< targate proxy";
const block = `${BEGIN}\nregistry=https://127.0.0.1:4873\nreplace-registry-host=npmjs\n${END}\n`;

describe("parseRegistryPath", () => {
  it("reads an unscoped packument request", () => {
    expect(parseRegistryPath("/is-odd")).toEqual({ name: "is-odd" });
  });

  it("reads a scoped packument request (percent-encoded slash)", () => {
    expect(parseRegistryPath("/@babel%2fcore")).toEqual({ name: "@babel/core" });
  });

  it("extracts name and version from an unscoped tarball", () => {
    expect(parseRegistryPath("/is-odd/-/is-odd-3.0.1.tgz")).toEqual({
      name: "is-odd",
      tarballVersion: "3.0.1",
    });
  });

  it("extracts name and version from a scoped tarball", () => {
    expect(parseRegistryPath("/@babel/core/-/core-7.24.0.tgz")).toEqual({
      name: "@babel/core",
      tarballVersion: "7.24.0",
    });
  });

  it("keeps hyphenated prerelease versions intact", () => {
    expect(parseRegistryPath("/next/-/next-14.0.0-canary.1.tgz")).toEqual({
      name: "next",
      tarballVersion: "14.0.0-canary.1",
    });
  });

  it("tolerates a leading registry origin in the URL", () => {
    expect(parseRegistryPath("http://localhost:4873/is-odd/-/is-odd-3.0.1.tgz")).toEqual({
      name: "is-odd",
      tarballVersion: "3.0.1",
    });
  });

  it("returns the name only when the tarball filename does not match the package", () => {
    // defensive: unexpected tarball layout must not be treated as a vettable version
    expect(parseRegistryPath("/is-odd/-/something-else.tgz")).toEqual({ name: "is-odd" });
  });

  it("returns null for an empty path", () => {
    expect(parseRegistryPath("/")).toBeNull();
  });
});

describe("removeNpmrcBlock", () => {
  it("leaves content without the managed block untouched", () => {
    const original = "registry=https://registry.npmjs.org\n//registry.npmjs.org/:_authToken=abc\n";
    expect(removeNpmrcBlock(original)).toBe(original);
  });

  it("strips the managed block while preserving surrounding entries", () => {
    const withBlock = `always-auth=true\n${block}`;
    expect(removeNpmrcBlock(withBlock)).toContain("always-auth=true");
    expect(removeNpmrcBlock(withBlock)).not.toContain("targate proxy");
    expect(removeNpmrcBlock(withBlock)).not.toContain("127.0.0.1:4873");
  });

  it("is idempotent", () => {
    const once = removeNpmrcBlock(`x=1\n${block}`);
    expect(removeNpmrcBlock(once)).toBe(once);
  });
});

describe("sha512Sri", () => {
  it("produces an SRI digest matching npm's dist.integrity format", () => {
    // echo -n "" | openssl dgst -sha512 -binary | openssl base64 -A
    expect(sha512Sri(Buffer.from(""))).toBe(
      "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==",
    );
  });

  it("changes when bytes change (a mutated tarball keys differently)", () => {
    expect(sha512Sri(Buffer.from("a"))).not.toBe(sha512Sri(Buffer.from("b")));
  });
});

describe("ProxyVerdictCache", () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), "targate-cache-"));
    file = path.join(dir, "verdicts.json");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("stores and retrieves a verdict by digest", () => {
    const cache = new ProxyVerdictCache(file);
    cache.set("sha512-AAA", { name: "x", version: "1.0.0", decision: "allow", summary: "ok", at: 1 });
    expect(cache.get("sha512-AAA")?.decision).toBe("allow");
    expect(cache.get("sha512-missing")).toBeUndefined();
    expect(cache.size).toBe(1);
  });

  it("persists to disk and reloads (survives a daemon restart)", () => {
    new ProxyVerdictCache(file).set("sha512-BBB", {
      name: "y",
      version: "2.0.0",
      decision: "block",
      summary: "bad",
      at: 2,
    });
    const reloaded = new ProxyVerdictCache(file);
    expect(reloaded.get("sha512-BBB")?.decision).toBe("block");
    expect(reloaded.size).toBe(1);
  });

  it("bounds growth by evicting the oldest entries", () => {
    const cache = new ProxyVerdictCache(file, 2);
    const rec = (n: string): VerdictRecord => ({ name: n, version: "1.0.0", decision: "allow", summary: "", at: 0 });
    cache.set("d1", rec("a"));
    cache.set("d2", rec("b"));
    cache.set("d3", rec("c")); // evicts d1
    expect(cache.size).toBe(2);
    expect(cache.get("d1")).toBeUndefined();
    expect(cache.get("d3")?.name).toBe("c");
  });
});

describe("insecureRegistryHostAllowed", () => {
  const saved = process.env.TARGATE_INSECURE_REGISTRY_HOSTS;
  afterEach(() => {
    if (saved === undefined) delete process.env.TARGATE_INSECURE_REGISTRY_HOSTS;
    else process.env.TARGATE_INSECURE_REGISTRY_HOSTS = saved;
  });
  it("is off unless the env var is set", () => {
    delete process.env.TARGATE_INSECURE_REGISTRY_HOSTS;
    expect(insecureRegistryHostAllowed("127.0.0.1")).toBe(false);
  });
  it("allows only listed hosts, case-insensitively", () => {
    process.env.TARGATE_INSECURE_REGISTRY_HOSTS = "127.0.0.1, Verdaccio.local";
    expect(insecureRegistryHostAllowed("127.0.0.1")).toBe(true);
    expect(insecureRegistryHostAllowed("verdaccio.local")).toBe(true);
    expect(insecureRegistryHostAllowed("evil.example")).toBe(false);
  });
});

describe("rewritePackumentTarballs", () => {
  const proxy = "https://127.0.0.1:4873";
  it("rewrites dist.tarball to a CLEAN canonical proxy path and reports the real URL via onEntry", () => {
    // GitHub Packages uses a non-/-/ download path — the real URL must survive
    // via the callback (not the URL) so the clean path stays lockfile-portable.
    const orig = "https://npm.pkg.github.com/download/@wts-paradigm/ui/0.8.0/e8a9";
    const doc = { name: "@wts-paradigm/ui", versions: { "0.8.0": { version: "0.8.0", dist: { tarball: orig } } } };
    const seen: Array<[string, string, string]> = [];
    const out = JSON.parse(
      rewritePackumentTarballs(JSON.stringify(doc), proxy, (n, v, u) => seen.push([n, v, u])),
    ) as typeof doc;
    const rewritten = out.versions["0.8.0"].dist.tarball;
    // Clean canonical path, NO query — so pnpm/yarn treat it as registry-derivable.
    expect(rewritten).toBe(`${proxy}/@wts-paradigm/ui/-/ui-0.8.0.tgz`);
    expect(new URL(rewritten).search).toBe("");
    expect(seen).toEqual([["@wts-paradigm/ui", "0.8.0", orig]]);
  });
  it("returns non-JSON unchanged", () => {
    expect(rewritePackumentTarballs("not json", proxy)).toBe("not json");
  });
});

describe("safeUpstreamUrl", () => {
  const npmjs = "https://registry.npmjs.org";
  it("keeps a normal request path on the intended origin", () => {
    expect(safeUpstreamUrl(npmjs, "/is-odd")).toBe("https://registry.npmjs.org/is-odd");
    expect(safeUpstreamUrl(npmjs, "/is-odd/-/is-odd-3.0.1.tgz")).toBe("https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz");
  });
  it("refuses a request-target that would leave the origin (SSRF via path)", () => {
    expect(() => safeUpstreamUrl(npmjs, "http://evil.example/x")).toThrow(/cross-origin/);
    expect(() => safeUpstreamUrl(npmjs, "//evil.example/x")).toThrow(/cross-origin/);
  });
});

describe("isLoopbackRemote", () => {
  it("accepts loopback addresses only", () => {
    expect(isLoopbackRemote("127.0.0.1")).toBe(true);
    expect(isLoopbackRemote("::1")).toBe(true);
    expect(isLoopbackRemote("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackRemote("10.0.0.5")).toBe(false);
    expect(isLoopbackRemote(undefined)).toBe(false);
  });
});

describe("isNpmClient", () => {
  // npm rewrites the tarball host itself (replace-registry-host); pnpm/yarn/bun
  // do not, so they must be classified as non-npm to get the dist.tarball rewrite.
  it("matches only npm's own user-agent", () => {
    expect(isNpmClient("npm/10.9.2 node/v22.13.0 darwin arm64 workspaces/false")).toBe(true);
  });
  it("does not misclassify pnpm/yarn (which embed npm/? later in their UA)", () => {
    expect(isNpmClient("pnpm/11.1.2 npm/? node/v22.13.0 darwin arm64")).toBe(false);
    expect(isNpmClient("yarn/1.22.22 npm/? node/v22.13.0")).toBe(false);
  });
  it("treats bun and unknown/absent clients as non-npm (safe: they get the rewrite)", () => {
    expect(isNpmClient("Bun/1.3.9")).toBe(false);
    expect(isNpmClient(undefined)).toBe(false);
    expect(isNpmClient("")).toBe(false);
  });
});

describe("Semaphore", () => {
  it("bounds concurrency and releases waiters in FIFO order", async () => {
    const sem = new Semaphore(1);
    await sem.acquire();
    let secondAcquired = false;
    const second = sem.acquire().then(() => {
      secondAcquired = true;
    });
    // the second acquire must block while the single slot is held
    await Promise.resolve();
    expect(secondAcquired).toBe(false);
    sem.release();
    await second;
    expect(secondAcquired).toBe(true);
  });
});

describe("isLoopbackBindHost", () => {
  it("accepts loopback hosts only", () => {
    for (const h of ["127.0.0.1", "::1", "localhost"]) expect(isLoopbackBindHost(h)).toBe(true);
    for (const h of ["0.0.0.0", "192.168.1.5", "10.0.0.1", "::", "example.com"]) expect(isLoopbackBindHost(h)).toBe(false);
  });
});

describe("proxy bind guard", () => {
  const savedOptIn = process.env.TARGATE_ALLOW_REMOTE_BIND;
  afterEach(() => {
    vi.restoreAllMocks();
    if (savedOptIn === undefined) delete process.env.TARGATE_ALLOW_REMOTE_BIND;
    else process.env.TARGATE_ALLOW_REMOTE_BIND = savedOptIn;
  });

  it("refuses a non-loopback bind without the opt-in and never starts the server", async () => {
    delete process.env.TARGATE_ALLOW_REMOTE_BIND;
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    // foreground:true means a passing guard would fall through to runForeground;
    // the refusal must short-circuit with exit 1 before any listen.
    const code = await proxyCommand(["start"], { port: "4990", host: "0.0.0.0", foreground: true } as never);
    expect(code).toBe(1);
    expect(err.mock.calls.flat().join(" ")).toContain("Refusing to bind 0.0.0.0");
  });

  it("allows a loopback bind subcommand past the guard (setup fails later, not on the guard)", async () => {
    // setup with the default loopback host must not be rejected by the guard;
    // it may still fail for other reasons (openssl/daemon), which is not code 1
    // from the guard path — we only assert the guard did not print a refusal.
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    await proxyCommand(["status"], { port: "4990" } as never); // status never binds
    expect(err.mock.calls.flat().join(" ")).not.toContain("Refusing to bind");
    log.mockRestore();
  });
});

describe("proxy setup — unsupported clients", () => {
  let dir: string;
  let cwd: string;
  beforeEach(() => {
    cwd = process.cwd();
    dir = mkdtempSync(path.join(tmpdir(), "targate-setup-"));
    process.chdir(dir);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    process.chdir(cwd);
    rmSync(dir, { recursive: true, force: true });
  });

  it("refuses bun before touching anything (would poison bun.lock)", async () => {
    writeFileSync(path.join(dir, "bun.lock"), "");
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await proxyCommand(["setup"], { port: "4990" } as never);
    expect(code).toBe(1);
    expect(err.mock.calls.flat().join(" ")).toMatch(/does not support bun/);
  });

  it("refuses yarn-classic (bare yarn.lock)", async () => {
    writeFileSync(path.join(dir, "yarn.lock"), "");
    const err = vi.spyOn(console, "error").mockImplementation(() => {});
    const code = await proxyCommand(["setup"], { port: "4990" } as never);
    expect(code).toBe(1);
    expect(err.mock.calls.flat().join(" ")).toMatch(/does not support yarn-classic/);
  });
});

describe("singleFlight", () => {
  it("runs fn once for concurrent callers on the same key and shares the result", async () => {
    const map = new Map<string, Promise<number>>();
    let calls = 0;
    let release!: (n: number) => void;
    const fn = (): Promise<number> => {
      calls++;
      return new Promise<number>((resolve) => {
        release = resolve;
      });
    };
    const a = singleFlight(map, "k", fn);
    const b = singleFlight(map, "k", fn);
    const c = singleFlight(map, "k", fn);
    expect(calls).toBe(1); // coalesced onto one invocation
    expect(map.size).toBe(1);
    release(42);
    expect(await Promise.all([a, b, c])).toEqual([42, 42, 42]);
  });

  it("does not coalesce different keys", async () => {
    const map = new Map<string, Promise<string>>();
    let calls = 0;
    const fn = (v: string) => (): Promise<string> => {
      calls++;
      return Promise.resolve(v);
    };
    const [x, y] = await Promise.all([singleFlight(map, "a", fn("a")), singleFlight(map, "b", fn("b"))]);
    expect([x, y]).toEqual(["a", "b"]);
    expect(calls).toBe(2);
  });

  it("clears the entry after settle so a later call re-runs fn", async () => {
    const map = new Map<string, Promise<number>>();
    let calls = 0;
    const fn = (): Promise<number> => {
      calls++;
      return Promise.resolve(calls);
    };
    expect(await singleFlight(map, "k", fn)).toBe(1);
    expect(map.size).toBe(0); // removed once settled
    expect(await singleFlight(map, "k", fn)).toBe(2); // fresh run
  });

  it("propagates rejection to all callers and clears the entry", async () => {
    const map = new Map<string, Promise<number>>();
    let calls = 0;
    const fn = (): Promise<number> => {
      calls++;
      return Promise.reject(new Error("boom"));
    };
    const a = singleFlight(map, "k", fn);
    const b = singleFlight(map, "k", fn);
    expect(calls).toBe(1);
    await expect(a).rejects.toThrow("boom");
    await expect(b).rejects.toThrow("boom");
    expect(map.size).toBe(0); // cleared even on failure, so a retry re-runs
  });
});

describe("proxy uplinks", () => {
  it("extracts the scope of a package name", () => {
    expect(scopeOf("@acme/pkg")).toBe("@acme");
    expect(scopeOf("@acme")).toBe("@acme");
    expect(scopeOf("lodash")).toBeUndefined();
  });

  it("matches a package to its scope uplink", () => {
    const uplinks = [{ scope: "@acme", upstream: "https://npm.acme.example" }];
    expect(uplinkFor("@acme/pkg", uplinks)?.upstream).toBe("https://npm.acme.example");
    expect(uplinkFor("@other/pkg", uplinks)).toBeUndefined();
    expect(uplinkFor("lodash", uplinks)).toBeUndefined();
  });

  it("reads, filters, and normalizes the uplinks file", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "targate-uplinks-"));
    const file = path.join(dir, "uplinks.json");
    try {
      writeFileSync(
        file,
        JSON.stringify([
          { scope: "@acme", upstream: "https://npm.acme.example/" }, // trailing slash normalized
          { scope: "no-at", upstream: "https://x" }, // dropped: scope lacks @
          { scope: "@bad" }, // dropped: no upstream
          "garbage", // dropped: not an object
        ]),
      );
      const uplinks = readProxyUplinks(file);
      expect(uplinks).toEqual([{ scope: "@acme", upstream: "https://npm.acme.example" }]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns an empty list when the file is absent", () => {
    expect(readProxyUplinks(path.join(tmpdir(), "targate-no-such-uplinks.json"))).toEqual([]);
  });
});

describe("CA trust commands", () => {
  it("builds an install command that references the CA path", () => {
    const cmd = caInstallCommand("/tmp/ca.pem");
    expect(cmd.command.length).toBeGreaterThan(0);
    expect(cmd.manual).toContain("/tmp/ca.pem");
    expect(typeof cmd.sudo).toBe("boolean");
  });

  it("builds an uninstall command that targets the CA for removal", () => {
    const cmd = caUninstallCommand("/tmp/ca.pem");
    if (process.platform === "linux") {
      // Debian/Ubuntu removes the installed cert file, then refreshes the store —
      // there is no "delete by common name", so the filename is what identifies it.
      expect(cmd.manual).toContain("targate-local-ca.crt");
      expect(cmd.manual).toContain("update-ca-certificates");
    } else {
      // macOS (security) and Windows (certutil) delete the cert by its common name.
      expect(cmd.manual).toContain(CA_COMMON_NAME);
    }
  });
});

describe("parseSpec", () => {
  it("splits name@version, including scoped names", () => {
    expect(parseSpec("lodash@4.17.21")).toEqual({ name: "lodash", version: "4.17.21" });
    expect(parseSpec("@scope/pkg@1.0.0")).toEqual({ name: "@scope/pkg", version: "1.0.0" });
  });
  it("rejects specs without a version", () => {
    expect(parseSpec("lodash")).toBeNull();
    expect(parseSpec("@scope/pkg")).toBeNull();
    expect(parseSpec(undefined)).toBeNull();
  });
});

describe("PendingApprovals", () => {
  it("resolves a hold when a matching decision arrives", async () => {
    const p = new PendingApprovals();
    const held = p.register("digest1", "core-js", "3.36.0", 1000);
    expect(p.size).toBe(1);
    expect(p.list()).toEqual([{ name: "core-js", version: "3.36.0", since: 1000 }]);
    expect(p.decide("core-js", "3.36.0", "approve")).toBe(1);
    await expect(held).resolves.toBe("approve");
    expect(p.size).toBe(0);
  });

  it("times out a hold that is never decided", async () => {
    const p = new PendingApprovals(16, 25);
    await expect(p.register("d", "x", "1.0.0", 0)).resolves.toBe("timeout");
  });

  it("reports capacity at the concurrency cap", () => {
    const p = new PendingApprovals(1, 60_000);
    void p.register("d1", "a", "1.0.0", 0);
    expect(p.atCapacity).toBe(true);
    expect(p.decide("a", "1.0.0", "deny")).toBe(1);
  });

  it("deduplicates concurrent holds for the same digest onto one decision", async () => {
    const p = new PendingApprovals();
    const a = p.register("same", "x", "1.0.0", 0);
    const b = p.register("same", "x", "1.0.0", 0);
    expect(p.decide("x", "1.0.0", "approve")).toBe(1);
    await expect(a).resolves.toBe("approve");
    await expect(b).resolves.toBe("approve");
  });
});

describe("migrateScopes", () => {
  it("turns private per-scope registries into uplinks with captured auth, skipping npmjs/local", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "targate-migrate-"));
    try {
      writeFileSync(
        path.join(dir, ".npmrc"),
        [
          "@acme:registry=https://npm.acme.example/",
          "//npm.acme.example/:_authToken=SECRET",
          "@pub:registry=https://registry.npmjs.org/", // skipped: npmjs
          "@local:registry=http://127.0.0.1:9999/", // skipped: loopback
        ].join("\n"),
      );
      const uplinks = migrateScopes(dir, "https://127.0.0.1:4873");
      const acme = uplinks.find((u) => u.scope === "@acme");
      expect(acme).toEqual({ scope: "@acme", upstream: "https://npm.acme.example", auth: "Bearer SECRET" });
      expect(uplinks.find((u) => u.scope === "@pub")).toBeUndefined();
      expect(uplinks.find((u) => u.scope === "@local")).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
