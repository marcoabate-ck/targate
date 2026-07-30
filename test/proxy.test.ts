import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { writeFileSync } from "node:fs";
import { parseRegistryPath, Semaphore } from "../src/proxy.js";
import { ProxyVerdictCache, sha512Sri, type VerdictRecord } from "../src/proxy-cache.js";
import { readProxyUplinks, scopeOf, uplinkFor } from "../src/proxy-uplinks.js";
import { PendingApprovals } from "../src/proxy-approvals.js";
import { CA_COMMON_NAME, caInstallCommand, caUninstallCommand } from "../src/proxy-tls.js";
import { migrateScopes, parseSpec, removeNpmrcBlock } from "../src/commands/proxy.js";

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

  it("builds an uninstall command that targets the CA by common name", () => {
    const cmd = caUninstallCommand("/tmp/ca.pem");
    expect(cmd.manual).toContain(CA_COMMON_NAME);
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
