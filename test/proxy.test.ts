import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { parseRegistryPath } from "../src/proxy.js";
import { ProxyVerdictCache, sha512Sri } from "../src/proxy-cache.js";
import { removeNpmrcBlock } from "../src/commands/proxy.js";

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
});
