import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  authHeaderForUrl,
  DEFAULT_REGISTRY,
  isInternalScope,
  loadNpmrc,
  parseNpmrc,
  resetNpmrcCacheForTests,
  resolveRegistry,
  type NpmrcConfig,
} from "../src/npmrc.js";

afterEach(() => {
  resetNpmrcCacheForTests();
  vi.unstubAllEnvs();
});

function config(entries: Record<string, string>): NpmrcConfig {
  return { entries, files: [] };
}

describe("parseNpmrc", () => {
  it("parses key=value lines, skipping comments and blanks", () => {
    const entries = parseNpmrc(
      [
        "# a comment",
        "; another comment",
        "",
        "registry=https://npm.acme.com/",
        "@acme:registry = https://npm.acme.com/private/",
        "//npm.acme.com/:_authToken=secret-token",
      ].join("\n"),
    );
    expect(entries.registry).toBe("https://npm.acme.com/");
    expect(entries["@acme:registry"]).toBe("https://npm.acme.com/private/");
    expect(entries["//npm.acme.com/:_authToken"]).toBe("secret-token");
  });

  it("strips quotes and expands ${ENV} references", () => {
    const entries = parseNpmrc('//npm.acme.com/:_authToken="${ACME_TOKEN}"', {
      ACME_TOKEN: "tok-123",
    } as NodeJS.ProcessEnv);
    expect(entries["//npm.acme.com/:_authToken"]).toBe("tok-123");
  });

  it("drops entries whose env var is unset (never sends a literal ${VAR})", () => {
    const entries = parseNpmrc("//npm.acme.com/:_authToken=${MISSING_TOKEN}", {} as NodeJS.ProcessEnv);
    expect(entries["//npm.acme.com/:_authToken"]).toBeUndefined();
  });
});

describe("loadNpmrc", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-npmrc-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("reads the project .npmrc", async () => {
    await writeFile(path.join(dir, ".npmrc"), "@acme:registry=https://npm.acme.com\n");
    const cfg = loadNpmrc(dir, {} as NodeJS.ProcessEnv);
    expect(cfg.entries["@acme:registry"]).toBe("https://npm.acme.com");
    expect(cfg.files.some((f) => f.startsWith(dir))).toBe(true);
  });

  it("returns an empty config when no .npmrc exists (and never throws)", async () => {
    const cfg = loadNpmrc(path.join(dir, "nowhere"), {} as NodeJS.ProcessEnv);
    expect(typeof cfg.entries).toBe("object");
  });
});

describe("resolveRegistry", () => {
  it("scope rule wins over global override, which wins over the default", () => {
    const cfg = config({
      registry: "https://mirror.acme.com/",
      "@acme:registry": "https://npm.acme.com/private/",
    });
    expect(resolveRegistry("@acme/lib", cfg)).toEqual({
      url: "https://npm.acme.com/private",
      source: "scope",
      scope: "@acme",
    });
    expect(resolveRegistry("lodash", cfg)).toEqual({
      url: "https://mirror.acme.com",
      source: "global",
    });
    expect(resolveRegistry("lodash", config({}))).toEqual({
      url: DEFAULT_REGISTRY,
      source: "default",
    });
  });

  it("a scoped package without a scope rule follows the global/default chain", () => {
    expect(resolveRegistry("@types/node", config({})).source).toBe("default");
    expect(resolveRegistry("@types/node", config({ registry: "https://m.x.com" })).source).toBe(
      "global",
    );
  });

  it("an explicit registry= pointing at npmjs stays 'default'", () => {
    expect(resolveRegistry("lodash", config({ registry: `${DEFAULT_REGISTRY}/` })).source).toBe(
      "default",
    );
  });
});

describe("authHeaderForUrl (nerf-dart)", () => {
  const cfg = config({
    "//npm.acme.com/:_authToken": "root-token",
    "//npm.acme.com/private/:_authToken": "private-token",
    "//basic.acme.com/:_auth": "cHJlLWVuY29kZWQ=",
    "//userpass.acme.com/:username": "alice",
    "//userpass.acme.com/:_password": Buffer.from("s3cret").toString("base64"),
  });

  it("matches the most specific path prefix first", () => {
    expect(authHeaderForUrl("https://npm.acme.com/private/@acme/lib", cfg)).toBe(
      "Bearer private-token",
    );
    expect(authHeaderForUrl("https://npm.acme.com/@acme/lib", cfg)).toBe("Bearer root-token");
    // Tarball URLs under the registry path inherit the registry credential.
    expect(authHeaderForUrl("https://npm.acme.com/private/lib/-/lib-1.0.0.tgz", cfg)).toBe(
      "Bearer private-token",
    );
  });

  it("supports _auth (pre-encoded) and username+_password (base64 password)", () => {
    expect(authHeaderForUrl("https://basic.acme.com/pkg", cfg)).toBe("Basic cHJlLWVuY29kZWQ=");
    expect(authHeaderForUrl("https://userpass.acme.com/pkg", cfg)).toBe(
      `Basic ${Buffer.from("alice:s3cret").toString("base64")}`,
    );
  });

  it("returns undefined for hosts without credentials and for invalid URLs", () => {
    expect(authHeaderForUrl("https://registry.npmjs.org/lodash", cfg)).toBeUndefined();
    expect(authHeaderForUrl("not a url", cfg)).toBeUndefined();
  });

  // Regression (P1.3): never transmit a credential over cleartext, even if a
  // packument points dist.tarball at an http URL on the token's host.
  it("never returns a credential for an http (cleartext) URL", () => {
    expect(authHeaderForUrl("http://npm.acme.com/private/@acme/lib", cfg)).toBeUndefined();
    expect(authHeaderForUrl("http://npm.acme.com/private/lib/-/lib-1.0.0.tgz", cfg)).toBeUndefined();
  });
});

describe("isInternalScope", () => {
  it("matches only listed scopes", () => {
    expect(isInternalScope("@acme/lib", ["@acme"])).toBe(true);
    expect(isInternalScope("@other/lib", ["@acme"])).toBe(false);
    expect(isInternalScope("lodash", ["@acme"])).toBe(false);
    expect(isInternalScope("@acme/lib", undefined)).toBe(false);
    expect(isInternalScope("@acme/lib", [])).toBe(false);
  });
});
