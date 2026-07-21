import { describe, expect, it } from "vitest";
import { assertSafeArtifactUrl, isPrivateHost } from "../src/network.js";

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
