import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { checkTarballIntegrity } from "../src/quarantine.js";

const bytes = Buffer.from("targate tarball bytes");
const sha512 = createHash("sha512").update(bytes).digest("base64");
const sha1hex = createHash("sha1").update(bytes).digest("hex");

describe("checkTarballIntegrity", () => {
  it("passes when the sha512 SRI matches", () => {
    const result = checkTarballIntegrity(bytes, { integrity: `sha512-${sha512}` });
    expect(result.ok).toBe(true);
    expect(result.algorithm).toBe("sha512");
  });

  it("fails when the downloaded bytes differ from the SRI", () => {
    const result = checkTarballIntegrity(Buffer.from("substituted content"), {
      integrity: `sha512-${sha512}`,
    });
    expect(result.ok).toBe(false);
    expect(result.algorithm).toBe("sha512");
    expect(result.actual).not.toBe(result.expected);
  });

  it("prefers the strongest algorithm in a multi-entry SRI", () => {
    const badSha1 = createHash("sha1").update(Buffer.from("other")).digest("base64");
    // sha512 valid, sha1 wrong: the sha512 entry must win.
    const result = checkTarballIntegrity(bytes, {
      integrity: `sha1-${badSha1} sha512-${sha512}`,
    });
    expect(result.ok).toBe(true);
    expect(result.algorithm).toBe("sha512");
  });

  it("falls back to the legacy sha1 shasum when no SRI is present", () => {
    expect(checkTarballIntegrity(bytes, { shasum: sha1hex }).ok).toBe(true);
    expect(checkTarballIntegrity(Buffer.from("evil"), { shasum: sha1hex }).ok).toBe(false);
  });

  it("is lenient when the registry provided no checksum at all", () => {
    const result = checkTarballIntegrity(bytes, {});
    expect(result.ok).toBe(true);
    expect(result.algorithm).toBe("none");
  });
});
