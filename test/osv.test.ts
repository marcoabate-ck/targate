import { describe, expect, it } from "vitest";
import { isMaliciousRecord } from "../src/osv.js";

describe("isMaliciousRecord", () => {
  it("flags OpenSSF MAL- records", () => {
    expect(isMaliciousRecord({ id: "MAL-2024-1234" })).toBe(true);
  });

  it("flags GHSA advisories that describe malware", () => {
    expect(
      isMaliciousRecord({
        id: "GHSA-hm6q-r2jc-cpqh",
        summary: "lodahs is malware",
        details: "All versions of this package contained malware.",
      }),
    ).toBe(true);
  });

  it("does not flag ordinary vulnerability advisories", () => {
    expect(
      isMaliciousRecord({
        id: "GHSA-jf85-cpcp-j695",
        summary: "Prototype Pollution in lodash",
        details: "Versions of lodash before 4.17.5 are vulnerable to prototype pollution.",
      }),
    ).toBe(false);
  });
});
