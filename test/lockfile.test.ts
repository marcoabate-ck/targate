import { describe, expect, it } from "vitest";
import { extractLockfileArtifacts, LockfileParseError } from "../src/lockfile.js";
import { packagesFromLockfile } from "../src/install-plan.js";

// Regression (P0.1): parse failures and the conflicting-integrity tamper signal
// used to be swallowed into an empty artifact list, which the decision path
// then reported as "0 packages, all clean" — letting a corrupt or tampered
// lockfile install completely unvetted. They must now fail loudly.
describe("extractLockfileArtifacts fail-closed", () => {
  it("returns [] for a genuinely empty but valid lockfile (nothing to vet)", () => {
    expect(extractLockfileArtifacts("npm", '{"packages":{}}')).toEqual([]);
    expect(extractLockfileArtifacts("pnpm", "lockfileVersion: '9.0'\n")).toEqual([]);
  });

  it("throws LockfileParseError on an unparsable npm lockfile", () => {
    expect(() => extractLockfileArtifacts("npm", "{not valid json")).toThrow(LockfileParseError);
  });

  it("throws LockfileParseError on an unparsable pnpm lockfile", () => {
    expect(() => extractLockfileArtifacts("pnpm", "\tbad: [unclosed")).toThrow(LockfileParseError);
  });

  it("throws on conflicting integrity for the same npm name@version (tamper signal)", () => {
    const lock = JSON.stringify({
      packages: {
        "node_modules/foo": { version: "1.0.0", integrity: "sha512-AAA" },
        "node_modules/bar/node_modules/foo": { version: "1.0.0", integrity: "sha512-BBB" },
      },
    });
    expect(() => extractLockfileArtifacts("npm", lock)).toThrow(/conflicting integrity/i);
  });

  it("throws on conflicting integrity for the same pnpm name@version", () => {
    const lock = [
      "packages:",
      "  /foo@1.0.0:",
      "    resolution: {integrity: sha512-AAA}",
      "  /foo@1.0.0(bar@2.0.0):",
      "    resolution: {integrity: sha512-BBB}",
      "",
    ].join("\n");
    expect(() => extractLockfileArtifacts("pnpm", lock)).toThrow(/conflicting integrity/i);
  });

  it("propagates through packagesFromLockfile (so resolveInstallPlan fails closed)", () => {
    expect(() => packagesFromLockfile("npm", "{corrupt")).toThrow(LockfileParseError);
  });
});
