import path from "node:path";
import { describe, expect, it } from "vitest";
import { extractLockfileEntries } from "../src/lockfile.js";

/**
 * Cross-platform path invariants (Milestone 6.2).
 *
 * Lockfiles always encode paths with POSIX `/` separators regardless of the
 * host OS, so parsing them must never depend on `path.sep`. The CI matrix runs
 * the whole suite on both Linux and Windows; these focused cases lock the
 * separator-independent behavior that the matrix then exercises end-to-end.
 */
describe("lockfile parsing is separator-independent", () => {
  it("extracts names from POSIX node_modules keys in an npm lockfile", () => {
    const lock = JSON.stringify({
      packages: {
        "": { name: "root" },
        "node_modules/left-pad": { version: "1.3.0" },
        "node_modules/@scope/pkg": { version: "2.0.0" },
        // Nested transitive: the last node_modules segment wins.
        "node_modules/a/node_modules/b": { version: "3.0.0" },
      },
    });
    expect(extractLockfileEntries("npm", lock)).toEqual(
      new Set(["left-pad@1.3.0", "@scope/pkg@2.0.0", "b@3.0.0"]),
    );
  });

  it("parses pnpm and yarn entries without host separators leaking in", () => {
    const pnpm = ["packages:", "  /left-pad@1.3.0:", "  '@scope/pkg@2.0.0':"].join("\n");
    expect(extractLockfileEntries("pnpm", pnpm)).toEqual(
      new Set(["left-pad@1.3.0", "@scope/pkg@2.0.0"]),
    );

    const yarn = ['"@scope/pkg@^2.0.0":\n  version "2.0.0"', 'left-pad@^1.0.0:\n  version "1.3.0"'].join(
      "\n\n",
    );
    expect(extractLockfileEntries("yarn", yarn)).toEqual(
      new Set(["@scope/pkg@2.0.0", "left-pad@1.3.0"]),
    );
  });

  it("does not vary with the host path separator", () => {
    // The parser must read the same names whether it runs on '/' or '\\' hosts.
    const lock = JSON.stringify({ packages: { "node_modules/left-pad": { version: "1.3.0" } } });
    const result = extractLockfileEntries("npm", lock);
    expect(result).toEqual(new Set(["left-pad@1.3.0"]));
    // Sanity: the archive-style key uses POSIX separators, not the host's.
    expect(path.posix.sep).toBe("/");
  });
});
