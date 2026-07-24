import { execFile } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Routing/validation tests for the real CLI entry point (finding #8 of the
 * review — main() had zero coverage). Every case here fails fast before any
 * network, AI, or docker access.
 */

const CLI = path.resolve(__dirname, "..", "src", "cli.ts");

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(...args: string[]): Promise<CliRun> {
  return new Promise((resolve, reject) => {
    // Run the TS entry through `node --import tsx` rather than the
    // node_modules/.bin/tsx shim: on Windows the shim is a .cmd, which Node
    // refuses to spawn without shell:true (CVE-2024-27980), so execFile'ing
    // the bare path fails with ENOENT. Invoking node directly is portable.
    execFile(
      process.execPath,
      ["--import", "tsx", CLI, ...args],
      { timeout: 30_000 },
      (err, stdout, stderr) => {
        if (err && typeof err.code !== "number") return reject(err); // spawn failure, not exit code
        resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
      },
    );
  });
}

describe("cli routing and validation", () => {
  it("prints help and exits 0 with --help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate add <package>");
    expect(stdout).toContain("targate sandbox");
    expect(stdout).toContain("--fail-on-osv-error");
  });

  it("prints help and exits 1 with no arguments", async () => {
    const { code, stdout } = await runCli();
    expect(code).toBe(1);
    expect(stdout).toContain("gate every dependency before it runs");
  });

  // Regression: the standalone binaries embed a version and bug_report.yml asks
  // users to run `targate --version`, but the CLI had no such flag (it printed
  // "Unknown command: --version"). Surfaced by the release-binary dry-run.
  it("prints the version and exits 0 with --version / -v", async () => {
    for (const flag of ["--version", "-v"]) {
      const { code, stdout } = await runCli(flag);
      expect(code, flag).toBe(0);
      // package.json version on the src/tsx path (a semver-ish token).
      expect(stdout.trim(), flag).toMatch(/^\d+\.\d+\.\d+/);
    }
  });

  it("prints command-specific help", async () => {
    const { code, stdout } = await runCli("add", "--help");
    expect(code).toBe(0);
    expect(stdout).toContain("Usage:\n  targate add <package>");
    expect(stdout).toContain("--deep");
    expect(stdout).not.toContain("--network");
  });

  it("rejects package shorthand and suggests the intended command safely", async () => {
    const typo = await runCli("instal");
    expect(typo.code).toBe(1);
    expect(typo.stderr).toContain("Unknown command: instal");
    expect(typo.stderr).toContain("targate install");

    const packageName = await runCli("left-pad");
    expect(packageName.code).toBe(1);
    expect(packageName.stderr).toContain("Unknown command: left-pad");
  });

  it("rejects an option that belongs to another command", async () => {
    const { code, stderr } = await runCli("doctor", "--deep");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown option '--deep'");
  });

  it("rejects an unknown provider before doing any work", async () => {
    const { code, stderr } = await runCli("add", "left-pad", "--provider", "bogus");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown provider: bogus");
  });

  it("rejects an invalid sandbox --network value", async () => {
    const { code, stderr } = await runCli("sandbox", "left-pad", "--network", "bogus");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown --network value");
  });

  it("rejects an invalid policy format", async () => {
    const { code, stderr } = await runCli("policy", "init", "--format", "toml");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown policy format");
  });

  it("lists the agents subcommand in help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate agents init");
  });

  it("rejects an unknown agents format", async () => {
    const { code, stderr } = await runCli("agents", "init", "--format", "bogus");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown agent format");
  });

  it("rejects agents without the init subcommand", async () => {
    const { code, stderr } = await runCli("agents");
    expect(code).toBe(1);
    expect(stderr).toContain("Usage: targate agents init");
  });

  it("lists the install subcommand in help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate install");
    expect(stdout).toContain("--update-lockfile");
    expect(stdout).toContain("--allow-scripts");
  });

  it("lists the approve subcommand in help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate approve <package>");
  });

  it("rejects approve without a package spec", async () => {
    const { code, stderr } = await runCli("approve");
    expect(code).toBe(1);
    expect(stderr).toContain("Usage: targate approve <package>");
  });

  it("documents the --concurrency and --no-ai-batch flags", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("--concurrency");
    expect(stdout).toContain("--no-ai-batch");
  });

  it("lists the doctor and explain subcommands and the new flags in help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate doctor");
    expect(stdout).toContain("targate explain <package>");
    expect(stdout).toContain("--no-reputation");
    expect(stdout).toContain("--ping");
  });

  it("lists the diff and monitor subcommands and their flags in help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate diff");
    expect(stdout).toContain("targate monitor");
    expect(stdout).toContain("--fail-on");
    expect(stdout).toContain("--no-capture");
  });

  it("rejects diff without a package spec", async () => {
    const { code, stderr } = await runCli("diff");
    expect(code).toBe(1);
    expect(stderr).toContain("Usage: targate diff");
  });

  it("rejects diff with an unknown --fail-on level", async () => {
    const { code, stderr } = await runCli("diff", "lodash@1", "lodash@2", "--fail-on", "extreme");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown --fail-on level");
  });

  it("lists the history subcommand and the signing flags in help", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate history");
    expect(stdout).toContain("--sign");
    expect(stdout).toContain("--verify");
    expect(stdout).toContain("--preset");
  });

  it("lists the recommend subcommand and --limit in help; rejects a bare recommend", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate recommend");
    expect(stdout).toContain("--limit");
    const bare = await runCli("recommend");
    expect(bare.code).toBe(1);
    expect(bare.stderr).toContain("Usage: targate recommend");
  });

  it("rejects an invalid recommend --limit", async () => {
    const { code, stderr } = await runCli("recommend", "padding", "--limit", "zero");
    expect(code).toBe(1);
    expect(stderr).toContain("Invalid --limit");
  });

  it("lists the graph subcommand and its flags in help; rejects a bad --format", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate graph");
    expect(stdout).toContain("--only");
    expect(stdout).toContain("--why");
    const bad = await runCli("graph", "--format", "png");
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain("Unknown --format");
  });

  it("rejects an unknown policy preset and lists the available packs", async () => {
    const { code, stderr } = await runCli("policy", "init", "--preset", "bogus");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown policy preset");
    expect(stderr).toContain("strict");
    expect(stderr).toContain("react-native");
    expect(stderr).toContain("ai-agent");
  });

  it("rejects explain with neither a spec nor --last", async () => {
    const { code, stderr } = await runCli("explain");
    expect(code).toBe(1);
    expect(stderr).toContain("Usage: targate explain");
  });

  it("rejects explain with both a spec and --last", async () => {
    const { code, stderr } = await runCli("explain", "left-pad", "--last");
    expect(code).toBe(1);
    expect(stderr).toContain("Usage: targate explain");
  });

  it("documents the cache command and --no-cache flag", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("targate cache");
    expect(stdout).toContain("--no-cache");
  });

  it("rejects an unknown cache action", async () => {
    const { code, stderr } = await runCli("cache", "bogus");
    expect(code).toBe(1);
    expect(stderr).toContain("Usage: targate cache");
  });

  it("rejects an invalid cache --scope", async () => {
    const { code, stderr } = await runCli("cache", "info", "--scope", "nope");
    expect(code).toBe(1);
    expect(stderr).toContain("Unknown --scope");
  });

  it("runs `cache info` (no network) and prints the cache location", async () => {
    const { code, stdout } = await runCli("cache", "info", "--json");
    expect(code).toBe(0);
    const parsed = JSON.parse(stdout);
    expect(parsed.action).toBe("info");
    expect(parsed).toHaveProperty("path");
  });
}, 60_000);
