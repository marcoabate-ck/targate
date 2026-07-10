import { execFile } from "node:child_process";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Routing/validation tests for the real CLI entry point (finding #8 of the
 * review — main() had zero coverage). Every case here fails fast before any
 * network, AI, or docker access.
 */

const CLI = path.resolve(__dirname, "..", "src", "cli.ts");
const TSX = path.resolve(__dirname, "..", "node_modules", ".bin", "tsx");

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(...args: string[]): Promise<CliRun> {
  return new Promise((resolve, reject) => {
    execFile(TSX, [CLI, ...args], { timeout: 30_000 }, (err, stdout, stderr) => {
      if (err && typeof err.code !== "number") return reject(err); // spawn failure, not exit code
      resolve({ code: err ? (err.code as number) : 0, stdout, stderr });
    });
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
    expect(stdout).toContain("--frozen-lockfile");
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

  it("accepts --concurrency without error on a rules-only dry run", async () => {
    // Rules-only + dry-run: no install; just confirm the flag parses/threads.
    const { code } = await runCli("add", "left-pad@1.3.0", "--no-ai", "--dry-run", "--concurrency", "8");
    expect(code).toBe(0);
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
