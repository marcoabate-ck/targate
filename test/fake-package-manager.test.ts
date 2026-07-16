import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { gateInstall } from "../src/installer.js";

/**
 * Fake package-manager integration (Milestone 6.2).
 *
 * These drive `gateInstall` against a REAL spawned child process standing in
 * for npm/pnpm/yarn, so the exit-code contract is exercised end-to-end rather
 * than mocked: a zero exit is reported as installed, and a non-zero exit is
 * propagated verbatim and never reported as success.
 */

let dir: string;

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

/** Write a fake package-manager script that records its argv and exits with `code`. */
async function fakePackageManager(exitCode: number): Promise<{ command: string[]; markerFile: string }> {
  dir = await mkdtemp(path.join(tmpdir(), "targate-fake-pm-"));
  const script = path.join(dir, "fake-pm.mjs");
  const markerFile = path.join(dir, "argv.json");
  await writeFile(
    script,
    [
      'import { writeFileSync } from "node:fs";',
      `writeFileSync(${JSON.stringify(markerFile)}, JSON.stringify(process.argv.slice(2)));`,
      `process.exit(${exitCode});`,
    ].join("\n"),
  );
  return { command: [process.execPath, script, "add", "left-pad@1.3.0"], markerFile };
}

describe("gateInstall against a real package-manager process", () => {
  it("reports installed when the package manager exits 0, and actually ran it", async () => {
    const { command, markerFile } = await fakePackageManager(0);

    const result = await gateInstall("allow", "npm", "left-pad@1.3.0", {
      assumeYes: true,
      commands: { normal: command, noScripts: command },
    });

    expect(result).toMatchObject({ status: "installed", mode: "normal", installed: true, command });
    expect(existsSync(markerFile)).toBe(true);
    expect(JSON.parse(await readFile(markerFile, "utf8"))).toEqual(["add", "left-pad@1.3.0"]);
  });

  it("propagates a non-zero exit code as a failed install, never as success", async () => {
    const { command } = await fakePackageManager(3);

    const result = await gateInstall("allow", "npm", "left-pad@1.3.0", {
      assumeYes: true,
      commands: { normal: command, noScripts: command },
    });

    expect(result).toMatchObject({ status: "failed", exitCode: 3, installed: false, command });
  });

  it("fails (never installs) when the package-manager binary cannot be spawned", async () => {
    const result = await gateInstall("allow", "npm", "left-pad@1.3.0", {
      assumeYes: true,
      commands: {
        normal: [path.join(tmpdir(), "targate-nonexistent-pm-binary"), "add", "left-pad@1.3.0"],
        noScripts: ["x"],
      },
    });

    expect(result.status).toBe("failed");
    expect(result.installed).toBe(false);
  });
});
