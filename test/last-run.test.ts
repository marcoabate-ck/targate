import { chmod, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  LAST_RUN_SCHEMA_VERSION,
  LastRunError,
  lastRunPath,
  readLastRun,
  writeLastRun,
  type LastRunPackage,
} from "../src/last-run.js";
import { computeSecurityScore } from "../src/score.js";
import { makeSignals } from "./helpers.js";

let dir: string;

function makePackage(): LastRunPackage {
  const signals = makeSignals();
  return {
    metadata: {
      name: "example",
      version: "1.0.0",
      maintainers: ["alice"],
      tarballUrl: "https://reg/example-1.0.0.tgz",
      scripts: {},
      dependencyCount: 0,
      directDependencies: [],
      registryReputation: { hasProvenance: false },
    },
    signals,
    assessment: {
      risk: "low",
      decision: "allow",
      summary: "fine",
      reasons: ["clean"],
      recommendedAction: "install",
      source: "rules",
    },
    score: computeSecurityScore(signals),
  };
}

beforeEach(async () => {
  dir = await mkdtemp(path.join(tmpdir(), "targate-lastrun-"));
});

afterEach(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("writeLastRun / readLastRun", () => {
  it("round-trips a run record", async () => {
    await writeLastRun("add", [makePackage()], dir);
    const record = await readLastRun(dir);
    expect(record.schemaVersion).toBe(LAST_RUN_SCHEMA_VERSION);
    expect(record.command).toBe("add");
    expect(record.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(record.packages).toHaveLength(1);
    expect(record.packages[0].metadata.name).toBe("example");
    expect(record.packages[0].score.total).toBeGreaterThan(0);
  });

  it("leaves no .tmp files behind (atomic write)", async () => {
    await writeLastRun("approve", [makePackage()], dir);
    const files = await readdir(path.join(dir, ".targate"));
    expect(files).toEqual(["last-run.json"]);
  });

  it("overwrites the previous record", async () => {
    await writeLastRun("add", [makePackage()], dir);
    await writeLastRun("approve", [makePackage()], dir);
    expect((await readLastRun(dir)).command).toBe("approve");
  });

  it("swallows write errors — recording must never fail the gate", async () => {
    const blocked = path.join(dir, "blocked");
    await mkdir(blocked, { mode: 0o555 });
    await expect(writeLastRun("add", [makePackage()], blocked)).resolves.toBeUndefined();
    await chmod(blocked, 0o755); // restore so cleanup works
  });

  it("errors actionably when no record exists", async () => {
    await expect(readLastRun(dir)).rejects.toThrow(LastRunError);
    await expect(readLastRun(dir)).rejects.toThrow(/no recorded run found/);
  });

  it("errors actionably on corrupt JSON", async () => {
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(lastRunPath(dir), "{not json");
    await expect(readLastRun(dir)).rejects.toThrow(/corrupt/);
  });

  it("errors actionably on a different schema version", async () => {
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      lastRunPath(dir),
      JSON.stringify({ schemaVersion: 999, command: "add", timestamp: "x", packages: [{}] }),
    );
    await expect(readLastRun(dir)).rejects.toThrow(/different targate version/);
  });
});
