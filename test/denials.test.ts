import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getDenial,
  isDenialApplicable,
  loadDenials,
  recordDenial,
  removeDenial,
} from "../src/denials.js";
import { loadApprovals, recordApproval, removeApproval } from "../src/approvals.js";

let dir: string;
let cwd: string;

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-denials-"));
  process.chdir(dir);
});
afterEach(async () => {
  vi.restoreAllMocks();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

describe("isDenialApplicable", () => {
  it("accepts a well-formed record and rejects junk", () => {
    expect(isDenialApplicable({ deniedAt: "2026-07-20T00:00:00.000Z" })).toBe(true);
    expect(isDenialApplicable({ deniedAt: "2026-07-20T00:00:00.000Z", reason: "no" })).toBe(true);
    expect(isDenialApplicable({ deniedAt: "not-a-date" })).toBe(false);
    expect(isDenialApplicable({ reason: "no" })).toBe(false);
    expect(isDenialApplicable(null)).toBe(false);
    expect(isDenialApplicable([])).toBe(false);
    expect(isDenialApplicable({ deniedAt: "2026-07-20T00:00:00.000Z", reason: 5 })).toBe(false);
  });
});

describe("recordDenial / loadDenials / getDenial", () => {
  it("round-trips a denial through .targate/denials.json", async () => {
    const record = await recordDenial("evil", "1.2.3", dir, { reason: "malware" });
    expect(record.reason).toBe("malware");
    expect(existsSync(path.join(dir, ".targate", "denials.json"))).toBe(true);

    const map = await loadDenials(dir);
    expect(getDenial(map, "evil", "1.2.3")).toMatchObject({ reason: "malware" });
    expect(getDenial(map, "evil", "9.9.9")).toBeNull(); // version-specific
  });

  it("keeps entries sorted and merges multiple records", async () => {
    await recordDenial("zeta", "1.0.0", dir);
    await recordDenial("alpha", "1.0.0", dir);
    const raw = await readFile(path.join(dir, ".targate", "denials.json"), "utf8");
    expect(raw.indexOf("alpha@1.0.0")).toBeLessThan(raw.indexOf("zeta@1.0.0"));
  });

  it("ignores malformed entries on load without throwing", async () => {
    await mkdir(path.join(dir, ".targate"), { recursive: true });
    await writeFile(
      path.join(dir, ".targate", "denials.json"),
      JSON.stringify({ "good@1.0.0": { deniedAt: "2026-07-20T00:00:00.000Z" }, "bad@1.0.0": { nope: true } }),
    );
    vi.spyOn(console, "error").mockImplementation(() => {});
    const map = await loadDenials(dir);
    expect(getDenial(map, "good", "1.0.0")).not.toBeNull();
    expect(getDenial(map, "bad", "1.0.0")).toBeNull();
  });
});

describe("removeDenial", () => {
  it("removes an entry and reports whether one existed", async () => {
    await recordDenial("evil", "1.0.0", dir);
    expect(await removeDenial("evil", "1.0.0", dir)).toBe(true);
    expect(await removeDenial("evil", "1.0.0", dir)).toBe(false);
    expect(getDenial(await loadDenials(dir), "evil", "1.0.0")).toBeNull();
  });

  it("returns false when no denials file exists", async () => {
    expect(await removeDenial("x", "1.0.0", dir)).toBe(false);
  });
});

describe("approval/denial mutual exclusion", () => {
  it("removeApproval clears an approval by key", async () => {
    await recordApproval("pkg", "1.0.0", "no-scripts", dir);
    expect(await removeApproval("pkg", "1.0.0", dir)).toBe(true);
    expect((await loadApprovals(dir))["pkg@1.0.0"]).toBeUndefined();
  });
});
