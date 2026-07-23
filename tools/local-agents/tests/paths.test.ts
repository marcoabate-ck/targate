import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { rm } from "node:fs/promises";
import { isInside, isWithinScopes, violatingPaths } from "../src/paths.js";

let dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.map((d) => rm(d, { recursive: true, force: true })));
  dirs = [];
});

async function temp(): Promise<string> {
  const d = await mkdtemp(path.join(tmpdir(), "la-paths-"));
  dirs.push(d);
  return d;
}

describe("isInside", () => {
  it("accepts a child and the root itself", async () => {
    const root = await temp();
    expect(isInside(root, path.join(root, "a/b.ts"))).toBe(true);
    expect(isInside(root, root)).toBe(true);
  });
  it("rejects traversal outside the root", async () => {
    const root = await temp();
    expect(isInside(root, path.join(root, "../escape"))).toBe(false);
    expect(isInside(root, "/etc/passwd")).toBe(false);
  });
  it("rejects a symlink that escapes the root", async () => {
    const root = await temp();
    const outside = await temp();
    await writeFile(path.join(outside, "secret.txt"), "x");
    await mkdir(path.join(root, "sub"), { recursive: true });
    const link = path.join(root, "sub", "link");
    await symlink(outside, link);
    // Resolving the symlink lands outside root → rejected.
    expect(isInside(root, path.join(link, "secret.txt"))).toBe(false);
  });
});

describe("scopes", () => {
  it("checks membership across multiple scopes", async () => {
    const a = await temp();
    const b = await temp();
    expect(isWithinScopes([a, b], path.join(b, "x"))).toBe(true);
    expect(isWithinScopes([a, b], "/nope")).toBe(false);
  });
  it("reports violating paths", async () => {
    const root = await temp();
    const bad = path.join(root, "../outside.ts");
    const good = path.join(root, "in.ts");
    expect(violatingPaths([root], [good, bad])).toEqual([bad]);
  });
});
