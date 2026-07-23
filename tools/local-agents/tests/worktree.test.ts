import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  cleanupWorktrees,
  createWorktree,
  isDirty,
  listWorktrees,
  worktreeBranch,
} from "../src/worktree.js";

const exec = promisify(execFile);
let repo: string;

async function git(args: string[], cwd = repo): Promise<void> {
  await exec("git", args, { cwd });
}

beforeEach(async () => {
  repo = await mkdtemp(path.join(tmpdir(), "la-wt-"));
  await git(["init", "-b", "main"]);
  await git(["config", "user.email", "t@example.com"]);
  await git(["config", "user.name", "Test"]);
  await writeFile(path.join(repo, "file.txt"), "hello\n");
  await git(["add", "."]);
  await git(["commit", "-m", "init"]);
});
afterEach(async () => {
  await rm(repo, { recursive: true, force: true });
});

describe("worktree isolation", () => {
  it("detects a clean vs dirty tree", async () => {
    expect(await isDirty(repo)).toBe(false);
    await writeFile(path.join(repo, "file.txt"), "changed\n");
    expect(await isDirty(repo)).toBe(true);
  });

  it("refuses to create a worktree from a dirty tree unless allowed", async () => {
    await writeFile(path.join(repo, "file.txt"), "dirty\n");
    await expect(
      createWorktree({ repoRoot: repo, runId: "r1", workerId: "w1" }),
    ).rejects.toThrow(/uncommitted changes/);
  });

  it("creates a worktree on a predictable branch and cleans it up", async () => {
    const wt = await createWorktree({ repoRoot: repo, runId: "r1", workerId: "w1" });
    expect(wt.branch).toBe(worktreeBranch("r1", "w1"));
    const trees = await listWorktrees(repo);
    // git prints worktree paths with forward slashes on every platform, so
    // compare separator-agnostically (path.join would use "\" on Windows).
    const norm = (p: string) => p.replace(/\\/g, "/");
    expect(trees.some((t) => norm(t).includes("r1/w1"))).toBe(true);

    const result = await cleanupWorktrees(repo, [wt]);
    expect(result.removed).toHaveLength(1);
    expect(result.skippedDirty).toHaveLength(0);
  });

  it("preserves a worktree with uncommitted changes instead of deleting it", async () => {
    const wt = await createWorktree({ repoRoot: repo, runId: "r2", workerId: "w1" });
    await writeFile(path.join(wt.path, "new.txt"), "work in progress\n");
    const result = await cleanupWorktrees(repo, [wt]);
    expect(result.removed).toHaveLength(0);
    expect(result.skippedDirty).toHaveLength(1);
  });
});
