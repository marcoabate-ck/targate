/**
 * Git worktree isolation for parallel writer workers (opt-in).
 *
 * Writers default to running sequentially in the main tree. When genuine
 * parallel writing is requested, each writer gets its own git worktree on a
 * predictable temporary branch so their edits never collide and never touch
 * the user's working tree. Safety rules:
 *   - never create a worktree from a dirty index/tree without opt-in;
 *   - use predictable branch names recorded in run metadata;
 *   - NEVER auto force-reset the user's branch or delete uncommitted work;
 *   - cleanup is an explicit, non-destructive command (skips dirty worktrees).
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";

const execFileAsync = promisify(execFile);

export interface WorktreeInfo {
  path: string;
  branch: string;
  workerId: string;
}

async function git(repoRoot: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync("git", args, { cwd: repoRoot, maxBuffer: 8 * 1024 * 1024 });
  return stdout.trim();
}

/** True when the repository has uncommitted changes. */
export async function isDirty(repoRoot: string): Promise<boolean> {
  const status = await git(repoRoot, ["status", "--porcelain"]);
  return status.length > 0;
}

/** Predictable branch name for a worktree. */
export function worktreeBranch(runId: string, workerId: string): string {
  return `local-agents/${runId}/${workerId}`;
}

export interface CreateWorktreeOptions {
  repoRoot: string;
  runId: string;
  workerId: string;
  /** Directory to hold worktrees (default: <repoRoot>/.local-agent-worktrees). */
  worktreeRoot?: string;
  /** Base ref to branch from (default: HEAD). */
  baseRef?: string;
  /** Allow creating from a dirty tree (default false — refuse and explain). */
  allowDirty?: boolean;
}

/**
 * Create an isolated worktree for a writer worker. Refuses on a dirty tree
 * unless `allowDirty` is set, so a parallel run can never silently strand the
 * user's uncommitted changes.
 */
export async function createWorktree(opts: CreateWorktreeOptions): Promise<WorktreeInfo> {
  if (!opts.allowDirty && (await isDirty(opts.repoRoot))) {
    throw new Error(
      "refusing to create worktrees: the working tree has uncommitted changes. Commit or stash first, or pass allowDirty.",
    );
  }
  const branch = worktreeBranch(opts.runId, opts.workerId);
  const root = opts.worktreeRoot ?? path.join(opts.repoRoot, ".local-agent-worktrees");
  const wtPath = path.join(root, opts.runId, opts.workerId);
  const base = opts.baseRef ?? "HEAD";

  // -b creates the branch; fails loudly if it already exists (predictable, no
  // silent reuse of a stale branch).
  await git(opts.repoRoot, ["worktree", "add", "-b", branch, wtPath, base]);
  return { path: wtPath, branch, workerId: opts.workerId };
}

/** List worktrees git knows about (porcelain), for diagnostics. */
export async function listWorktrees(repoRoot: string): Promise<string[]> {
  const out = await git(repoRoot, ["worktree", "list", "--porcelain"]);
  return out
    .split("\n")
    .filter((l) => l.startsWith("worktree "))
    .map((l) => l.slice("worktree ".length));
}

export interface CleanupResult {
  removed: WorktreeInfo[];
  skippedDirty: WorktreeInfo[];
}

/**
 * Remove the worktrees for a run. A worktree with uncommitted changes is
 * SKIPPED (never force-removed) so potentially useful work is preserved; the
 * caller surfaces skipped entries so a human can decide. Branches are left in
 * place — deleting a branch is a human decision.
 */
export async function cleanupWorktrees(
  repoRoot: string,
  worktrees: WorktreeInfo[],
): Promise<CleanupResult> {
  const removed: WorktreeInfo[] = [];
  const skippedDirty: WorktreeInfo[] = [];
  for (const wt of worktrees) {
    let dirty = false;
    try {
      const status = await execFileAsync("git", ["status", "--porcelain"], { cwd: wt.path });
      dirty = status.stdout.trim().length > 0;
    } catch {
      // Worktree path already gone — treat as removable metadata only.
    }
    if (dirty) {
      skippedDirty.push(wt);
      continue;
    }
    // Non-forced remove: git refuses if the worktree is dirty, a second guard.
    await git(repoRoot, ["worktree", "remove", wt.path]).catch(async () => {
      // If the directory is missing, prune the stale administrative entry.
      await git(repoRoot, ["worktree", "prune"]);
    });
    removed.push(wt);
  }
  return { removed, skippedDirty };
}
