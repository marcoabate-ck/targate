/**
 * Workflow run persistence.
 *
 * This is WORKFLOW state, not model-session state. Each run gets a stable id
 * and a directory under the configured run root, holding the task, plan,
 * approval record, per-worker structured results, an append-only event log,
 * and a final summary. Enough to inspect or resume a workflow after a crash;
 * never any secret or full environment dump.
 */

import { appendFile, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import type { WorkerResult } from "./protocol.js";

export interface RunMetadata {
  runId: string;
  createdAt: string;
  updatedAt: string;
  cwd: string;
  status: "created" | "running" | "awaiting-approval" | "completed" | "failed" | "cancelled";
  task: string;
  model: string;
  /** Configured worker concurrency, for the status display. */
  maxConcurrency: number;
  /** Roles the flow intends to run, in order — lets status show what is queued. */
  plannedFlow: string[];
  approval: ApprovalRecord;
  workers: WorkerSummaryRef[];
}

/** Lifecycle state of a worker within a run. */
export type WorkerState = "running" | "done";

export interface ApprovalRecord {
  required: boolean;
  reason?: string;
  approvedAt?: string;
  approvedBy?: string;
  approvedPlanHash?: string;
}

export interface WorkerSummaryRef {
  workerId: string;
  role: string;
  /** "running" while in flight; "done" once a result is recorded. */
  state: WorkerState;
  /** Final worker status; present once state is "done". */
  status?: WorkerResult["status"];
  /** Result file path; present once state is "done". */
  resultFile?: string;
}

export interface RunEvent {
  at: string;
  kind: string;
  message: string;
  data?: Record<string, unknown>;
}

/**
 * Build a run id. The timestamp is supplied by the caller (the CLI stamps it)
 * so this module stays deterministic and testable.
 */
export function makeRunId(isoTimestamp: string, slug: string): string {
  const stamp = isoTimestamp.replace(/[:.]/g, "").replace(/[-T]/g, "").slice(0, 14);
  const safeSlug = slug
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "task";
  return `${stamp}-${safeSlug}`;
}

export class RunStore {
  readonly dir: string;

  constructor(
    readonly runRoot: string,
    readonly runId: string,
  ) {
    this.dir = path.join(runRoot, runId);
  }

  private file(name: string): string {
    return path.join(this.dir, name);
  }

  async init(metadata: RunMetadata): Promise<void> {
    await mkdir(path.join(this.dir, "workers"), { recursive: true });
    await this.writeMetadata(metadata);
  }

  async writeMetadata(metadata: RunMetadata): Promise<void> {
    await writeFile(this.file("metadata.json"), JSON.stringify(metadata, null, 2) + "\n");
  }

  async readMetadata(): Promise<RunMetadata> {
    return JSON.parse(await readFile(this.file("metadata.json"), "utf8")) as RunMetadata;
  }

  async writeText(name: string, content: string): Promise<string> {
    await mkdir(path.dirname(this.file(name)), { recursive: true });
    await writeFile(this.file(name), content);
    return name;
  }

  /** Insert or merge a worker entry by workerId, stamping updatedAt. */
  async upsertWorker(entry: WorkerSummaryRef, updatedAt: string): Promise<void> {
    const meta = await this.readMetadata();
    const i = meta.workers.findIndex((w) => w.workerId === entry.workerId);
    if (i >= 0) meta.workers[i] = { ...meta.workers[i], ...entry };
    else meta.workers.push(entry);
    meta.updatedAt = updatedAt;
    await this.writeMetadata(meta);
  }

  async writeWorkerResult(result: WorkerResult): Promise<string> {
    const rel = path.join("workers", `${result.workerId}.json`);
    await writeFile(this.file(rel), JSON.stringify(result, null, 2) + "\n");
    return rel;
  }

  /** Append one line to events.jsonl. `at` is caller-supplied for determinism. */
  async appendEvent(event: RunEvent): Promise<void> {
    await appendFile(this.file("events.jsonl"), JSON.stringify(event) + "\n");
  }

  async readEvents(): Promise<RunEvent[]> {
    const file = this.file("events.jsonl");
    if (!existsSync(file)) return [];
    const text = await readFile(file, "utf8");
    return text
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as RunEvent);
  }

  exists(): boolean {
    return existsSync(this.file("metadata.json"));
  }
}

/** List run ids under a run root, newest id first (ids sort chronologically). */
export async function listRuns(runRoot: string): Promise<string[]> {
  if (!existsSync(runRoot)) return [];
  const entries = await readdir(runRoot, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .sort()
    .reverse();
}
