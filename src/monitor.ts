import { readFile } from "node:fs/promises";
import { mkdir, rename, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { loadApprovals } from "./approvals.js";
import { DEFAULT_CONCURRENCY, mapLimit } from "./concurrency.js";
import { extractLockfileEntries, snapshotLockfile } from "./lockfile.js";
import { osvUnavailable, queryOsvBatch, type OsvResult } from "./osv.js";
import { fetchPackageMetadata, PackageNotFoundError } from "./registry.js";
import { fetchReputation } from "./reputation.js";
import { RELEASE_GAP_ANOMALY_DAYS } from "./reputation.js";
import { compareSemver } from "./semver.js";
import type { LookupStatus, PackageManager } from "./types.js";

/**
 * `targate monitor` — one-shot risk-evolution check. A package that was safe
 * when approved can turn risky later (new vulnerability, maintainer takeover,
 * deprecation, archived repo, a suspicious new release). This re-checks the
 * monitored set against a stored baseline and reports what changed. It is a
 * LIGHT pipeline: metadata + OSV + reputation only — no tarball download, no
 * AI — so it is cheap enough to run in a scheduled CI step.
 */

export const MONITOR_SCHEMA_VERSION = 1;

export type MonitorOrigin = "approval" | "direct" | "lockfile";

export interface MonitorTarget {
  name: string;
  version: string;
  origin: MonitorOrigin;
}

export interface MonitorSnapshot {
  name: string;
  version: string;
  knownMalicious: boolean;
  maliciousIds: string[];
  advisoryIds: string[];
  osvUnavailable: boolean;
  deprecated: string | false;
  hasProvenance: boolean;
  maintainers: string[];
  repositoryUrl?: string;
  latestVersion?: string;
  latestVersionPublishDate?: string;
  latestHasProvenance?: boolean;
  downloadsStatus: LookupStatus;
  weeklyDownloads?: number;
  downloadsTrend?: "stable" | "spike" | "drop";
  repoStatus: string;
  repoArchived?: boolean;
  capturedAt: string;
}

export interface MonitorBaselineFile {
  schemaVersion: number;
  updatedAt: string;
  snapshots: Record<string, MonitorSnapshot>;
}

export type MonitorEventKind =
  | "known-malicious"
  | "deprecated"
  | "repo-archived"
  | "repo-gone"
  | "new-advisory"
  | "maintainer-added"
  | "maintainer-removed"
  | "repository-changed"
  | "provenance-removed"
  | "suspicious-new-version"
  | "new-version"
  | "download-drop"
  | "download-spike"
  | "lookup-degraded";

export interface MonitorEvent {
  package: string;
  kind: MonitorEventKind;
  severity: "info" | "warn" | "critical";
  detail: string;
  /** True when the state was already present in the baseline (always-on kinds). */
  alreadyKnown?: boolean;
}

export function baselinePath(cwd: string = process.cwd()): string {
  return path.join(cwd, ".targate", "monitor-baseline.json");
}

/** Collect the packages to monitor: approvals ∪ direct deps, or the whole tree. */
export async function collectTargets(
  pm: PackageManager,
  all: boolean,
  treePackages: { name: string; version: string }[],
  cwd: string = process.cwd(),
): Promise<MonitorTarget[]> {
  const byKey = new Map<string, MonitorTarget>();
  const add = (name: string, version: string, origin: MonitorOrigin) => {
    const key = `${name}@${version}`;
    if (!byKey.has(key)) byKey.set(key, { name, version, origin });
  };

  if (all) {
    for (const p of treePackages) add(p.name, p.version, "lockfile");
  } else {
    // Approvals (exact versions a human vouched for).
    const approvals = await loadApprovals(cwd);
    for (const key of Object.keys(approvals)) {
      const at = key.lastIndexOf("@");
      if (at > 0) add(key.slice(0, at), key.slice(at + 1), "approval");
    }
    // Direct dependencies, resolved to installed versions via the lockfile.
    const directNames = await readDirectDependencyNames(cwd);
    const content = await snapshotLockfile(pm, cwd);
    const installed = new Map<string, string[]>();
    if (content) {
      for (const entry of extractLockfileEntries(pm, content)) {
        const at = entry.lastIndexOf("@");
        if (at <= 0) continue;
        const name = entry.slice(0, at);
        const version = entry.slice(at + 1);
        (installed.get(name) ?? installed.set(name, []).get(name)!).push(version);
      }
    }
    for (const name of directNames) {
      for (const version of installed.get(name) ?? []) add(name, version, "direct");
    }
  }
  return [...byKey.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

async function readDirectDependencyNames(cwd: string): Promise<string[]> {
  try {
    const pkg = JSON.parse(await readFile(path.join(cwd, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})];
  } catch {
    return [];
  }
}

export interface SnapshotOptions {
  failOnOsvError?: boolean;
  noReputation?: boolean;
  concurrency?: number;
}

/** Build a current snapshot for every target (metadata + OSV + reputation). */
export async function snapshotTargets(
  targets: MonitorTarget[],
  opts: SnapshotOptions = {},
): Promise<{ snapshots: MonitorSnapshot[]; errors: { package: string; message: string }[] }> {
  const capturedAt = new Date().toISOString();
  // One batched OSV lookup for everything.
  let osvMap = new Map<string, OsvResult>();
  try {
    osvMap = await queryOsvBatch(targets);
  } catch {
    /* per-target fallback below */
  }

  const errors: { package: string; message: string }[] = [];
  const snapshots = await mapLimit(
    targets,
    opts.concurrency ?? DEFAULT_CONCURRENCY,
    async (t): Promise<MonitorSnapshot | null> => {
      try {
        const metadata = await fetchPackageMetadata(t.name, t.version);
        const osv = osvMap.get(`${t.name}@${t.version}`) ?? osvUnavailable();
        const reputation = opts.noReputation
          ? undefined
          : await fetchReputation(t.name, metadata.repositoryUrl);
        const rep = metadata.registryReputation;
        return {
          name: t.name,
          version: t.version,
          knownMalicious: osv.knownMalicious,
          maliciousIds: osv.maliciousRecords.map((r) => r.id),
          advisoryIds: osv.advisories.map((r) => r.id),
          osvUnavailable: osv.unavailable,
          deprecated:
            rep.deprecated === undefined ? false : rep.deprecated === true ? "deprecated (no message)" : rep.deprecated,
          hasProvenance: rep.hasProvenance,
          maintainers: metadata.maintainers,
          repositoryUrl: metadata.repositoryUrl,
          latestVersion: rep.latestVersion,
          latestVersionPublishDate: rep.latestVersionPublishDate,
          latestHasProvenance: rep.latestHasProvenance,
          downloadsStatus: reputation?.downloads.status ?? "skipped",
          weeklyDownloads: reputation?.downloads.weeklyDownloads,
          downloadsTrend: reputation?.downloads.trend,
          repoStatus: reputation?.repo.status ?? "skipped",
          repoArchived: reputation?.repo.archived,
          capturedAt,
        };
      } catch (err) {
        const message = err instanceof PackageNotFoundError ? err.message : err instanceof Error ? err.message : String(err);
        errors.push({ package: `${t.name}@${t.version}`, message });
        return null;
      }
    },
  );
  return { snapshots: snapshots.filter((s): s is MonitorSnapshot => s !== null), errors };
}

/** Findings that hold regardless of a baseline — a bad state must keep failing. */
export function alwaysOnFindings(snap: MonitorSnapshot, failOnOsvError = false): MonitorEvent[] {
  const pkg = `${snap.name}@${snap.version}`;
  const events: MonitorEvent[] = [];
  if (snap.knownMalicious) {
    events.push({ package: pkg, kind: "known-malicious", severity: "critical", detail: `known malicious-package record: ${snap.maliciousIds.join(", ")}` });
  }
  if (snap.deprecated !== false) {
    events.push({ package: pkg, kind: "deprecated", severity: "warn", detail: `deprecated: ${snap.deprecated}` });
  }
  if (snap.repoStatus === "ok" && snap.repoArchived) {
    events.push({ package: pkg, kind: "repo-archived", severity: "warn", detail: "GitHub repository is archived" });
  }
  if (snap.repoStatus === "not-found") {
    events.push({ package: pkg, kind: "repo-gone", severity: "warn", detail: "repository is missing or private (GitHub 404)" });
  }
  if (snap.osvUnavailable) {
    events.push({
      package: pkg,
      kind: "lookup-degraded",
      severity: failOnOsvError ? "warn" : "info",
      detail: "OSV lookup unavailable — malicious/advisory status is UNKNOWN",
    });
  }
  return events;
}

/** Findings that require comparison against the baseline. */
export function diffSnapshots(before: MonitorSnapshot, after: MonitorSnapshot): MonitorEvent[] {
  const pkg = `${after.name}@${after.version}`;
  const events: MonitorEvent[] = [];
  const push = (kind: MonitorEventKind, severity: MonitorEvent["severity"], detail: string) =>
    events.push({ package: pkg, kind, severity, detail });

  const beforeAdv = new Set(before.advisoryIds);
  const newAdv = after.advisoryIds.filter((id) => !beforeAdv.has(id));
  if (newAdv.length > 0) push("new-advisory", "warn", `new vulnerability advisories: ${newAdv.join(", ")}`);

  const beforeMaint = new Set(before.maintainers);
  const afterMaint = new Set(after.maintainers);
  const added = after.maintainers.filter((m) => !beforeMaint.has(m));
  const removed = before.maintainers.filter((m) => !afterMaint.has(m));
  if (added.length > 0) push("maintainer-added", "warn", `maintainer(s) added: ${added.join(", ")}`);
  if (removed.length > 0) push("maintainer-removed", "warn", `maintainer(s) removed: ${removed.join(", ")}`);

  if ((before.repositoryUrl ?? "") !== (after.repositoryUrl ?? "")) {
    push("repository-changed", "warn", `repository URL changed: ${before.repositoryUrl ?? "(none)"} → ${after.repositoryUrl ?? "(none)"}`);
  }

  if (before.latestHasProvenance && after.latestHasProvenance === false) {
    push("provenance-removed", "warn", "latest release stopped publishing with provenance");
  }

  if (before.latestVersion && after.latestVersion && before.latestVersion !== after.latestVersion) {
    const notGreater = compareSemver(after.latestVersion, before.latestVersion) <= 0;
    const gap = releaseGapDays(before.latestVersionPublishDate, after.latestVersionPublishDate);
    if (notGreater || (gap !== undefined && gap >= RELEASE_GAP_ANOMALY_DAYS)) {
      push("suspicious-new-version", "warn", `new latest ${after.latestVersion} (was ${before.latestVersion})${notGreater ? " — not a semver increase" : ` — after ${gap} days of inactivity`}`);
    } else {
      push("new-version", "info", `new latest version available: ${after.latestVersion} (was ${before.latestVersion})`);
    }
  }

  if (before.downloadsTrend !== "drop" && after.downloadsTrend === "drop") {
    push("download-drop", "warn", "weekly downloads dropped sharply");
  }
  if (before.downloadsTrend !== "spike" && after.downloadsTrend === "spike") {
    push("download-spike", "info", "weekly downloads spiked");
  }
  return events;
}

function releaseGapDays(before?: string, after?: string): number | undefined {
  if (!before || !after) return undefined;
  return Math.floor((new Date(after).getTime() - new Date(before).getTime()) / 86_400_000);
}

/** Best-effort atomic write of the baseline (mirrors last-run.ts). */
export async function writeBaseline(snapshots: MonitorSnapshot[], cwd?: string): Promise<void> {
  try {
    const file = baselinePath(cwd);
    await mkdir(path.dirname(file), { recursive: true });
    const record: MonitorBaselineFile = {
      schemaVersion: MONITOR_SCHEMA_VERSION,
      updatedAt: new Date().toISOString(),
      snapshots: Object.fromEntries(snapshots.map((s) => [`${s.name}@${s.version}`, s])),
    };
    const tmp = `${file}.${randomUUID()}.tmp`;
    await writeFile(tmp, JSON.stringify(record, null, 2));
    await rename(tmp, file);
  } catch {
    /* best-effort */
  }
}

/** Read the baseline; null when absent or unusable (caller rebuilds). */
export async function readBaseline(cwd?: string): Promise<MonitorBaselineFile | null> {
  try {
    const parsed = JSON.parse(await readFile(baselinePath(cwd), "utf8")) as MonitorBaselineFile;
    if (parsed?.schemaVersion !== MONITOR_SCHEMA_VERSION || typeof parsed.snapshots !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
}
