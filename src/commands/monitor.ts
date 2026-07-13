import type { AssessOptions } from "../ai.js";
import { loadPolicy } from "../policy.js";
import { detectPackageManager } from "../installer.js";
import { printJson } from "../json-output.js";
import {
  alwaysOnFindings,
  baselinePath,
  collectTargets,
  diffSnapshots,
  readBaseline,
  snapshotTargets,
  writeBaseline,
  type MonitorEvent,
  type MonitorSnapshot,
} from "../monitor.js";
import { resolveProjectTree } from "../full-install.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import type { PackageManager } from "../types.js";

export interface MonitorCommandOptions {
  packageManager?: string;
  json: boolean;
  /** Monitor the entire lockfile tree instead of approvals + direct deps. */
  all?: boolean;
  /** Report events without advancing the baseline. */
  noUpdate?: boolean;
  failOnOsvError?: boolean;
  noReputation?: boolean;
  concurrency?: number;
  assess: AssessOptions; // unused (no AI) — accepted for CLI uniformity
}

const SEVERITY_ICON = { critical: "✗", warn: "⚠", info: "ℹ" } as const;
const SEVERITY_PAINT = { critical: red, warn: yellow, info: cyan } as const;

/** `targate monitor` — re-check monitored packages against a stored baseline. */
export async function monitorCommand(opts: MonitorCommandOptions): Promise<number> {
  const pm = (opts.packageManager as PackageManager) ?? detectPackageManager();
  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };

  let treePackages: { name: string; version: string }[] = [];
  if (opts.all) {
    treePackages = (await resolveProjectTree(pm)).packages;
  }
  const targets = await collectTargets(pm, Boolean(opts.all), treePackages);

  if (targets.length === 0) {
    console.error(
      red("Nothing to monitor — no approvals and no resolvable dependencies. Run from a project with a lockfile, or approve some packages first."),
    );
    return 1;
  }

  note(dim(`\nMonitoring ${bold(String(targets.length))} package(s) ...`));
  const policy = await loadPolicy();
  const { snapshots, errors } = await snapshotTargets(targets, {
    internalScopes: policy?.policy.dependencyPolicy.internalScopes,
    resourceLimits: policy?.policy.resourceLimits,
    failOnOsvError: opts.failOnOsvError,
    noReputation: opts.noReputation,
    concurrency: opts.concurrency,
  });

  const baseline = await readBaseline();
  const baselineExisted = baseline !== null;
  const baselineFile = baselinePath();

  // Compose events: always-on findings + baseline diffs.
  const events: MonitorEvent[] = [];
  const baselineSnaps = baseline?.snapshots ?? {};
  for (const snap of snapshots) {
    const key = `${snap.name}@${snap.version}`;
    const prior = baselineSnaps[key];
    for (const e of alwaysOnFindings(snap, opts.failOnOsvError)) {
      events.push({ ...e, alreadyKnown: prior ? isAlreadyKnown(e.kind, prior) : false });
    }
    if (prior) events.push(...diffSnapshots(prior, snap));
  }

  const summary = { critical: 0, warn: 0, info: 0 };
  for (const e of events) summary[e.severity]++;
  const exitCode = summary.critical > 0 || summary.warn > 0 ? 2 : 0;

  const updated = !opts.noUpdate;
  if (updated) await writeBaseline(snapshots);

  if (opts.json) {
    const bySource = { approval: 0, direct: 0, lockfile: 0 };
    for (const t of targets) bySource[t.origin]++;
    printJson("monitor", {
      packages: targets.length,
      source: bySource,
      baseline: {
        created: !baselineExisted,
        path: baselineFile,
        previousUpdatedAt: baseline?.updatedAt ?? null,
        updated,
      },
      events,
      errors,
      summary,
      exitCode,
    });
    return exitCode;
  }

  // Human output.
  if (!baselineExisted) {
    note(green(`  ✓ baseline created for ${snapshots.length} package(s) → ${baselineFile}`));
  }
  const sorted = [...events].sort(
    (a, b) => rank(b.severity) - rank(a.severity) || a.package.localeCompare(b.package),
  );
  for (const e of sorted) {
    const paint = SEVERITY_PAINT[e.severity];
    const known = e.alreadyKnown ? dim(" (already known)") : "";
    console.log(paint(`  ${SEVERITY_ICON[e.severity]} ${e.package}: ${e.detail}`) + known);
  }
  for (const err of errors) console.log(dim(`  · ${err.package}: could not check (${err.message})`));

  console.log("");
  const quiet = snapshots.length - new Set(events.map((e) => e.package)).size;
  if (events.length === 0) {
    console.log(green(bold(baselineExisted ? "No risk changes since the last baseline." : "Baseline created — no active risks.")));
  } else {
    console.log(
      (summary.critical > 0 || summary.warn > 0 ? red : cyan)(
        bold(`${summary.critical} critical, ${summary.warn} warning, ${summary.info} info across ${new Set(events.map((e) => e.package)).size} package(s).`),
      ),
    );
    if (quiet > 0) console.log(dim(`${quiet} package(s) unchanged.`));
  }
  if (updated && baselineExisted) console.log(dim(`Baseline updated → ${baselineFile}`));
  return exitCode;
}

function rank(s: MonitorEvent["severity"]): number {
  return s === "critical" ? 2 : s === "warn" ? 1 : 0;
}

function isAlreadyKnown(kind: MonitorEvent["kind"], prior: MonitorSnapshot): boolean {
  switch (kind) {
    case "known-malicious":
      return prior.knownMalicious;
    case "deprecated":
      return prior.deprecated !== false;
    case "repo-archived":
      return prior.repoStatus === "ok" && Boolean(prior.repoArchived);
    case "repo-gone":
      return prior.repoStatus === "not-found";
    default:
      return false;
  }
}
