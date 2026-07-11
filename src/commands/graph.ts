import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import {
  buildDependencyGraph,
  filterGraph,
  whyChains,
  GRAPH_FILTERS,
  type DependencyGraph,
  type GraphFilter,
} from "../graph.js";
import {
  renderGraphDot,
  renderGraphHtml,
  renderGraphMermaid,
  renderGraphSvg,
  renderWhy,
} from "../graph-render.js";
import { printJson } from "../json-output.js";
import { createTreeProgress } from "../progress.js";
import { loadPolicy } from "../policy.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";
import type { PackageManager } from "../types.js";

export type GraphFormat = "html" | "svg" | "dot" | "mermaid" | "json";
export const GRAPH_FORMATS: GraphFormat[] = ["html", "svg", "dot", "mermaid", "json"];

export interface GraphCommandOptions {
  /** Graph a package instead of the current project. */
  spec?: string;
  format?: string;
  /** Output file; "-" forces stdout. Defaults: html/svg → targate-graph.<ext>, dot/mermaid/json → stdout. */
  output?: string;
  /** Comma-separated GraphFilter list — prune to matching nodes + their paths to root. */
  only?: string;
  /** "Why is this package in my tree?" — print risk-annotated chains instead of a graph. */
  why?: string;
  /** Open the written html/svg file with the platform opener. */
  open?: boolean;
  json: boolean;
  packageManager?: string;
  noReputation?: boolean;
  failOnOsvError?: boolean;
  concurrency?: number;
}

/** Parse and validate --only. Returns null (with a message) on unknown filters. */
export function parseOnly(raw: string | undefined): GraphFilter[] | null {
  if (!raw) return [];
  const parts = raw.split(",").map((s) => s.trim()).filter(Boolean);
  const invalid = parts.filter((p) => !GRAPH_FILTERS.includes(p as GraphFilter));
  if (invalid.length > 0) return null;
  return parts as GraphFilter[];
}

function openFile(file: string): void {
  const opener = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
  const args = process.platform === "win32" ? ["/c", "start", "", file] : [file];
  execFile(opener, args, () => {
    /* best-effort — a headless box simply doesn't open a browser */
  });
}

/**
 * `targate graph` — visualize risk across the dependency tree. Deterministic
 * analysis only (no AI); always exit 0 on success — the graph is a lens, the
 * gate lives in add/install/ci.
 */
export async function graphCommand(opts: GraphCommandOptions): Promise<number> {
  const format = (opts.format ?? "html") as GraphFormat;
  if (!GRAPH_FORMATS.includes(format)) {
    console.error(red(`Unknown --format: ${opts.format}. Valid options: ${GRAPH_FORMATS.join(", ")}`));
    return 1;
  }
  const only = parseOnly(opts.only);
  if (only === null) {
    console.error(red(`Unknown --only filter. Valid filters: ${GRAPH_FILTERS.join(", ")}`));
    return 1;
  }
  // Anything that sends the DOCUMENT to stdout must keep stdout clean of
  // progress/notes: --json, json format, --output -, and the dot/mermaid
  // formats (which default to stdout because they exist to be piped).
  const stdoutDocument =
    !opts.why &&
    (opts.json ||
      format === "json" ||
      opts.output === "-" ||
      (opts.output === undefined && format !== "html" && format !== "svg"));
  const machineStdout = stdoutDocument;
  const note = (line: string): void => {
    if (!machineStdout) console.log(line);
  };

  const policy = await loadPolicy();
  const progress = createTreeProgress({ json: machineStdout });

  let graph: DependencyGraph;
  try {
    note(dim(`\nResolving ${opts.spec ? `the ${opts.spec} tree` : "the project dependency tree"} and analyzing every package (deterministic, no AI) ...`));
    graph = await buildDependencyGraph({
      spec: opts.spec ? parsePackageSpec(opts.spec) : undefined,
      packageManager: opts.packageManager as PackageManager | undefined,
      policy,
      noReputation: opts.noReputation,
      failOnOsvError: opts.failOnOsvError,
      concurrency: opts.concurrency,
      onProgress: (done, total) => progress.update("scan", done, total),
    });
  } catch (err) {
    progress.done();
    if (err instanceof PackageNotFoundError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }
  progress.done(dim(`  ✓ ${graph.stats.packages} packages analyzed, ${graph.stats.edges} edges`));

  // --why: chains to root, no graph document.
  if (opts.why) {
    const { name } = parsePackageSpec(opts.why);
    const { chains, truncated } = whyChains(graph, name);
    if (opts.json) {
      printJson("graph", { source: graph.source, why: name, chains, truncated, exitCode: 0 });
      return 0;
    }
    console.log("");
    console.log(renderWhy(graph, name, chains, truncated, { dim, yellow, red, bold }));
    return 0;
  }

  const view = only.length > 0 ? filterGraph(graph, only) : graph;

  if (opts.json || format === "json") {
    printJson("graph", {
      source: view.source,
      packageManager: view.packageManager,
      roots: view.roots,
      workspaces: view.workspaces,
      baselineCompared: view.baselineCompared,
      only: only.length > 0 ? only : undefined,
      stats: view.stats,
      nodes: view.nodes,
      edges: view.edges,
      exitCode: 0,
    });
    return 0;
  }

  const title = `targate graph — ${opts.spec ?? (view.roots.map((r) => r.replace(/^(project|workspace):/, "")).join(", ") || "project")}${only.length > 0 ? ` (filtered: ${only.join(", ")})` : ""}`;
  const document =
    format === "html"
      ? renderGraphHtml(view, title)
      : format === "svg"
        ? renderGraphSvg(view)
        : format === "dot"
          ? renderGraphDot(view)
          : renderGraphMermaid(view);

  // Where it goes: html/svg default to a file (a browser artifact is useless
  // on stdout); dot/mermaid default to stdout (they exist to be piped).
  const defaultFile = format === "html" || format === "svg" ? `targate-graph.${format}` : null;
  const target = opts.output === "-" ? null : (opts.output ?? defaultFile);

  if (target) {
    await writeFile(target, document);
    note(green(`\nWrote ${path.resolve(target)}`));
    const s = view.stats;
    note(
      dim(
        `  ${s.packages} packages · ${s.highRisk} high-risk · ${s.withScripts} with lifecycle scripts${view.baselineCompared ? ` · ${s.riskIncreased} risk-increased since baseline` : ""}`,
      ),
    );
    if (s.malicious > 0) note(red(bold(`  ☠ ${s.malicious} package(s) with a known-malicious record — run targate install / add for the gate.`)));
    if (format === "html") note(cyan(`  Open it in a browser — filters, search, and per-package details are built in.`));
    if (opts.open) openFile(target);
  } else {
    console.log(document);
  }
  return 0;
}
