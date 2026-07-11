import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";
import { mapLimit, DEFAULT_CONCURRENCY } from "./concurrency.js";
import { detectPackageManager } from "./installer.js";
import { resolveProjectTree } from "./full-install.js";
import { readBaseline, type MonitorSnapshot } from "./monitor.js";
import { isInternalScope } from "./npmrc.js";
import { queryOsvBatch, type OsvResult } from "./osv.js";
import { buildPackageSignals } from "./pipeline.js";
import type { LoadedPolicy } from "./policy.js";
import { fetchPackageMetadata } from "./registry.js";
import { evaluateRules, isHardBlock } from "./rules.js";
import { computeSecurityScore } from "./score.js";
import { resolveTransitiveTree, type TreePackage } from "./transitive.js";
import type { PackageManager } from "./types.js";

/**
 * `targate graph` — the dependency tree as a RISK GRAPH.
 *
 * Nodes are the resolved packages (plus synthetic roots for the project /
 * each workspace), analyzed with the same deterministic pipeline as
 * `targate install --no-ai` (signals → security score → rules verdict; no
 * AI — a graph must be reproducible). Edges come from each packument's
 * DECLARED dependencies resolved against the versions present in the tree.
 *
 * Edge fidelity note: lockfiles are flattened per package manager, so when
 * the tree contains several versions of a dependency, a declared edge is
 * drawn to every present version that could satisfy it — a deliberate
 * over-approximation (documented in docs/dependency-graph.md) that never
 * hides a real edge.
 */

export type NodeRisk = "none" | "low" | "medium" | "high" | "critical";

export interface GraphNode {
  /** "name@version" for packages; "workspace:<name>" / "project:<name>" for roots. */
  id: string;
  name: string;
  version?: string;
  kind: "package" | "root";
  /** Security score 0–100 (absent on roots and failed analyses). */
  score?: number;
  risk: NodeRisk;
  decision?: string;
  hasLifecycleScripts?: boolean;
  hasNativeCode?: boolean;
  knownMalicious?: boolean;
  advisories?: string[];
  deprecated?: boolean;
  hasProvenance?: boolean;
  /** Direct dependency of at least one root. */
  direct?: boolean;
  /** Workspace roots (by name) whose subtree reaches this node. */
  workspaces?: string[];
  /** Risk rose vs .targate/monitor-baseline.json — one reason per line. */
  riskIncreased?: string[];
  /** Top assessment reasons (for the detail panel). */
  reasons?: string[];
  /** Analysis failed — the node is shown, honestly marked unknown. */
  error?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
}

export interface GraphStats {
  packages: number;
  edges: number;
  highRisk: number;
  withScripts: number;
  withNativeCode: number;
  deprecated: number;
  malicious: number;
  withoutProvenance: number;
  riskIncreased: number;
  analysisErrors: number;
}

export interface DependencyGraph {
  /** "project" (lockfile), "resolved" (no lockfile, npm-resolved), or "package". */
  source: "project" | "resolved" | "package";
  packageManager?: PackageManager;
  /** Root node ids (project / workspaces / the graphed package). */
  roots: string[];
  /** Workspace names, when the project is a monorepo. */
  workspaces: string[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
  /** True when a monitor baseline existed and the overlay was computed. */
  baselineCompared: boolean;
}

/* ---------------------------------------------------------------- roots -- */

interface RootSpec {
  /** Display name (package.json name, or the directory name). */
  name: string;
  /** Node id ("project:app" / "workspace:@acme/ui"). */
  id: string;
  /** Direct dependency NAMES (dependencies + devDependencies). */
  dependencyNames: string[];
}

function readPackageJson(dir: string): { name?: string; deps: string[]; workspaces?: unknown } | null {
  try {
    const doc = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")) as {
      name?: string;
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      workspaces?: unknown;
    };
    return {
      name: typeof doc.name === "string" ? doc.name : undefined,
      deps: [...Object.keys(doc.dependencies ?? {}), ...Object.keys(doc.devDependencies ?? {})],
      workspaces: doc.workspaces,
    };
  } catch {
    return null;
  }
}

/**
 * Expand workspace glob patterns. Deliberately minimal — the two forms that
 * cover real-world configs: an exact directory ("docs") and a single-star
 * suffix ("packages/*"). Deeper patterns are skipped (documented).
 */
export function expandWorkspaceGlobs(cwd: string, patterns: string[]): string[] {
  const dirs: string[] = [];
  for (const pattern of patterns) {
    if (typeof pattern !== "string" || pattern.startsWith("!")) continue;
    if (pattern.endsWith("/*")) {
      const base = path.join(cwd, pattern.slice(0, -2));
      try {
        for (const entry of readdirSync(base)) {
          const dir = path.join(base, entry);
          try {
            if (statSync(dir).isDirectory()) dirs.push(dir);
          } catch {
            /* unreadable entry */
          }
        }
      } catch {
        /* base dir absent */
      }
    } else if (!pattern.includes("*")) {
      dirs.push(path.join(cwd, pattern));
    }
    // "**" and mid-pattern stars are out of scope — skipped, not guessed.
  }
  return dirs;
}

/** Workspace patterns from pnpm-workspace.yaml or package.json "workspaces". */
function workspacePatterns(cwd: string): string[] {
  try {
    const doc = parseYaml(readFileSync(path.join(cwd, "pnpm-workspace.yaml"), "utf8")) as {
      packages?: unknown;
    };
    if (Array.isArray(doc?.packages)) return doc.packages.filter((p): p is string => typeof p === "string");
  } catch {
    /* not a pnpm workspace */
  }
  const rootPkg = readPackageJson(cwd);
  const ws = rootPkg?.workspaces;
  if (Array.isArray(ws)) return ws.filter((p): p is string => typeof p === "string");
  if (typeof ws === "object" && ws !== null && Array.isArray((ws as { packages?: unknown }).packages)) {
    return (ws as { packages: unknown[] }).packages.filter((p): p is string => typeof p === "string");
  }
  return [];
}

/** The project root + every workspace package, with their direct dep names. */
export function detectRoots(cwd: string): { roots: RootSpec[]; workspaces: string[] } {
  const roots: RootSpec[] = [];
  const rootPkg = readPackageJson(cwd);
  const projectName = rootPkg?.name ?? path.basename(cwd);
  roots.push({ name: projectName, id: `project:${projectName}`, dependencyNames: rootPkg?.deps ?? [] });

  const workspaces: string[] = [];
  for (const dir of expandWorkspaceGlobs(cwd, workspacePatterns(cwd))) {
    const pkg = readPackageJson(dir);
    if (!pkg) continue;
    const name = pkg.name ?? path.basename(dir);
    workspaces.push(name);
    roots.push({ name, id: `workspace:${name}`, dependencyNames: pkg.deps });
  }
  return { roots, workspaces };
}

/* ------------------------------------------------------- build the graph -- */

export interface BuildGraphOptions {
  /** Graph a package instead of the current project. */
  spec?: { name: string; version?: string };
  packageManager?: PackageManager;
  cwd?: string;
  policy?: LoadedPolicy | null;
  noReputation?: boolean;
  failOnOsvError?: boolean;
  concurrency?: number;
  onProgress?: (done: number, total: number) => void;
}

function riskOf(node: Pick<GraphNode, "knownMalicious" | "decision">, hardBlock: boolean, risk?: string): NodeRisk {
  if (node.knownMalicious || hardBlock) return "critical";
  if (node.decision === "block") return "high";
  if (risk === "high") return "high";
  if (risk === "medium" || node.decision === "require_approval") return "medium";
  return "low";
}

/** Compare a node against the monitor baseline snapshot — what got WORSE. */
export function riskIncreasedSince(
  node: Pick<GraphNode, "knownMalicious" | "advisories" | "deprecated" | "hasProvenance">,
  baseline: Pick<MonitorSnapshot, "knownMalicious" | "advisoryIds" | "deprecated" | "hasProvenance">,
): string[] {
  const reasons: string[] = [];
  if (node.knownMalicious && !baseline.knownMalicious) {
    reasons.push("known-malicious record appeared since the baseline");
  }
  const before = new Set(baseline.advisoryIds);
  const fresh = (node.advisories ?? []).filter((id) => !before.has(id));
  if (fresh.length > 0) reasons.push(`new advisories since the baseline: ${fresh.join(", ")}`);
  if (node.deprecated && !baseline.deprecated) reasons.push("deprecated since the baseline");
  if (node.hasProvenance === false && baseline.hasProvenance) {
    reasons.push("provenance attestation present in the baseline is gone");
  }
  return reasons;
}

export async function buildDependencyGraph(opts: BuildGraphOptions = {}): Promise<DependencyGraph> {
  const cwd = opts.cwd ?? process.cwd();
  const internalScopes = opts.policy?.policy.dependencyPolicy.internalScopes;

  // 1. Targets + roots.
  let packages: TreePackage[];
  let roots: RootSpec[];
  let workspaces: string[] = [];
  let source: DependencyGraph["source"];
  let pm: PackageManager | undefined;

  if (opts.spec) {
    const metadata = await fetchPackageMetadata(opts.spec.name, opts.spec.version);
    const tree = await resolveTransitiveTree(metadata.name, metadata.version);
    packages = [{ name: metadata.name, version: metadata.version }, ...tree];
    roots = []; // the package itself is the root node
    source = "package";
  } else {
    pm = opts.packageManager ?? detectPackageManager(cwd);
    const project = await resolveProjectTree(pm, cwd);
    packages = project.packages;
    source = project.source === "lockfile" ? "project" : "resolved";
    const detected = detectRoots(cwd);
    roots = detected.roots;
    workspaces = detected.workspaces;
  }

  // Dedupe (lockfiles can repeat entries) and index versions per name.
  const seen = new Set<string>();
  packages = packages.filter((p) => {
    const id = `${p.name}@${p.version}`;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  const versionsByName = new Map<string, string[]>();
  for (const p of packages) {
    versionsByName.set(p.name, [...(versionsByName.get(p.name) ?? []), p.version]);
  }

  // 2. One batched OSV query (internal scopes excluded — their names stay private).
  let osvMap = new Map<string, OsvResult>();
  try {
    osvMap = await queryOsvBatch(packages.filter((p) => !isInternalScope(p.name, internalScopes)));
  } catch {
    /* per-package fallback inside the pipeline */
  }

  // 3. Analyze every package (deterministic; no AI) and build its node + edges.
  const edges = new Set<string>();
  let done = 0;
  const nodes = await mapLimit(packages, opts.concurrency ?? DEFAULT_CONCURRENCY, async (pkg): Promise<GraphNode> => {
    const id = `${pkg.name}@${pkg.version}`;
    let node: GraphNode;
    try {
      const { metadata, signals } = await buildPackageSignals(pkg.name, pkg.version, {
        osv: osvMap.get(id),
        noReputation: opts.noReputation,
        failOnOsvError: opts.failOnOsvError,
        policy: opts.policy,
      });
      const assessment = evaluateRules(signals);
      const score = computeSecurityScore(signals);
      // Edges from ALL declared relationships that npm may install: runtime
      // deps, optional deps (esbuild's platform binaries live here), and peer
      // deps — each drawn only when the target is actually present in the tree.
      const declared = new Set([
        ...metadata.directDependencies,
        ...(metadata.optionalDependencyNames ?? []),
        ...(metadata.peerDependencyNames ?? []),
      ]);
      for (const dep of declared) {
        for (const v of versionsByName.get(dep) ?? []) edges.add(`${id} ${dep}@${v}`);
      }
      node = {
        id,
        name: pkg.name,
        version: pkg.version,
        kind: "package",
        score: score.total,
        risk: "low",
        decision: assessment.decision,
        hasLifecycleScripts: signals.hasLifecycleScripts,
        hasNativeCode: signals.hasNativeCode,
        knownMalicious: signals.knownMalicious,
        advisories: signals.advisories.map((a) => a.id),
        deprecated: Boolean(signals.reputation.deprecated),
        hasProvenance: signals.reputation.hasProvenance,
        reasons: assessment.reasons.slice(0, 5),
      };
      node.risk = riskOf(node, isHardBlock(signals), assessment.risk);
    } catch (err) {
      node = {
        id,
        name: pkg.name,
        version: pkg.version,
        kind: "package",
        risk: "none",
        error: err instanceof Error ? err.message : String(err),
      };
    }
    opts.onProgress?.(++done, packages.length);
    return node;
  });

  // 4. Root nodes + their edges (project mode), or mark the package root.
  const nodeById = new Map(nodes.map((n) => [n.id, n]));
  const rootIds: string[] = [];
  if (opts.spec) {
    const rootId = `${packages[0].name}@${packages[0].version}`;
    rootIds.push(rootId);
  } else {
    for (const root of roots) {
      const rootNode: GraphNode = { id: root.id, name: root.name, kind: "root", risk: "none" };
      nodes.unshift(rootNode);
      nodeById.set(root.id, rootNode);
      rootIds.push(root.id);
      for (const dep of root.dependencyNames) {
        for (const v of versionsByName.get(dep) ?? []) edges.add(`${root.id} ${dep}@${v}`);
      }
    }
  }

  const edgeList: GraphEdge[] = [...edges]
    .map((key) => {
      const [from, to] = key.split(" ");
      return { from, to };
    })
    .filter((e) => nodeById.has(e.from) && nodeById.has(e.to) && e.from !== e.to);

  // 5. Direct flags + workspace reachability.
  const childrenOf = new Map<string, string[]>();
  for (const e of edgeList) childrenOf.set(e.from, [...(childrenOf.get(e.from) ?? []), e.to]);
  for (const rootId of rootIds) {
    for (const child of childrenOf.get(rootId) ?? []) {
      const n = nodeById.get(child);
      if (n && n.kind === "package") n.direct = true;
    }
  }
  for (const root of roots) {
    if (!root.id.startsWith("workspace:")) continue;
    const reachable = reachableFrom(root.id, childrenOf);
    for (const id of reachable) {
      const n = nodeById.get(id);
      if (n && n.kind === "package") n.workspaces = [...(n.workspaces ?? []), root.name];
    }
  }

  // 6. Monitor-baseline overlay (best-effort; absent baseline → no overlay).
  let baselineCompared = false;
  if (!opts.spec) {
    const baseline = await readBaseline(cwd).catch(() => null);
    if (baseline) {
      baselineCompared = true;
      for (const n of nodes) {
        if (n.kind !== "package" || n.error) continue;
        const snap = baseline.snapshots[n.id];
        if (!snap) continue;
        const worse = riskIncreasedSince(n, snap);
        if (worse.length > 0) n.riskIncreased = worse;
      }
    }
  }

  const packageNodes = nodes.filter((n) => n.kind === "package");
  const stats: GraphStats = {
    packages: packageNodes.length,
    edges: edgeList.length,
    highRisk: packageNodes.filter((n) => n.risk === "high" || n.risk === "critical").length,
    withScripts: packageNodes.filter((n) => n.hasLifecycleScripts).length,
    withNativeCode: packageNodes.filter((n) => n.hasNativeCode).length,
    deprecated: packageNodes.filter((n) => n.deprecated).length,
    malicious: packageNodes.filter((n) => n.knownMalicious).length,
    withoutProvenance: packageNodes.filter((n) => n.hasProvenance === false).length,
    riskIncreased: packageNodes.filter((n) => (n.riskIncreased?.length ?? 0) > 0).length,
    analysisErrors: packageNodes.filter((n) => n.error).length,
  };

  return { source, packageManager: pm, roots: rootIds, workspaces, nodes, edges: edgeList, stats, baselineCompared };
}

function reachableFrom(start: string, childrenOf: Map<string, string[]>): Set<string> {
  const seen = new Set<string>();
  const queue = [start];
  while (queue.length > 0) {
    const current = queue.pop()!;
    for (const child of childrenOf.get(current) ?? []) {
      if (!seen.has(child)) {
        seen.add(child);
        queue.push(child);
      }
    }
  }
  return seen;
}

/* ---------------------------------------------------------------- filter -- */

export const GRAPH_FILTERS = [
  "high-risk",
  "scripts",
  "native",
  "deprecated",
  "malicious",
  "no-provenance",
  "risk-increased",
] as const;
export type GraphFilter = (typeof GRAPH_FILTERS)[number];

export function nodeMatchesFilter(node: GraphNode, filter: GraphFilter): boolean {
  switch (filter) {
    case "high-risk":
      return node.risk === "high" || node.risk === "critical";
    case "scripts":
      return node.hasLifecycleScripts === true;
    case "native":
      return node.hasNativeCode === true;
    case "deprecated":
      return node.deprecated === true;
    case "malicious":
      return node.knownMalicious === true;
    case "no-provenance":
      return node.hasProvenance === false;
    case "risk-increased":
      return (node.riskIncreased?.length ?? 0) > 0;
  }
}

/**
 * Prune the graph to nodes matching ANY of the filters, PLUS every ancestor
 * on a path to a root — a filtered view must still show HOW a risky package
 * got into the tree, or it explains nothing.
 */
export function filterGraph(graph: DependencyGraph, filters: GraphFilter[]): DependencyGraph {
  if (filters.length === 0) return graph;
  const parentsOf = new Map<string, string[]>();
  for (const e of graph.edges) parentsOf.set(e.to, [...(parentsOf.get(e.to) ?? []), e.from]);

  const keep = new Set<string>(graph.roots);
  const queue: string[] = [];
  for (const n of graph.nodes) {
    if (n.kind === "package" && filters.some((f) => nodeMatchesFilter(n, f))) {
      keep.add(n.id);
      queue.push(n.id);
    }
  }
  while (queue.length > 0) {
    const current = queue.pop()!;
    for (const parent of parentsOf.get(current) ?? []) {
      if (!keep.has(parent)) {
        keep.add(parent);
        queue.push(parent);
      }
    }
  }

  const nodes = graph.nodes.filter((n) => keep.has(n.id));
  const edges = graph.edges.filter((e) => keep.has(e.from) && keep.has(e.to));
  return { ...graph, nodes, edges, stats: { ...graph.stats, packages: nodes.filter((n) => n.kind === "package").length, edges: edges.length } };
}

/* ------------------------------------------------------------------- why -- */

export const WHY_MAX_CHAINS = 50;

/**
 * Every dependency chain from a root down to `target` (a name, any version).
 * DFS over the reverse adjacency with a per-path cycle guard; capped at
 * WHY_MAX_CHAINS (the cap is reported by the caller).
 */
export function whyChains(graph: DependencyGraph, target: string): { chains: string[][]; truncated: boolean } {
  const parentsOf = new Map<string, string[]>();
  for (const e of graph.edges) parentsOf.set(e.to, [...(parentsOf.get(e.to) ?? []), e.from]);
  const rootSet = new Set(graph.roots);

  const targets = graph.nodes.filter((n) => n.kind === "package" && n.name === target);
  const chains: string[][] = [];
  let truncated = false;

  const walk = (id: string, path: string[]): void => {
    if (chains.length >= WHY_MAX_CHAINS) {
      truncated = true;
      return;
    }
    if (rootSet.has(id)) {
      chains.push([id, ...path]);
      return;
    }
    const parents = parentsOf.get(id) ?? [];
    if (parents.length === 0) {
      chains.push([id, ...path]); // orphan chain — still worth showing
      return;
    }
    for (const parent of parents) {
      if (path.includes(parent) || parent === id) continue; // cycle guard
      walk(parent, [id, ...path]);
    }
  };

  for (const t of targets) {
    if (rootSet.has(t.id)) chains.push([t.id]);
    else walk(t.id, []);
  }
  return { chains, truncated };
}
