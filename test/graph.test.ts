import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import * as tar from "tar";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { graphCommand, parseOnly } from "../src/commands/graph.js";
import {
  buildDependencyGraph,
  detectRoots,
  expandWorkspaceGlobs,
  filterGraph,
  nodeMatchesFilter,
  riskIncreasedSince,
  whyChains,
  type DependencyGraph,
  type GraphNode,
} from "../src/graph.js";
import { layoutGraph } from "../src/graph-layout.js";
import {
  escapeHtml,
  renderGraphDot,
  renderGraphHtml,
  renderGraphMermaid,
  renderGraphSvg,
  MERMAID_MAX_NODES,
} from "../src/graph-render.js";
import { resetNpmrcCacheForTests } from "../src/npmrc.js";
import { resetReputationCacheForTests } from "../src/reputation.js";

let dir: string;
let cwd: string;

async function buildTarball(pkg: FakePkg): Promise<Buffer> {
  const work = await mkdtemp(path.join(tmpdir(), "targate-tgz-"));
  try {
    await mkdir(path.join(work, "package"));
    await writeFile(
      path.join(work, "package", "package.json"),
      JSON.stringify({
        name: pkg.name,
        version: pkg.version,
        scripts: pkg.scripts ?? {},
        dependencies: pkg.deps ?? {},
        optionalDependencies: pkg.optionalDeps ?? {},
      }),
    );
    const file = path.join(work, "p.tgz");
    await tar.c({ gzip: true, cwd: work, file }, ["package"]);
    return await readFile(file);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

interface FakePkg {
  name: string;
  version: string;
  deps?: Record<string, string>;
  optionalDeps?: Record<string, string>;
  scripts?: Record<string, string>;
  malicious?: boolean;
  deprecated?: string;
}

function stubNetwork(pkgs: FakePkg[]): void {
  const byName = new Map(pkgs.map((p) => [p.name, p]));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith(".tgz")) {
        const name = decodeURIComponent(url.split("/").at(-3) ?? "");
        const pkg = byName.get(name)!;
        const bytes = await buildTarball(pkg);
        return { ok: true, status: 200, arrayBuffer: async () => bytes };
      }
      if (url.includes("api.osv.dev")) {
        const body = init?.body ? JSON.parse(String(init.body)) : {};
        if (Array.isArray(body.queries)) {
          const results = body.queries.map((q: { package: { name: string } }) =>
            byName.get(q.package.name)?.malicious ? { vulns: [{ id: "MAL-2026-7" }] } : {},
          );
          return { ok: true, status: 200, json: async () => ({ results }) };
        }
        return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
      }
      if (url.includes("api.npmjs.org") || url.includes("api.github.com")) {
        return { ok: true, status: 200, headers: new Headers(), json: async () => ({}) };
      }
      const name = decodeURIComponent(url.split("/").pop() ?? "");
      const p = byName.get(name);
      if (!p) return { ok: false, status: 404, json: async () => ({}) };
      return {
        ok: true,
        status: 200,
        json: async () => ({
          "dist-tags": { latest: p.version },
          versions: {
            [p.version]: {
              name: p.name,
              dist: { tarball: `https://registry.npmjs.org/${p.name}/-/x.tgz` },
              maintainers: [{ name: "alice" }],
              repository: { url: `https://github.com/x/${p.name}` },
              scripts: p.scripts ?? {},
              dependencies: p.deps ?? {},
              optionalDependencies: p.optionalDeps ?? {},
              ...(p.deprecated ? { deprecated: p.deprecated } : {}),
            },
          },
          time: { created: "2019-01-01T00:00:00Z", [p.version]: "2019-01-01T00:00:00Z" },
        }),
      };
    }),
  );
}

/** Write a minimal npm lockfile (v3 shape) for the given packages. */
async function writeLockfile(pkgs: FakePkg[]): Promise<void> {
  const packages: Record<string, { version: string }> = {};
  for (const p of pkgs) packages[`node_modules/${p.name}`] = { version: p.version };
  await writeFile(
    path.join(dir, "package-lock.json"),
    JSON.stringify({ name: "demo", lockfileVersion: 3, packages }),
  );
}

beforeEach(async () => {
  cwd = process.cwd();
  dir = await mkdtemp(path.join(tmpdir(), "targate-graph-"));
  process.chdir(dir);
  resetNpmrcCacheForTests();
  resetReputationCacheForTests();
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.chdir(cwd);
  await rm(dir, { recursive: true, force: true });
});

const PKGS: FakePkg[] = [
  { name: "app-lib", version: "1.0.0", deps: { "sub-lib": "^2.0.0" } },
  { name: "sub-lib", version: "2.0.0" },
  { name: "native-tool", version: "3.0.0", optionalDeps: { "native-bin": "3.0.0" }, scripts: { postinstall: "node i.js" } },
  { name: "native-bin", version: "3.0.0" },
  { name: "evil-pkg", version: "0.0.1", malicious: true },
];

async function demoProject(): Promise<void> {
  await writeFile(
    path.join(dir, "package.json"),
    JSON.stringify({
      name: "demo",
      version: "1.0.0",
      dependencies: { "app-lib": "^1.0.0", "native-tool": "^3.0.0", "evil-pkg": "*" },
    }),
  );
  await writeLockfile(PKGS);
}

describe("buildDependencyGraph", () => {
  it("builds nodes with risk data and edges incl. optional deps; roots wired", async () => {
    await demoProject();
    stubNetwork(PKGS);
    const graph = await buildDependencyGraph({ noReputation: true, cwd: dir });

    expect(graph.source).toBe("project");
    expect(graph.roots).toEqual(["project:demo"]);
    const ids = graph.nodes.map((n) => n.id);
    expect(ids).toContain("app-lib@1.0.0");
    expect(ids).toContain("project:demo");

    const edgeSet = new Set(graph.edges.map((e) => `${e.from}>${e.to}`));
    expect(edgeSet.has("project:demo>app-lib@1.0.0")).toBe(true);
    expect(edgeSet.has("app-lib@1.0.0>sub-lib@2.0.0")).toBe(true);
    expect(edgeSet.has("native-tool@3.0.0>native-bin@3.0.0")).toBe(true); // optionalDependencies

    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    expect(byId.get("evil-pkg@0.0.1")!.risk).toBe("critical");
    expect(byId.get("evil-pkg@0.0.1")!.knownMalicious).toBe(true);
    expect(byId.get("native-tool@3.0.0")!.hasLifecycleScripts).toBe(true);
    expect(byId.get("app-lib@1.0.0")!.direct).toBe(true);
    expect(byId.get("sub-lib@2.0.0")!.direct).toBeUndefined();
    expect(byId.get("sub-lib@2.0.0")!.score).toBeGreaterThan(0);

    expect(graph.stats.malicious).toBe(1);
    expect(graph.stats.withScripts).toBe(1);
  });

  it("marks packages whose analysis failed instead of dying", async () => {
    await writeFile(path.join(dir, "package.json"), JSON.stringify({ name: "demo", dependencies: { ghost: "*" } }));
    await writeLockfile([{ name: "ghost", version: "9.9.9" }]);
    stubNetwork([]); // registry knows nothing
    const graph = await buildDependencyGraph({ noReputation: true, cwd: dir });
    const ghost = graph.nodes.find((n) => n.id === "ghost@9.9.9")!;
    expect(ghost.error).toBeTruthy();
    expect(ghost.risk).toBe("none");
    expect(graph.stats.analysisErrors).toBe(1);
  });
});

describe("workspaces", () => {
  it("expandWorkspaceGlobs handles exact dirs and single-star patterns only", async () => {
    await mkdir(path.join(dir, "packages", "ui"), { recursive: true });
    await mkdir(path.join(dir, "packages", "api"), { recursive: true });
    await mkdir(path.join(dir, "docs"));
    const found = expandWorkspaceGlobs(dir, ["packages/*", "docs", "apps/**"]);
    expect(found.map((d) => path.basename(d)).sort()).toEqual(["api", "docs", "ui"]);
  });

  it("detectRoots yields the project plus each workspace with its deps", async () => {
    await writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "mono", workspaces: ["packages/*"], dependencies: { "app-lib": "^1" } }),
    );
    await mkdir(path.join(dir, "packages", "ui"), { recursive: true });
    await writeFile(
      path.join(dir, "packages", "ui", "package.json"),
      JSON.stringify({ name: "@mono/ui", dependencies: { "sub-lib": "^2" } }),
    );
    const { roots, workspaces } = detectRoots(dir);
    expect(workspaces).toEqual(["@mono/ui"]);
    expect(roots.map((r) => r.id)).toEqual(["project:mono", "workspace:@mono/ui"]);
    expect(roots[1].dependencyNames).toEqual(["sub-lib"]);
  });

  it("workspace reachability tags nodes and roots get edges", async () => {
    await writeFile(
      path.join(dir, "package.json"),
      JSON.stringify({ name: "mono", workspaces: ["packages/*"] }),
    );
    await mkdir(path.join(dir, "packages", "ui"), { recursive: true });
    await writeFile(
      path.join(dir, "packages", "ui", "package.json"),
      JSON.stringify({ name: "@mono/ui", dependencies: { "app-lib": "^1.0.0" } }),
    );
    await writeLockfile([PKGS[0], PKGS[1]]);
    stubNetwork([PKGS[0], PKGS[1]]);
    const graph = await buildDependencyGraph({ noReputation: true, cwd: dir });
    expect(graph.workspaces).toEqual(["@mono/ui"]);
    const app = graph.nodes.find((n) => n.id === "app-lib@1.0.0")!;
    const sub = graph.nodes.find((n) => n.id === "sub-lib@2.0.0")!;
    expect(app.workspaces).toEqual(["@mono/ui"]);
    expect(sub.workspaces).toEqual(["@mono/ui"]); // transitive reachability
  });
});

/* ---------------- pure helpers over a synthetic graph ---------------- */

function syntheticGraph(): DependencyGraph {
  const node = (id: string, extra: Partial<GraphNode> = {}): GraphNode => ({
    id,
    name: id.split("@")[0],
    version: id.includes("@") ? id.split("@")[1] : undefined,
    kind: id.startsWith("project:") ? "root" : "package",
    risk: "low",
    ...extra,
  });
  return {
    source: "project",
    roots: ["project:demo"],
    workspaces: [],
    baselineCompared: false,
    nodes: [
      node("project:demo"),
      node("a@1.0.0", { hasLifecycleScripts: true }),
      node("b@1.0.0"),
      node("c@1.0.0", { risk: "high" }),
      node("d@1.0.0"),
    ],
    edges: [
      { from: "project:demo", to: "a@1.0.0" },
      { from: "project:demo", to: "b@1.0.0" },
      { from: "a@1.0.0", to: "c@1.0.0" },
      { from: "b@1.0.0", to: "c@1.0.0" },
      { from: "c@1.0.0", to: "d@1.0.0" },
    ],
    stats: {
      packages: 4, edges: 5, highRisk: 1, withScripts: 1, withNativeCode: 0,
      deprecated: 0, malicious: 0, withoutProvenance: 0, riskIncreased: 0, analysisErrors: 0,
    },
  };
}

describe("filterGraph", () => {
  it("keeps matching nodes PLUS every ancestor path to the root", () => {
    const filtered = filterGraph(syntheticGraph(), ["high-risk"]);
    const ids = filtered.nodes.map((n) => n.id).sort();
    // c matches; a and b are its parents; d (child of c, low risk) is pruned.
    expect(ids).toEqual(["a@1.0.0", "b@1.0.0", "c@1.0.0", "project:demo"]);
    expect(filtered.edges).toHaveLength(4);
  });

  it("union of several filters; empty filter list is identity", () => {
    const g = syntheticGraph();
    expect(filterGraph(g, [])).toBe(g);
    const filtered = filterGraph(g, ["scripts", "high-risk"]);
    expect(filtered.nodes.map((n) => n.id)).toContain("a@1.0.0");
    expect(filtered.nodes.map((n) => n.id)).toContain("c@1.0.0");
  });

  it("nodeMatchesFilter covers every advertised filter", () => {
    const n: GraphNode = {
      id: "x@1", name: "x", kind: "package", risk: "critical",
      hasLifecycleScripts: true, hasNativeCode: true, deprecated: true,
      knownMalicious: true, hasProvenance: false, riskIncreased: ["r"],
    };
    for (const f of ["high-risk", "scripts", "native", "deprecated", "malicious", "no-provenance", "risk-increased"] as const) {
      expect(nodeMatchesFilter(n, f), f).toBe(true);
    }
  });
});

describe("whyChains", () => {
  it("finds every chain from the root to the target", () => {
    const { chains, truncated } = whyChains(syntheticGraph(), "c");
    expect(truncated).toBe(false);
    expect(chains.map((c) => c.join(" > ")).sort()).toEqual([
      "project:demo > a@1.0.0 > c@1.0.0",
      "project:demo > b@1.0.0 > c@1.0.0",
    ]);
  });

  it("tolerates cycles and reports a missing package as zero chains", () => {
    const g = syntheticGraph();
    g.edges.push({ from: "d@1.0.0", to: "a@1.0.0" }); // cycle a→c→d→a
    expect(whyChains(g, "d").chains.length).toBeGreaterThan(0);
    expect(whyChains(g, "not-here").chains).toEqual([]);
  });
});

describe("riskIncreasedSince", () => {
  const baseline = { knownMalicious: false, advisoryIds: ["GHSA-old"], deprecated: false as const, hasProvenance: true };
  it("flags only what got worse", () => {
    expect(
      riskIncreasedSince(
        { knownMalicious: true, advisories: ["GHSA-old", "GHSA-new"], deprecated: true, hasProvenance: false },
        baseline,
      ),
    ).toHaveLength(4);
    expect(
      riskIncreasedSince({ knownMalicious: false, advisories: ["GHSA-old"], deprecated: false, hasProvenance: true }, baseline),
    ).toEqual([]);
  });
});

describe("layoutGraph", () => {
  it("positions every node with layers monotone along acyclic edges", () => {
    const g = syntheticGraph();
    const layout = layoutGraph(g);
    expect(layout.nodes.size).toBe(g.nodes.length);
    for (const e of g.edges) {
      expect(layout.nodes.get(e.to)!.layer).toBeGreaterThan(layout.nodes.get(e.from)!.layer);
    }
    expect(layout.width).toBeGreaterThan(0);
    expect(layout.height).toBeGreaterThan(0);
  });

  it("terminates on cyclic graphs", () => {
    const g = syntheticGraph();
    g.edges.push({ from: "d@1.0.0", to: "a@1.0.0" });
    expect(() => layoutGraph(g)).not.toThrow();
    expect(layoutGraph(g).nodes.size).toBe(g.nodes.length);
  });

  // Regression: a root with dozens of direct deps put every child in one layer,
  // producing a single row ~11000px wide and a ~17:1 aspect ratio that rendered
  // as a ~70px-tall strip once scaled to a page. The layer must now wrap.
  it("wraps a wide layer so the aspect ratio stays page-like", () => {
    const nodes: DependencyGraph["nodes"] = [
      { id: "root@1.0.0", name: "root", version: "1.0.0", risk: "low", kind: "root" },
    ];
    const edges: DependencyGraph["edges"] = [];
    for (let i = 0; i < 60; i++) {
      const id = `dep-${i}@1.0.0`;
      nodes.push({ id, name: `dep-${i}`, version: "1.0.0", risk: "low", kind: "dependency" });
      edges.push({ from: "root@1.0.0", to: id });
    }
    const g: DependencyGraph = { ...syntheticGraph(), nodes, edges, roots: ["root@1.0.0"] };
    const layout = layoutGraph(g);
    expect(layout.nodes.size).toBe(nodes.length);
    // 60 children can't fit one capped row, so they wrap onto several — the
    // drawing is no longer a thin strip.
    expect(layout.width / layout.height).toBeLessThan(6);
    // Semantic layering is still intact: every child sits below the root.
    for (const e of edges) {
      expect(layout.nodes.get(e.to)!.layer).toBeGreaterThan(layout.nodes.get(e.from)!.layer);
    }
  });
});

describe("renderers", () => {
  it("HTML embeds the data, controls, and script; hostile names cannot escape", () => {
    const g = syntheticGraph();
    g.nodes.push({
      id: '<img src=x onerror=alert(1)>@1.0.0',
      name: '<img src=x onerror=alert(1)>',
      version: "1.0.0",
      kind: "package",
      risk: "low",
    });
    const html = renderGraphHtml(g, "t <script>");
    expect(html).toContain('id="data"');
    expect(html).toContain("data-filter=\"high-risk\"");
    expect(html).not.toContain("<img src=x onerror"); // escaped in SVG markup
    expect(html).not.toContain("<script>alert"); // sanity
    // Embedded JSON escapes "<" so "</script>" in a name can't close the block.
    expect(html).not.toMatch(/<\/script><script>alert/);
    expect(html.split("\\u003c").length).toBeGreaterThan(1);
  });

  it("SVG renders nodes, edges, and badges", () => {
    const svg = renderGraphSvg(syntheticGraph());
    expect(svg).toContain("<svg");
    expect(svg).toContain('data-id="c@1.0.0"');
    expect(svg).toContain("⚙"); // lifecycle badge on a@1.0.0
    expect((svg.match(/class="edge"/g) ?? []).length).toBe(5);
  });

  it("DOT quotes ids and colors by risk", () => {
    const dot = renderGraphDot(syntheticGraph());
    expect(dot).toContain('digraph targate');
    expect(dot).toContain('"c@1.0.0"');
    expect(dot).toContain('"project:demo" -> "a@1.0.0"');
  });

  it("Mermaid aliases ids, classes by risk, and caps node count", () => {
    const mermaid = renderGraphMermaid(syntheticGraph());
    expect(mermaid).toContain("flowchart TD");
    expect(mermaid).toContain(':::risk_high');
    expect(mermaid).toContain("classDef risk_critical");

    const big = syntheticGraph();
    for (let i = 0; i < MERMAID_MAX_NODES + 10; i++) {
      big.nodes.push({ id: `p${i}@1.0.0`, name: `p${i}`, version: "1.0.0", kind: "package", risk: "low" });
    }
    expect(renderGraphMermaid(big)).toContain("truncated");
  });

  it("escapeHtml neutralizes markup metacharacters", () => {
    expect(escapeHtml(`<a b="c">&'`)).toBe("&lt;a b=&quot;c&quot;&gt;&amp;&#39;");
  });
});

describe("graphCommand", () => {
  it("parseOnly validates filters", () => {
    expect(parseOnly(undefined)).toEqual([]);
    expect(parseOnly("high-risk, scripts")).toEqual(["high-risk", "scripts"]);
    expect(parseOnly("bogus")).toBeNull();
  });

  it("--json prints a single enveloped document", async () => {
    await demoProject();
    stubNetwork(PKGS);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    const code = await graphCommand({ json: true, noReputation: true });
    expect(code).toBe(0);
    const doc = JSON.parse(logs.join("\n"));
    expect(doc.schemaVersion).toBe(1);
    expect(doc.command).toBe("graph");
    expect(doc.stats.malicious).toBe(1);
    expect(doc.nodes.length).toBeGreaterThan(0);
  });

  it("--why prints risk-annotated chains", async () => {
    await demoProject();
    stubNetwork(PKGS);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    const code = await graphCommand({ json: false, noReputation: true, why: "sub-lib" });
    expect(code).toBe(0);
    const out = logs.join("\n");
    expect(out).toContain("Why is sub-lib in the tree?");
    expect(out).toContain("app-lib@1.0.0");
  });

  it("rejects an unknown --format and --only", async () => {
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...a) => errors.push(a.join(" ")));
    expect(await graphCommand({ json: false, format: "png" })).toBe(1);
    expect(await graphCommand({ json: false, only: "nope" })).toBe(1);
    expect(errors.join("\n")).toContain("Unknown --format");
    expect(errors.join("\n")).toContain("Unknown --only");
  });

  it("writes the html file and mentions it", async () => {
    await demoProject();
    stubNetwork(PKGS);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...a) => logs.push(a.join(" ")));
    const out = path.join(dir, "out.html");
    const code = await graphCommand({ json: false, noReputation: true, output: out });
    expect(code).toBe(0);
    const html = await readFile(out, "utf8");
    expect(html).toContain("<!doctype html>");
    expect(logs.join("\n")).toContain("out.html");
  });
});
