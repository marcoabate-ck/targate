import { GRAPH_FILTERS, type DependencyGraph, type GraphNode, type NodeRisk } from "./graph.js";
import { layoutGraph, type GraphLayout } from "./graph-layout.js";

/**
 * Renderers for the dependency risk graph. All of them are pure
 * string-producers over a (possibly pre-filtered) DependencyGraph:
 *
 * - HTML  — ONE self-contained interactive file: inline CSS/JS, embedded
 *           graph JSON, zero external requests (offline- and CI-artifact-safe,
 *           strict-CSP friendly). Node names are attacker-controlled strings,
 *           so EVERYTHING interpolated into markup is escaped.
 * - SVG   — the same server-side-rendered drawing, standalone.
 * - DOT   — Graphviz interchange.
 * - Mermaid — GitHub-native diagrams (PR comments, $GITHUB_STEP_SUMMARY).
 */

export const RISK_FILL: Record<NodeRisk, string> = {
  none: "#e2e8f0",
  low: "#bbf7d0",
  medium: "#fde68a",
  high: "#fdba74",
  critical: "#fca5a5",
};
const RISK_STROKE: Record<NodeRisk, string> = {
  none: "#94a3b8",
  low: "#16a34a",
  medium: "#ca8a04",
  high: "#ea580c",
  critical: "#dc2626",
};

export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function nodeLabel(node: GraphNode): string {
  return node.version ? `${node.name}@${node.version}` : node.name;
}

function badges(node: GraphNode): string {
  return [
    node.knownMalicious ? "☠" : null,
    node.hasLifecycleScripts ? "⚙" : null,
    node.hasNativeCode ? "⬢" : null,
    node.deprecated ? "⚠" : null,
    node.error ? "?" : null,
  ]
    .filter(Boolean)
    .join(" ");
}

/* ------------------------------------------------------------------- SVG -- */

/** The <svg> body shared by the standalone SVG and the interactive HTML. */
function svgBody(graph: DependencyGraph, layout: GraphLayout): string {
  const parts: string[] = [];

  parts.push(`<g class="edges">`);
  for (const e of graph.edges) {
    const from = layout.nodes.get(e.from);
    const to = layout.nodes.get(e.to);
    if (!from || !to) continue;
    const x1 = from.x, y1 = from.y + from.height / 2;
    const x2 = to.x, y2 = to.y - to.height / 2;
    const bend = Math.max(18, (y2 - y1) / 2);
    parts.push(
      `<path class="edge" data-from="${escapeHtml(e.from)}" data-to="${escapeHtml(e.to)}" d="M ${x1} ${y1} C ${x1} ${y1 + bend}, ${x2} ${y2 - bend}, ${x2} ${y2}"/>`,
    );
  }
  parts.push(`</g>`);

  parts.push(`<g class="nodes">`);
  for (const node of graph.nodes) {
    const p = layout.nodes.get(node.id);
    if (!p) continue;
    const label = escapeHtml(nodeLabel(node));
    const badge = badges(node);
    parts.push(
      [
        `<g class="node risk-${node.risk}${node.kind === "root" ? " root" : ""}${node.riskIncreased ? " risk-up" : ""}" data-id="${escapeHtml(node.id)}" transform="translate(${p.x - p.width / 2},${p.y - p.height / 2})">`,
        node.riskIncreased
          ? `<rect class="ring" x="-3" y="-3" width="${p.width + 6}" height="${p.height + 6}" rx="10"/>`
          : "",
        `<rect width="${p.width}" height="${p.height}" rx="8" fill="${RISK_FILL[node.risk]}" stroke="${RISK_STROKE[node.risk]}"/>`,
        `<text x="${p.width / 2}" y="${p.height / 2 - (badge ? 4 : 0)}" text-anchor="middle" dominant-baseline="middle">${label}</text>`,
        badge
          ? `<text class="badges" x="${p.width / 2}" y="${p.height - 6}" text-anchor="middle">${badge}</text>`
          : "",
        `</g>`,
      ].join(""),
    );
  }
  parts.push(`</g>`);
  return parts.join("\n");
}

const SVG_STYLE = `
  .edge { fill: none; stroke: #94a3b8; stroke-width: 1.1; opacity: .55; }
  .node text { font: 11px ui-monospace, SFMono-Regular, Menlo, monospace; fill: #0f172a; }
  .node .badges { font-size: 9px; }
  .node.root rect { fill: #e0e7ff; stroke: #4f46e5; stroke-width: 1.6; }
  .node .ring { fill: none; stroke: #dc2626; stroke-width: 1.6; stroke-dasharray: 4 3; }
`;

/** Standalone static SVG document (embeddable in READMEs / wikis). */
export function renderGraphSvg(graph: DependencyGraph): string {
  const layout = layoutGraph(graph);
  return [
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${layout.width} ${layout.height}" width="${layout.width}" height="${layout.height}">`,
    `<style>${SVG_STYLE}</style>`,
    `<rect width="100%" height="100%" fill="#ffffff"/>`,
    svgBody(graph, layout),
    `</svg>`,
  ].join("\n");
}

/* ------------------------------------------------------------------ HTML -- */

/** One self-contained interactive HTML document. */
export function renderGraphHtml(graph: DependencyGraph, title = "targate dependency graph"): string {
  const layout = layoutGraph(graph);
  const svg = `<svg id="graph" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${layout.width} ${layout.height}">${`<style>${SVG_STYLE}</style>`}${svgBody(graph, layout)}</svg>`;

  // Data for the client script. JSON is embedded in a <script type="application/json">
  // block; "</" is escaped so a hostile package name can never close the tag.
  const data = JSON.stringify({
    roots: graph.roots,
    workspaces: graph.workspaces,
    stats: graph.stats,
    baselineCompared: graph.baselineCompared,
    nodes: graph.nodes,
    edges: graph.edges,
  }).replace(/</g, "\\u003c");

  const s = graph.stats;
  const statLine = [
    `${s.packages} packages`,
    `${s.edges} edges`,
    `${s.highRisk} high-risk`,
    `${s.withScripts} with scripts`,
    `${s.withNativeCode} native`,
    `${s.deprecated} deprecated`,
    s.malicious > 0 ? `${s.malicious} MALICIOUS` : null,
    graph.baselineCompared ? `${s.riskIncreased} risk-increased` : null,
    s.analysisErrors > 0 ? `${s.analysisErrors} analysis errors` : null,
  ]
    .filter(Boolean)
    .join(" · ");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; --bg:#f8fafc; --fg:#0f172a; --panel:#ffffff; --border:#e2e8f0; --dim:#64748b; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0b1220; --fg:#e2e8f0; --panel:#101a2e; --border:#1e293b; --dim:#94a3b8; } }
  * { box-sizing: border-box; }
  body { margin:0; font:13px/1.45 system-ui, sans-serif; background:var(--bg); color:var(--fg); display:flex; flex-direction:column; height:100vh; }
  header { padding:10px 14px; border-bottom:1px solid var(--border); display:flex; gap:14px; align-items:baseline; flex-wrap:wrap; }
  header h1 { font-size:15px; margin:0; }
  header .stats { color:var(--dim); font-size:12px; }
  #controls { padding:8px 14px; border-bottom:1px solid var(--border); display:flex; gap:12px; align-items:center; flex-wrap:wrap; font-size:12px; }
  #controls label { display:flex; gap:4px; align-items:center; cursor:pointer; user-select:none; }
  #controls input[type=search] { padding:4px 8px; border:1px solid var(--border); border-radius:6px; background:var(--panel); color:var(--fg); min-width:180px; }
  #controls select { padding:3px 6px; border:1px solid var(--border); border-radius:6px; background:var(--panel); color:var(--fg); }
  main { flex:1; display:flex; min-height:0; }
  #viewport { flex:1; overflow:hidden; cursor:grab; position:relative; }
  #viewport.grabbing { cursor:grabbing; }
  #graph { display:block; }
  @media (prefers-color-scheme: dark) {
    .node text { fill:#0f172a; }
    .edge { stroke:#475569; }
  }
  aside { width:320px; border-left:1px solid var(--border); background:var(--panel); padding:14px; overflow:auto; display:none; }
  aside.open { display:block; }
  aside h2 { font:600 13px ui-monospace, monospace; margin:0 0 8px; word-break:break-all; }
  aside dl { margin:0; font-size:12px; }
  aside dt { color:var(--dim); margin-top:8px; }
  aside dd { margin:2px 0 0; word-break:break-word; }
  aside .close { float:right; cursor:pointer; border:none; background:none; color:var(--dim); font-size:16px; }
  .pill { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px; border:1px solid var(--border); }
  .legend { display:flex; gap:10px; align-items:center; font-size:11px; color:var(--dim); }
  .legend i { display:inline-block; width:10px; height:10px; border-radius:3px; margin-right:3px; }
  .node { cursor:pointer; }
  .node.hidden, .edge.hidden { display:none; }
  .node.dimmed { opacity:.14; }
  .edge.dimmed { opacity:.06; }
  .edge.onpath { stroke:#4f46e5; stroke-width:2; opacity:1; }
  .node.selected rect { stroke-width:2.6; }
  footer { padding:6px 14px; border-top:1px solid var(--border); color:var(--dim); font-size:11px; }
</style>
</head>
<body>
<header>
  <h1>${escapeHtml(title)}</h1>
  <span class="stats">${escapeHtml(statLine)}</span>
  <span class="legend">
    <span><i style="background:${RISK_FILL.low}"></i>low</span>
    <span><i style="background:${RISK_FILL.medium}"></i>medium</span>
    <span><i style="background:${RISK_FILL.high}"></i>high</span>
    <span><i style="background:${RISK_FILL.critical}"></i>critical</span>
    <span>⚙ scripts&nbsp; ⬢ native&nbsp; ⚠ deprecated&nbsp; ☠ malicious</span>
  </span>
</header>
<div id="controls">
  <input id="search" type="search" placeholder="search packages…">
  <label><input type="checkbox" data-filter="high-risk"> high-risk</label>
  <label><input type="checkbox" data-filter="scripts"> lifecycle scripts</label>
  <label><input type="checkbox" data-filter="native"> native code</label>
  <label><input type="checkbox" data-filter="deprecated"> deprecated</label>
  <label><input type="checkbox" data-filter="no-provenance"> no provenance</label>
  <label id="riskup-label" hidden><input type="checkbox" data-filter="risk-increased"> risk increased</label>
  <select id="workspace" hidden><option value="">all workspaces</option></select>
  <span id="visible" style="color:var(--dim)"></span>
</div>
<main>
  <div id="viewport">${svg}</div>
  <aside id="panel"><button class="close" id="panel-close">×</button><div id="panel-body"></div></aside>
</main>
<footer>Click a node for details and its paths to the root · drag to pan, wheel to zoom · filters keep the connecting paths so context is never lost · generated by targate (deterministic analysis, no AI)</footer>
<script type="application/json" id="data">${data}</script>
<script>
(function () {
  "use strict";
  var DATA = JSON.parse(document.getElementById("data").textContent);
  var byId = {}; DATA.nodes.forEach(function (n) { byId[n.id] = n; });
  var parents = {}, children = {};
  DATA.edges.forEach(function (e) {
    (parents[e.to] = parents[e.to] || []).push(e.from);
    (children[e.from] = children[e.from] || []).push(e.to);
  });
  var svg = document.getElementById("graph");
  var nodeEls = {}, edgeEls = [];
  svg.querySelectorAll(".node").forEach(function (el) { nodeEls[el.dataset.id] = el; });
  svg.querySelectorAll(".edge").forEach(function (el) { edgeEls.push(el); });

  /* ---- filters ---- */
  var matchers = {
    "high-risk": function (n) { return n.risk === "high" || n.risk === "critical"; },
    "scripts": function (n) { return n.hasLifecycleScripts === true; },
    "native": function (n) { return n.hasNativeCode === true; },
    "deprecated": function (n) { return n.deprecated === true; },
    "no-provenance": function (n) { return n.hasProvenance === false; },
    "risk-increased": function (n) { return (n.riskIncreased || []).length > 0; }
  };
  var boxes = Array.prototype.slice.call(document.querySelectorAll("[data-filter]"));
  var search = document.getElementById("search");
  var wsSelect = document.getElementById("workspace");
  if (DATA.workspaces.length > 0) {
    wsSelect.hidden = false;
    DATA.workspaces.forEach(function (w) {
      var o = document.createElement("option"); o.value = w; o.textContent = w; wsSelect.appendChild(o);
    });
  }
  if (DATA.baselineCompared) document.getElementById("riskup-label").hidden = false;

  function ancestorsOf(seed) {
    var keep = {}, stack = Object.keys(seed);
    stack.forEach(function (id) { keep[id] = true; });
    while (stack.length) {
      (parents[stack.pop()] || []).forEach(function (p) {
        if (!keep[p]) { keep[p] = true; stack.push(p); }
      });
    }
    return keep;
  }

  function applyFilters() {
    var active = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.dataset.filter; });
    var q = search.value.trim().toLowerCase();
    var ws = wsSelect.value;
    var all = active.length === 0 && !q && !ws;
    var visible = {};
    if (all) {
      DATA.nodes.forEach(function (n) { visible[n.id] = true; });
    } else {
      var seed = {};
      DATA.nodes.forEach(function (n) {
        if (n.kind !== "package") return;
        var hit = active.length === 0 || active.some(function (f) { return matchers[f](n); });
        if (hit && q) hit = n.id.toLowerCase().indexOf(q) !== -1;
        if (hit && ws) hit = (n.workspaces || []).indexOf(ws) !== -1;
        if (hit) seed[n.id] = true;
      });
      visible = ancestorsOf(seed);
      DATA.roots.forEach(function (r) { visible[r] = true; });
    }
    var count = 0;
    DATA.nodes.forEach(function (n) {
      var el = nodeEls[n.id]; if (!el) return;
      var show = Boolean(visible[n.id]);
      el.classList.toggle("hidden", !show);
      if (show && n.kind === "package") count++;
    });
    edgeEls.forEach(function (el) {
      el.classList.toggle("hidden", !(visible[el.dataset.from] && visible[el.dataset.to]));
    });
    document.getElementById("visible").textContent = all ? "" : count + " matching (+ paths to root)";
  }
  boxes.forEach(function (b) { b.addEventListener("change", applyFilters); });
  search.addEventListener("input", applyFilters);
  wsSelect.addEventListener("change", applyFilters);

  /* ---- selection: detail panel + path-to-root highlight ---- */
  var panel = document.getElementById("panel"), panelBody = document.getElementById("panel-body");
  var selected = null;
  function esc(t) { var d = document.createElement("i"); d.textContent = String(t); return d.innerHTML; }
  function clearSelection() {
    selected = null;
    panel.classList.remove("open");
    Object.keys(nodeEls).forEach(function (id) { nodeEls[id].classList.remove("dimmed", "selected"); });
    edgeEls.forEach(function (el) { el.classList.remove("dimmed", "onpath"); });
  }
  document.getElementById("panel-close").addEventListener("click", clearSelection);
  function select(id) {
    clearSelection();
    selected = id;
    var n = byId[id]; if (!n) return;
    var up = ancestorsOf(function () { var s = {}; s[id] = true; return s; }());
    Object.keys(nodeEls).forEach(function (nid) {
      nodeEls[nid].classList.toggle("dimmed", !up[nid]);
    });
    nodeEls[id].classList.add("selected");
    edgeEls.forEach(function (el) {
      var on = up[el.dataset.from] && up[el.dataset.to];
      el.classList.toggle("onpath", Boolean(on));
      el.classList.toggle("dimmed", !on);
    });
    var rows = [];
    function row(k, v) { if (v !== undefined && v !== null && v !== "") rows.push("<dt>" + k + "</dt><dd>" + v + "</dd>"); }
    row("risk", '<span class="pill">' + esc(n.risk) + "</span>" + (n.decision ? " · " + esc(n.decision) : ""));
    if (n.score !== undefined) row("security score", esc(n.score) + "/100");
    row("lifecycle scripts", n.hasLifecycleScripts === undefined ? null : n.hasLifecycleScripts ? "yes ⚙" : "no");
    row("native code", n.hasNativeCode ? "yes ⬢" : null);
    row("deprecated", n.deprecated ? "yes ⚠" : null);
    row("known malicious", n.knownMalicious ? "YES ☠" : null);
    row("advisories", (n.advisories || []).map(esc).join("<br>") || null);
    row("provenance", n.hasProvenance === undefined ? null : n.hasProvenance ? "attested" : "none");
    row("direct dependency", n.direct ? "yes" : null);
    row("workspaces", (n.workspaces || []).map(esc).join(", ") || null);
    row("risk increased", (n.riskIncreased || []).map(esc).join("<br>") || null);
    row("reasons", (n.reasons || []).map(esc).join("<br>") || null);
    row("analysis error", n.error ? esc(n.error) : null);
    row("dependencies", (children[id] || []).length + " · dependents: " + (parents[id] || []).length);
    panelBody.innerHTML = "<h2>" + esc(id) + "</h2><dl>" + rows.join("") + "</dl>";
    panel.classList.add("open");
  }
  svg.addEventListener("click", function (ev) {
    var g = ev.target.closest ? ev.target.closest(".node") : null;
    if (g) select(g.dataset.id);
    else clearSelection();
  });

  /* ---- pan & zoom (viewBox-based) ---- */
  var vb = svg.viewBox.baseVal;
  var viewport = document.getElementById("viewport");
  var dragging = null;
  viewport.addEventListener("mousedown", function (ev) {
    dragging = { x: ev.clientX, y: ev.clientY, vx: vb.x, vy: vb.y };
    viewport.classList.add("grabbing");
  });
  window.addEventListener("mousemove", function (ev) {
    if (!dragging) return;
    var scale = vb.width / viewport.clientWidth;
    vb.x = dragging.vx - (ev.clientX - dragging.x) * scale;
    vb.y = dragging.vy - (ev.clientY - dragging.y) * scale;
  });
  window.addEventListener("mouseup", function () { dragging = null; viewport.classList.remove("grabbing"); });
  viewport.addEventListener("wheel", function (ev) {
    ev.preventDefault();
    var factor = ev.deltaY > 0 ? 1.12 : 1 / 1.12;
    var rect = viewport.getBoundingClientRect();
    var px = vb.x + ((ev.clientX - rect.left) / rect.width) * vb.width;
    var py = vb.y + ((ev.clientY - rect.top) / rect.height) * vb.height;
    vb.width *= factor; vb.height *= factor;
    vb.x = px - ((ev.clientX - rect.left) / rect.width) * vb.width;
    vb.y = py - ((ev.clientY - rect.top) / rect.height) * vb.height;
  }, { passive: false });

  applyFilters();
})();
</script>
</body>
</html>
`;
}

/* ------------------------------------------------------------------- DOT -- */

function dotQuote(text: string): string {
  return `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export function renderGraphDot(graph: DependencyGraph): string {
  const lines: string[] = [
    "digraph targate {",
    "  rankdir=TB;",
    '  node [shape=box, style="rounded,filled", fontname="monospace", fontsize=10];',
    "  edge [color=gray60, arrowsize=0.6];",
  ];
  for (const n of graph.nodes) {
    const label = nodeLabel(n) + (badges(n) ? `\\n${badges(n)}` : "");
    const fill = n.kind === "root" ? "#e0e7ff" : RISK_FILL[n.risk];
    lines.push(`  ${dotQuote(n.id)} [label=${dotQuote(label)}, fillcolor="${fill}"];`);
  }
  for (const e of graph.edges) lines.push(`  ${dotQuote(e.from)} -> ${dotQuote(e.to)};`);
  lines.push("}");
  return lines.join("\n") + "\n";
}

/* --------------------------------------------------------------- Mermaid -- */

/** Mermaid chokes on big graphs — cap and say so instead of rendering mush. */
export const MERMAID_MAX_NODES = 150;

export function renderGraphMermaid(graph: DependencyGraph): string {
  const lines: string[] = ["flowchart TD"];
  const truncated = graph.nodes.length > MERMAID_MAX_NODES;
  const nodes = truncated ? graph.nodes.slice(0, MERMAID_MAX_NODES) : graph.nodes;
  const keep = new Set(nodes.map((n) => n.id));
  const alias = new Map<string, string>(nodes.map((n, i) => [n.id, `n${i}`]));

  for (const n of nodes) {
    // Mermaid labels: quotes break the parser — replace; everything else is safe inside "…".
    const label = (nodeLabel(n) + (badges(n) ? ` ${badges(n)}` : "")).replace(/"/g, "'");
    lines.push(`  ${alias.get(n.id)}["${label}"]:::risk_${n.kind === "root" ? "root" : n.risk}`);
  }
  for (const e of graph.edges) {
    if (!keep.has(e.from) || !keep.has(e.to)) continue;
    lines.push(`  ${alias.get(e.from)} --> ${alias.get(e.to)}`);
  }
  for (const [risk, fill] of Object.entries(RISK_FILL)) {
    lines.push(`  classDef risk_${risk} fill:${fill},stroke:${RISK_STROKE[risk as NodeRisk]},color:#0f172a`);
  }
  lines.push("  classDef risk_root fill:#e0e7ff,stroke:#4f46e5,color:#0f172a");
  if (truncated) {
    lines.push(
      `  %% truncated to ${MERMAID_MAX_NODES} of ${graph.nodes.length} nodes — narrow it with --only high-risk,scripts`,
    );
  }
  return lines.join("\n") + "\n";
}

/* ------------------------------------------------------------------- why -- */

/** Terminal rendering of `targate graph --why <pkg>` chains, risk-annotated. */
export function renderWhy(
  graph: DependencyGraph,
  target: string,
  chains: string[][],
  truncated: boolean,
  paint: { dim: (t: string) => string; yellow: (t: string) => string; red: (t: string) => string; bold: (t: string) => string },
): string {
  if (chains.length === 0) {
    return paint.yellow(`No dependency chain found — "${target}" is not in this tree.`);
  }
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const lines: string[] = [
    paint.bold(`Why is ${target} in the tree? ${chains.length} chain(s)${truncated ? " (truncated)" : ""}:`),
    "",
  ];
  chains.forEach((chain, i) => {
    lines.push(paint.dim(`  ${i + 1}.`));
    chain.forEach((id, depth) => {
      const node = byId.get(id);
      const risk = node?.risk ?? "none";
      const annotate =
        node?.kind === "root"
          ? paint.dim("(root)")
          : `${risk === "high" || risk === "critical" ? paint.red(risk) : risk === "medium" ? paint.yellow(risk) : paint.dim(risk)}${node?.hasLifecycleScripts ? " ⚙" : ""}${node?.knownMalicious ? paint.red(" ☠") : ""}`;
      lines.push(`  ${"  ".repeat(depth)}${depth > 0 ? "└─ " : ""}${id}  ${annotate}`);
    });
    lines.push("");
  });
  return lines.join("\n");
}
