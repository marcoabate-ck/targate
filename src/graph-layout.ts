import type { DependencyGraph, GraphEdge, GraphNode } from "./graph.js";

/**
 * Layered DAG layout (Sugiyama-lite), computed at generation time so every
 * output format — interactive HTML, static SVG — shares identical, stable
 * positions and the browser ships zero layout code:
 *
 *   1. drop back-edges (npm graphs CAN cycle) via DFS so layering terminates;
 *   2. longest-path layering from the roots (a node sits below its deepest
 *      parent — dependency arrows always point downward);
 *   3. a few barycenter sweeps to reduce crossings;
 *   4. coordinates: label-sized boxes, centered layers.
 */

export interface PositionedNode {
  id: string;
  x: number; // center
  y: number; // center
  width: number;
  height: number;
  layer: number;
}

export interface GraphLayout {
  nodes: Map<string, PositionedNode>;
  /** Edges that survived cycle-breaking (all edges are still DRAWN; back-edges
   *  just don't constrain layering). */
  width: number;
  height: number;
}

export const NODE_HEIGHT = 34;
const LAYER_GAP = 56;
const COLUMN_GAP = 22;
const CHAR_WIDTH = 7.3;
const MIN_NODE_WIDTH = 70;
const MAX_NODE_WIDTH = 280;
const PADDING = 40;
const BARYCENTER_SWEEPS = 4;

export function nodeWidth(label: string): number {
  return Math.max(MIN_NODE_WIDTH, Math.min(MAX_NODE_WIDTH, Math.round(label.length * CHAR_WIDTH) + 28));
}

/** DFS from the roots, collecting back-edges (they close cycles). */
function dropBackEdges(nodes: GraphNode[], edges: GraphEdge[], roots: string[]): GraphEdge[] {
  const childrenOf = new Map<string, GraphEdge[]>();
  for (const e of edges) childrenOf.set(e.from, [...(childrenOf.get(e.from) ?? []), e]);

  const WHITE = 0, GRAY = 1, BLACK = 2;
  const state = new Map<string, number>(nodes.map((n) => [n.id, WHITE]));
  const kept: GraphEdge[] = [];

  // Iterative DFS with an explicit stack (trees can be deep).
  const visit = (start: string): void => {
    const stack: { id: string; edgeIndex: number }[] = [{ id: start, edgeIndex: 0 }];
    state.set(start, GRAY);
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const out = childrenOf.get(frame.id) ?? [];
      if (frame.edgeIndex >= out.length) {
        state.set(frame.id, BLACK);
        stack.pop();
        continue;
      }
      const edge = out[frame.edgeIndex++];
      const s = state.get(edge.to);
      if (s === GRAY) continue; // back-edge → drop from layering
      kept.push(edge);
      if (s === WHITE) {
        state.set(edge.to, GRAY);
        stack.push({ id: edge.to, edgeIndex: 0 });
      }
    }
  };

  for (const root of roots) if (state.get(root) === WHITE) visit(root);
  for (const n of nodes) if (state.get(n.id) === WHITE) visit(n.id); // disconnected parts
  return kept;
}

export function layoutGraph(graph: DependencyGraph): GraphLayout {
  const acyclicEdges = dropBackEdges(graph.nodes, graph.edges, graph.roots);
  const parentsOf = new Map<string, string[]>();
  const childrenOf = new Map<string, string[]>();
  for (const e of acyclicEdges) {
    childrenOf.set(e.from, [...(childrenOf.get(e.from) ?? []), e.to]);
    parentsOf.set(e.to, [...(parentsOf.get(e.to) ?? []), e.from]);
  }

  // Longest-path layering over a topological order (Kahn on the acyclic set).
  const layer = new Map<string, number>();
  const indegree = new Map<string, number>(graph.nodes.map((n) => [n.id, 0]));
  for (const e of acyclicEdges) indegree.set(e.to, (indegree.get(e.to) ?? 0) + 1);
  const queue = graph.nodes.filter((n) => (indegree.get(n.id) ?? 0) === 0).map((n) => n.id);
  for (const id of queue) layer.set(id, 0);
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const child of childrenOf.get(current) ?? []) {
      layer.set(child, Math.max(layer.get(child) ?? 0, (layer.get(current) ?? 0) + 1));
      const remaining = (indegree.get(child) ?? 1) - 1;
      indegree.set(child, remaining);
      if (remaining === 0) queue.push(child);
    }
  }
  for (const n of graph.nodes) if (!layer.has(n.id)) layer.set(n.id, 0);

  // Group per layer; initial order = insertion order.
  const layers: string[][] = [];
  for (const n of graph.nodes) {
    const l = layer.get(n.id)!;
    (layers[l] ??= []).push(n.id);
  }
  for (let i = 0; i < layers.length; i++) layers[i] ??= [];

  // Barycenter sweeps: order each layer by the mean index of its neighbors.
  const indexIn = (ids: string[]): Map<string, number> => new Map(ids.map((id, i) => [id, i]));
  for (let sweep = 0; sweep < BARYCENTER_SWEEPS; sweep++) {
    const downward = sweep % 2 === 0;
    const range = downward
      ? Array.from({ length: layers.length - 1 }, (_, i) => i + 1)
      : Array.from({ length: layers.length - 1 }, (_, i) => layers.length - 2 - i);
    for (const l of range) {
      const reference = indexIn(layers[downward ? l - 1 : l + 1]);
      const neighbors = downward ? parentsOf : childrenOf;
      const scored = layers[l].map((id, i) => {
        const linked = (neighbors.get(id) ?? []).map((n) => reference.get(n)).filter((v): v is number => v !== undefined);
        return { id, key: linked.length > 0 ? linked.reduce((a, b) => a + b, 0) / linked.length : i };
      });
      scored.sort((a, b) => a.key - b.key);
      layers[l] = scored.map((s) => s.id);
    }
  }

  // Coordinates.
  const label = new Map(graph.nodes.map((n) => [n.id, n.version ? `${n.name}@${n.version}` : n.name]));
  const positioned = new Map<string, PositionedNode>();
  let maxRowWidth = 0;
  const rowWidths = layers.map((row) =>
    row.reduce((sum, id) => sum + nodeWidth(label.get(id) ?? id) + COLUMN_GAP, -COLUMN_GAP),
  );
  maxRowWidth = Math.max(0, ...rowWidths);

  layers.forEach((row, l) => {
    let x = PADDING + (maxRowWidth - rowWidths[l]) / 2;
    for (const id of row) {
      const w = nodeWidth(label.get(id) ?? id);
      positioned.set(id, {
        id,
        x: x + w / 2,
        y: PADDING + l * (NODE_HEIGHT + LAYER_GAP) + NODE_HEIGHT / 2,
        width: w,
        height: NODE_HEIGHT,
        layer: l,
      });
      x += w + COLUMN_GAP;
    }
  });

  return {
    nodes: positioned,
    width: maxRowWidth + PADDING * 2,
    height: PADDING * 2 + layers.length * NODE_HEIGHT + (layers.length - 1) * LAYER_GAP,
  };
}
