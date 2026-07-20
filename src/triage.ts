import readline from "node:readline";
import { bold, cyan, dim, green, red, yellow } from "./report.js";

/**
 * Interactive three-way triage picker for flagged packages (no dependency).
 * Where `multiSelect` is a binary approve/skip, this lets a human walk the
 * flagged list with the arrow keys and, per package, choose to APPROVE it
 * (recorded in .targate/approvals.json), DENY it (recorded in
 * .targate/denials.json so it is never re-offered), or SKIP it (decide later).
 * Approvals default to no-scripts; a per-item toggle upgrades one to allow its
 * lifecycle scripts. A live detail panel shows the highlighted package's
 * verdict so the decision is informed without leaving the picker.
 *
 * TTY-only by design — in any non-interactive context (pipes, CI, --json) the
 * caller falls back to the plain textual `targate approve` suggestion.
 */

export type TriageDecision = "skip" | "approve" | "deny";

/** The verdict detail shown in the side panel for the highlighted package. */
export interface TriageDetail {
  decision: string;
  risk: string;
  summary: string;
  reasons: string[];
  recommendedAction?: string;
  /** "ai" | "rules". */
  source?: string;
  /** Extra one-line facts (native surface, requested capabilities, artifact digest). */
  facts?: string[];
}

export interface TriageItem {
  label: string;
  detail: TriageDetail;
  /** A HARD block — can never be approved or denied away; shown read-only. */
  disabled?: boolean;
}

export interface TriageItemState {
  decision: TriageDecision;
  /** Only meaningful when decision === "approve": allow lifecycle scripts. */
  scripts: boolean;
}

export interface TriageState {
  cursor: number;
  items: TriageItemState[];
}

export type TriageKey =
  | "up"
  | "down"
  | "approve"
  | "deny"
  | "scripts"
  | "confirm"
  | "cancel";

export interface TriageResult {
  /** Indices approved, with their per-item scripts choice. */
  approve: { index: number; scripts: boolean }[];
  /** Indices denied. */
  deny: number[];
}

function nextEnabled(items: TriageItem[], from: number, step: 1 | -1): number {
  const n = items.length;
  let i = from;
  for (let hops = 0; hops < n; hops++) {
    i = (i + step + n) % n;
    if (!items[i].disabled) return i;
  }
  return from; // everything disabled — cursor stays put
}

/** First selectable index and an all-skip decision vector. */
export function initialTriageState(items: TriageItem[]): TriageState {
  const first = items.findIndex((i) => !i.disabled);
  return {
    cursor: first === -1 ? 0 : first,
    items: items.map(() => ({ decision: "skip", scripts: false })),
  };
}

/**
 * Pure keypress reducer — all triage logic lives here so it is unit-testable
 * without a TTY. Pressing the same action twice on an item toggles it back to
 * "skip"; the scripts toggle only affects an already-approved item.
 */
export function reduceTriageKey(
  state: TriageState,
  key: TriageKey,
  items: TriageItem[],
): TriageState {
  switch (key) {
    case "up":
      return { ...state, cursor: nextEnabled(items, state.cursor, -1) };
    case "down":
      return { ...state, cursor: nextEnabled(items, state.cursor, 1) };
    case "approve":
    case "deny": {
      if (items[state.cursor]?.disabled) return state;
      const target: TriageDecision = key === "approve" ? "approve" : "deny";
      const current = state.items[state.cursor];
      const next = current.decision === target ? "skip" : target;
      const nextItems = state.items.slice();
      nextItems[state.cursor] = {
        decision: next,
        // Leaving "approve" clears the scripts choice so it can't linger.
        scripts: next === "approve" ? current.scripts : false,
      };
      return { ...state, items: nextItems };
    }
    case "scripts": {
      if (items[state.cursor]?.disabled) return state;
      const current = state.items[state.cursor];
      if (current.decision !== "approve") return state; // scripts only apply to approvals
      const nextItems = state.items.slice();
      nextItems[state.cursor] = { ...current, scripts: !current.scripts };
      return { ...state, items: nextItems };
    }
    default:
      return state;
  }
}

/** Project the decision vector into the result buckets. */
export function collectTriageResult(state: TriageState): TriageResult {
  const approve: { index: number; scripts: boolean }[] = [];
  const deny: number[] = [];
  state.items.forEach((it, index) => {
    if (it.decision === "approve") approve.push({ index, scripts: it.scripts });
    else if (it.decision === "deny") deny.push(index);
  });
  return { approve, deny };
}

function marker(item: TriageItem, decision: TriageItemState): string {
  if (item.disabled) return red("✗");
  switch (decision.decision) {
    case "approve":
      return green(decision.scripts ? "●" : "◉");
    case "deny":
      return red("✗");
    default:
      return dim("○");
  }
}

function renderItem(item: TriageItem, index: number, state: TriageState): string {
  const focused = index === state.cursor;
  const cursor = focused ? cyan("❯") : " ";
  const decision = state.items[index];
  const label = focused ? bold(item.label) : item.label;
  let tag = "";
  if (item.disabled) tag = dim(" — HARD block, cannot be approved");
  else if (decision.decision === "approve") {
    tag = decision.scripts ? green("  approve · scripts") : green("  approve · no-scripts");
  } else if (decision.decision === "deny") tag = red("  deny");
  return `${cursor} ${marker(item, decision)} ${label}${tag}`;
}

/** Render the detail panel for the highlighted item. Pure; returns styled lines. */
export function renderTriageDetail(item: TriageItem): string[] {
  const d = item.detail;
  const lines: string[] = [dim("─ package details ─────────────────────")];
  const verdict = `${d.decision} · risk ${d.risk}${d.source ? dim(` · via ${d.source}`) : ""}`;
  lines.push(bold(item.label));
  lines.push(d.risk === "high" ? red(verdict) : yellow(verdict));
  if (d.summary) lines.push(d.summary);
  for (const reason of d.reasons.slice(0, 4)) lines.push(dim(`  • ${reason}`));
  if (d.recommendedAction) lines.push(dim(`  recommended: ${d.recommendedAction}`));
  for (const fact of d.facts ?? []) lines.push(dim(`  ${fact}`));
  return lines;
}

/** Injectable I/O — production uses process.stdin/stdout; tests use mock TTYs. */
export interface TriageIo {
  input?: NodeJS.ReadStream & { isTTY?: boolean };
  output?: NodeJS.WriteStream & { isTTY?: boolean };
}

/**
 * Show the triage picker and resolve with the approve/deny buckets, or null
 * when the user cancels (q / esc / ctrl-c), stdin ends, or the terminal is not
 * interactive.
 */
export async function triage(
  title: string,
  items: TriageItem[],
  footer?: string,
  io: TriageIo = {},
): Promise<TriageResult | null> {
  const stdin = io.input ?? process.stdin;
  const out = io.output ?? process.stdout;
  if (!stdin.isTTY || !out.isTTY || items.length === 0) return null;
  let state = initialTriageState(items);
  let prevLines = 0;

  const frame = (): string[] => {
    const lines = [
      bold(title),
      ...items.map((item, i) => renderItem(item, i, state)),
      dim("↑/↓ move · a approve · d deny · s scripts · enter confirm · q cancel"),
    ];
    if (footer) lines.push(dim(footer));
    lines.push("");
    lines.push(...renderTriageDetail(items[state.cursor] ?? items[0]));
    return lines;
  };

  const render = (first: boolean): void => {
    if (!first && prevLines > 0) {
      out.write(`\x1b[${prevLines}A`); // back to the top of the previous block
      out.write("\x1b[0J"); // clear everything below (panel height varies)
    }
    const lines = frame();
    for (const line of lines) out.write(`${line}\n`);
    prevLines = lines.length;
  };

  readline.emitKeypressEvents(stdin);
  const wasRaw = stdin.isRaw;
  stdin.setRawMode?.(true);
  stdin.resume();
  out.write("\x1b[?25l"); // hide cursor
  render(true);

  try {
    return await new Promise<TriageResult | null>((resolve) => {
      const finish = (value: TriageResult | null): void => {
        stdin.removeListener("keypress", onKey);
        stdin.removeListener("end", onEnd);
        stdin.removeListener("close", onEnd);
        resolve(value);
      };
      const onEnd = (): void => finish(null);
      const onKey = (_str: string, key: { name?: string; ctrl?: boolean }): void => {
        let action: TriageKey | null = null;
        if (key.ctrl && key.name === "c") action = "cancel";
        else if (key.name === "up" || key.name === "k") action = "up";
        else if (key.name === "down" || key.name === "j") action = "down";
        else if (key.name === "a") action = "approve";
        else if (key.name === "d") action = "deny";
        else if (key.name === "s") action = "scripts";
        else if (key.name === "return") action = "confirm";
        else if (key.name === "escape" || key.name === "q") action = "cancel";
        if (!action) return;

        if (action === "confirm" || action === "cancel") {
          finish(action === "confirm" ? collectTriageResult(state) : null);
          return;
        }
        state = reduceTriageKey(state, action, items);
        render(false);
      };
      stdin.on("keypress", onKey);
      stdin.once("end", onEnd);
      stdin.once("close", onEnd);
    });
  } finally {
    stdin.setRawMode?.(wasRaw ?? false);
    stdin.pause();
    out.write("\x1b[?25h"); // show cursor again
  }
}
