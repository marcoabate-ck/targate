import readline from "node:readline";
import { bold, dim, green, red } from "./report.js";

/**
 * Minimal arrow-key multi-select for the terminal (no dependency): used to
 * approve flagged packages in one interactive step instead of telling the
 * user to run `targate approve <pkg>` N times. TTY-only by design — in any
 * non-interactive context (pipes, CI, --json) the caller falls back to the
 * plain textual suggestion.
 */

export interface SelectItem {
  label: string;
  /** Shown dimmed after the label (e.g. the decision that flagged it). */
  hint?: string;
  /** Not selectable and skipped by the cursor (e.g. a HARD block). */
  disabled?: boolean;
}

export interface SelectState {
  cursor: number;
  selected: Set<number>;
}

export type SelectKey = "up" | "down" | "space" | "all" | "confirm" | "cancel";

function nextEnabled(items: SelectItem[], from: number, step: 1 | -1): number {
  const n = items.length;
  let i = from;
  for (let hops = 0; hops < n; hops++) {
    i = (i + step + n) % n;
    if (!items[i].disabled) return i;
  }
  return from; // everything disabled — cursor stays put
}

/** First selectable index (initial cursor position). */
export function initialSelectState(items: SelectItem[]): SelectState {
  const first = items.findIndex((i) => !i.disabled);
  return { cursor: first === -1 ? 0 : first, selected: new Set() };
}

/**
 * Pure keypress reducer — all the selection logic lives here so it is unit-
 * testable without a TTY. The I/O shell (multiSelect) only maps raw keys to
 * SelectKey and re-renders.
 */
export function reduceSelectKey(
  state: SelectState,
  key: SelectKey,
  items: SelectItem[],
): SelectState {
  switch (key) {
    case "up":
      return { ...state, cursor: nextEnabled(items, state.cursor, -1) };
    case "down":
      return { ...state, cursor: nextEnabled(items, state.cursor, 1) };
    case "space": {
      if (items[state.cursor]?.disabled) return state;
      const selected = new Set(state.selected);
      if (selected.has(state.cursor)) selected.delete(state.cursor);
      else selected.add(state.cursor);
      return { ...state, selected };
    }
    case "all": {
      const enabled = items.map((it, i) => (it.disabled ? -1 : i)).filter((i) => i >= 0);
      const allSelected = enabled.every((i) => state.selected.has(i));
      return { ...state, selected: new Set(allSelected ? [] : enabled) };
    }
    default:
      return state;
  }
}

function renderItem(item: SelectItem, index: number, state: SelectState): string {
  const cursor = index === state.cursor ? "❯" : " ";
  if (item.disabled) {
    return red(`  ✗ ${item.label}`) + (item.hint ? dim(` — ${item.hint}`) : "");
  }
  const box = state.selected.has(index) ? green("◉") : "◯";
  const label = index === state.cursor ? bold(item.label) : item.label;
  return `${cursor} ${box} ${label}` + (item.hint ? dim(` — ${item.hint}`) : "");
}

/** Injectable I/O — production uses process.stdin/stdout; tests use mock TTYs. */
export interface SelectIo {
  input?: NodeJS.ReadStream & { isTTY?: boolean };
  output?: NodeJS.WriteStream & { isTTY?: boolean };
}

/**
 * Show the picker and resolve with the selected indices, or null when the
 * user cancels (q / esc / ctrl-c), stdin ends, or the terminal is not
 * interactive.
 */
export async function multiSelect(
  title: string,
  items: SelectItem[],
  footer?: string,
  io: SelectIo = {},
): Promise<number[] | null> {
  const stdin = io.input ?? process.stdin;
  const out = io.output ?? process.stdout;
  if (!stdin.isTTY || !out.isTTY || items.length === 0) return null;
  let state = initialSelectState(items);
  // title + items + footer + keys-help
  const lineCount = items.length + (footer ? 1 : 0) + 2;

  const render = (first: boolean): void => {
    if (!first) out.write(`\x1b[${lineCount}A`); // back to the top of the block
    const lines = [
      bold(title),
      ...items.map((item, i) => renderItem(item, i, state)),
      dim("↑/↓ move · space select · a all · enter confirm · q cancel"),
    ];
    if (footer) lines.push(dim(footer));
    for (const line of lines) out.write(`\x1b[2K${line}\n`);
  };

  readline.emitKeypressEvents(stdin);
  const wasRaw = stdin.isRaw;
  stdin.setRawMode?.(true);
  stdin.resume();
  out.write("\x1b[?25l"); // hide cursor
  render(true);

  try {
    return await new Promise<number[] | null>((resolve) => {
      const finish = (value: number[] | null): void => {
        stdin.removeListener("keypress", onKey);
        stdin.removeListener("end", onEnd);
        stdin.removeListener("close", onEnd);
        resolve(value);
      };
      // If stdin ends/closes (detached terminal, exhausted pipe), no key can
      // ever arrive — treat it as cancel instead of hanging forever.
      const onEnd = (): void => finish(null);
      const onKey = (_str: string, key: { name?: string; ctrl?: boolean }): void => {
        let action: SelectKey | null = null;
        if (key.ctrl && key.name === "c") action = "cancel";
        else if (key.name === "up" || key.name === "k") action = "up";
        else if (key.name === "down" || key.name === "j") action = "down";
        else if (key.name === "space") action = "space";
        else if (key.name === "a") action = "all";
        else if (key.name === "return") action = "confirm";
        else if (key.name === "escape" || key.name === "q") action = "cancel";
        if (!action) return;

        if (action === "confirm" || action === "cancel") {
          finish(action === "confirm" ? [...state.selected].sort((a, b) => a - b) : null);
          return;
        }
        state = reduceSelectKey(state, action, items);
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
