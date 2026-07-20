import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  collectTriageResult,
  initialTriageState,
  reduceTriageKey,
  renderTriageDetail,
  triage,
  type TriageItem,
  type TriageState,
} from "../src/triage.js";

const detail = (decision: string) => ({
  decision,
  risk: "high",
  summary: "does suspicious things at install time",
  reasons: ["runs a postinstall script", "reads process.env"],
  recommendedAction: "review the install script",
  source: "rules",
});

const items: TriageItem[] = [
  { label: "a@1.0.0", detail: detail("require_approval") },
  { label: "b@2.0.0", detail: detail("block") },
  { label: "evil@9.9.9", detail: detail("block"), disabled: true }, // hard block
  { label: "c@3.0.0", detail: detail("require_approval") },
];

function state(cursor: number, decisions: ("skip" | "approve" | "deny")[] = [], scripts: boolean[] = []): TriageState {
  return {
    cursor,
    items: items.map((_, i) => ({ decision: decisions[i] ?? "skip", scripts: scripts[i] ?? false })),
  };
}

describe("initialTriageState", () => {
  it("starts on the first selectable item, everything skipped", () => {
    const s = initialTriageState(items);
    expect(s.cursor).toBe(0);
    expect(s.items.every((it) => it.decision === "skip" && !it.scripts)).toBe(true);
  });

  it("skips a leading disabled item", () => {
    expect(initialTriageState([{ label: "x", detail: detail("block"), disabled: true }, { label: "y", detail: detail("block") }]).cursor).toBe(1);
  });
});

describe("reduceTriageKey", () => {
  it("moves down/up skipping disabled items and wraps", () => {
    expect(reduceTriageKey(state(1), "down", items).cursor).toBe(3); // skips disabled 2
    expect(reduceTriageKey(state(3), "up", items).cursor).toBe(1);
    expect(reduceTriageKey(state(3), "down", items).cursor).toBe(0);
    expect(reduceTriageKey(state(0), "up", items).cursor).toBe(3);
  });

  it("approve sets and toggles back to skip", () => {
    const on = reduceTriageKey(state(0), "approve", items);
    expect(on.items[0].decision).toBe("approve");
    const off = reduceTriageKey(on, "approve", items);
    expect(off.items[0].decision).toBe("skip");
  });

  it("deny sets and toggles back to skip", () => {
    const on = reduceTriageKey(state(0), "deny", items);
    expect(on.items[0].decision).toBe("deny");
    expect(reduceTriageKey(on, "deny", items).items[0].decision).toBe("skip");
  });

  it("switching approve->deny clears the scripts flag", () => {
    let s = reduceTriageKey(state(0), "approve", items);
    s = reduceTriageKey(s, "scripts", items);
    expect(s.items[0].scripts).toBe(true);
    s = reduceTriageKey(s, "deny", items);
    expect(s.items[0]).toEqual({ decision: "deny", scripts: false });
  });

  it("scripts toggles only on an approved item", () => {
    expect(reduceTriageKey(state(0), "scripts", items).items[0].scripts).toBe(false); // skip: ignored
    const approved = reduceTriageKey(state(0), "approve", items);
    expect(reduceTriageKey(approved, "scripts", items).items[0].scripts).toBe(true);
  });

  it("approve/deny are no-ops on a disabled (hard-block) item", () => {
    expect(reduceTriageKey(state(2), "approve", items).items[2].decision).toBe("skip");
    expect(reduceTriageKey(state(2), "deny", items).items[2].decision).toBe("skip");
  });
});

describe("collectTriageResult", () => {
  it("buckets approvals (with scripts) and denials", () => {
    const s = state(0, ["approve", "deny", "skip", "approve"], [true, false, false, false]);
    expect(collectTriageResult(s)).toEqual({
      approve: [
        { index: 0, scripts: true },
        { index: 3, scripts: false },
      ],
      deny: [1],
    });
  });
});

describe("renderTriageDetail", () => {
  it("shows the label, verdict and reasons of the highlighted package", () => {
    const lines = renderTriageDetail(items[0]).join("\n");
    expect(lines).toContain("a@1.0.0");
    expect(lines).toContain("require_approval");
    expect(lines).toContain("runs a postinstall script");
  });
});

function mockTty() {
  const input = new PassThrough() as unknown as NodeJS.ReadStream & {
    isTTY: boolean;
    write(s: string): void;
  };
  Object.assign(input, { isTTY: true, isRaw: false, setRawMode: () => input });
  const written: string[] = [];
  const output = {
    isTTY: true,
    write: (s: string) => {
      written.push(s);
      return true;
    },
  } as unknown as NodeJS.WriteStream;
  return { input, output, written };
}

describe("triage (keypress shell with mock TTY)", () => {
  it("approve + enter records an approval (no-scripts by default)", async () => {
    const { input, output, written } = mockTty();
    const promise = triage("Decide", items, undefined, { input, output });
    input.write("a"); // approve item 0
    input.write("\r"); // confirm
    await expect(promise).resolves.toEqual({ approve: [{ index: 0, scripts: false }], deny: [] });
    expect(written.join("")).toContain("Decide");
  });

  it("s upgrades an approval to scripts", async () => {
    const { input, output } = mockTty();
    const promise = triage("Decide", items, undefined, { input, output });
    input.write("a");
    input.write("s");
    input.write("\r");
    await expect(promise).resolves.toEqual({ approve: [{ index: 0, scripts: true }], deny: [] });
  });

  it("d + enter records a denial", async () => {
    const { input, output } = mockTty();
    const promise = triage("Decide", items, undefined, { input, output });
    input.write("\x1b[B"); // down -> 1
    input.write("d");
    input.write("\r");
    await expect(promise).resolves.toEqual({ approve: [], deny: [1] });
  });

  it("navigates past disabled items", async () => {
    const { input, output } = mockTty();
    const promise = triage("Decide", items, undefined, { input, output });
    input.write("\x1b[B"); // 0 -> 1
    input.write("\x1b[B"); // 1 -> 3 (skips disabled 2)
    input.write("a");
    input.write("\r");
    await expect(promise).resolves.toEqual({ approve: [{ index: 3, scripts: false }], deny: [] });
  });

  it("q cancels with null", async () => {
    const { input, output } = mockTty();
    const promise = triage("Decide", items, undefined, { input, output });
    input.write("q");
    await expect(promise).resolves.toBeNull();
  });

  it("cancels instead of hanging when stdin ends", async () => {
    const { input, output } = mockTty();
    const promise = triage("Decide", items, undefined, { input, output });
    input.end();
    await expect(promise).resolves.toBeNull();
  });

  it("returns null without rendering on a non-TTY", async () => {
    const { input, output, written } = mockTty();
    (input as { isTTY: boolean }).isTTY = false;
    const result = await triage("Decide", items, undefined, { input, output });
    expect(result).toBeNull();
    expect(written).toHaveLength(0);
  });
});
