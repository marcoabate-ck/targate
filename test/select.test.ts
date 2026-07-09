import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  initialSelectState,
  multiSelect,
  reduceSelectKey,
  type SelectItem,
  type SelectState,
} from "../src/select.js";

const items: SelectItem[] = [
  { label: "a@1.0.0" },
  { label: "b@2.0.0" },
  { label: "evil@9.9.9", disabled: true }, // hard block — never selectable
  { label: "c@3.0.0" },
];

function state(cursor: number, selected: number[] = []): SelectState {
  return { cursor, selected: new Set(selected) };
}

describe("initialSelectState", () => {
  it("starts on the first selectable item", () => {
    expect(initialSelectState(items).cursor).toBe(0);
    expect(initialSelectState([{ label: "x", disabled: true }, { label: "y" }]).cursor).toBe(1);
  });
});

describe("reduceSelectKey", () => {
  it("moves down and skips disabled items", () => {
    const s = reduceSelectKey(state(1), "down", items);
    expect(s.cursor).toBe(3); // skipped index 2 (disabled)
  });

  it("moves up and skips disabled items", () => {
    const s = reduceSelectKey(state(3), "up", items);
    expect(s.cursor).toBe(1);
  });

  it("wraps around at the edges", () => {
    expect(reduceSelectKey(state(3), "down", items).cursor).toBe(0);
    expect(reduceSelectKey(state(0), "up", items).cursor).toBe(3);
  });

  it("space toggles the item under the cursor", () => {
    const on = reduceSelectKey(state(1), "space", items);
    expect([...on.selected]).toEqual([1]);
    const off = reduceSelectKey(on, "space", items);
    expect(off.selected.size).toBe(0);
  });

  it("space never selects a disabled item", () => {
    const s = reduceSelectKey(state(2), "space", items);
    expect(s.selected.size).toBe(0);
  });

  it("'a' selects all enabled items, then deselects all", () => {
    const all = reduceSelectKey(state(0), "all", items);
    expect([...all.selected].sort()).toEqual([0, 1, 3]); // disabled 2 excluded
    const none = reduceSelectKey(all, "all", items);
    expect(none.selected.size).toBe(0);
  });

  it("keeps the cursor in place when every item is disabled", () => {
    const allDisabled: SelectItem[] = [
      { label: "x", disabled: true },
      { label: "y", disabled: true },
    ];
    expect(reduceSelectKey(state(0), "down", allDisabled).cursor).toBe(0);
  });
});

/** A PassThrough dressed up as an interactive TTY for the keypress shell. */
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

describe("multiSelect (keypress shell with mock TTY)", () => {
  it("space + enter selects the item under the cursor", async () => {
    const { input, output, written } = mockTty();
    const promise = multiSelect("Pick", items, undefined, { input, output });
    input.write(" "); // toggle first item
    input.write("\r"); // confirm
    await expect(promise).resolves.toEqual([0]);
    expect(written.join("")).toContain("Pick");
  });

  it("navigates past disabled items before selecting", async () => {
    const { input, output } = mockTty();
    const promise = multiSelect("Pick", items, undefined, { input, output });
    input.write("\x1b[B"); // down -> 1
    input.write("\x1b[B"); // down -> 3 (skips disabled 2)
    input.write(" ");
    input.write("\r");
    await expect(promise).resolves.toEqual([3]);
  });

  it("'a' selects everything selectable", async () => {
    const { input, output } = mockTty();
    const promise = multiSelect("Pick", items, undefined, { input, output });
    input.write("a");
    input.write("\r");
    await expect(promise).resolves.toEqual([0, 1, 3]);
  });

  it("q cancels with null", async () => {
    const { input, output } = mockTty();
    const promise = multiSelect("Pick", items, undefined, { input, output });
    input.write("q");
    await expect(promise).resolves.toBeNull();
  });

  it("cancels instead of hanging when stdin ends (exhausted pipe)", async () => {
    const { input, output } = mockTty();
    const promise = multiSelect("Pick", items, undefined, { input, output });
    input.end();
    await expect(promise).resolves.toBeNull();
  });

  it("returns null without rendering on a non-TTY", async () => {
    const { input, output, written } = mockTty();
    (input as { isTTY: boolean }).isTTY = false;
    const result = await multiSelect("Pick", items, undefined, { input, output });
    expect(result).toBeNull();
    expect(written).toHaveLength(0);
  });
});
