import { afterEach, describe, expect, it, vi } from "vitest";
import { createTreeProgress, formatProgressLine } from "../src/progress.js";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("formatProgressLine", () => {
  it("shows phase label, counters and elapsed time", () => {
    const line = formatProgressLine("scan", 10, 67, 12_000);
    expect(line).toContain("downloading & scanning");
    expect(line).toContain("10/67");
    expect(line).toContain("12s");
  });

  it("adds an ETA once there is enough signal", () => {
    // 10 done in 10s -> 1s each -> ~57s left for the remaining 57.
    const line = formatProgressLine("assess", 10, 67, 10_000);
    expect(line).toMatch(/~57s left/);
  });

  it("withholds the ETA when data is too thin or the work is done", () => {
    expect(formatProgressLine("scan", 1, 67, 500)).not.toContain("left");
    expect(formatProgressLine("scan", 67, 67, 30_000)).not.toContain("left");
  });

  it("formats long durations as minutes", () => {
    const line = formatProgressLine("assess", 10, 100, 120_000);
    expect(line).toContain("2m 0s");
  });
});

describe("createTreeProgress", () => {
  it("is fully silent in --json mode", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const p = createTreeProgress({ json: true });
    p.update("scan", 1, 4);
    p.log("something");
    p.done("summary");
    expect(log).not.toHaveBeenCalled();
  });

  it("prints milestone lines on a non-TTY stream", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const p = createTreeProgress({ json: false, stream: { isTTY: false } as NodeJS.WriteStream });
    for (let done = 1; done <= 8; done++) p.update("scan", done, 8);
    p.done("done!");
    const lines = log.mock.calls.map((c) => String(c[0]));
    // Quartile milestones, not one line per package.
    expect(lines.filter((l) => l.includes("downloading & scanning")).length).toBeLessThan(8);
    expect(lines.some((l) => l.includes("8/8"))).toBe(true);
    expect(lines.at(-1)).toBe("done!");
  });

  it("renders a live line on a TTY and clears it on done()", () => {
    const writes: string[] = [];
    const stream = {
      isTTY: true,
      write: (s: string) => {
        writes.push(s);
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    const p = createTreeProgress({ json: false, stream });
    p.update("assess", 3, 8);
    p.done();
    expect(writes.some((w) => w.includes("AI risk assessment") && w.includes("3/8"))).toBe(true);
    expect(writes.at(-1)).toContain("\x1b[2K"); // final clear
  });
});
