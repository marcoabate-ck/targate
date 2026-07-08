import { describe, expect, it } from "vitest";
import { approveOutcome } from "../src/commands/approve.js";

describe("approveOutcome", () => {
  it("refuses a HARD block — never approvable", () => {
    expect(approveOutcome("block", true)).toBe("hard-blocked");
  });

  it("treats a SOFT block as approvable", () => {
    expect(approveOutcome("block", false)).toBe("approvable");
  });

  it("treats require_approval as approvable", () => {
    expect(approveOutcome("require_approval", false)).toBe("approvable");
  });

  it("needs no approval for allow / allow_with_warnings", () => {
    expect(approveOutcome("allow", false)).toBe("already-allowed");
    expect(approveOutcome("allow_with_warnings", false)).toBe("already-allowed");
  });
});
