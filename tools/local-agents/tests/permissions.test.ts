import { describe, expect, it } from "vitest";
import { resolvePermissions } from "../src/permissions.js";

describe("resolvePermissions", () => {
  it("denies write tools to read-only roles", () => {
    const p = resolvePermissions({ readOnly: true });
    expect(p.disallowedTools).toEqual(expect.arrayContaining(["Edit", "Write", "NotebookEdit"]));
    expect(p.allowedTools).toContain("Read");
    expect(p.allowedTools).toContain("Bash");
    expect(p.allowedTools).not.toContain("Edit");
  });

  it("grants write tools to writer roles", () => {
    const p = resolvePermissions({ readOnly: false });
    expect(p.allowedTools).toEqual(expect.arrayContaining(["Edit", "Write"]));
    expect(p.disallowedTools).not.toContain("Edit");
  });

  it("always denies Task and network tools", () => {
    const p = resolvePermissions({ readOnly: false });
    expect(p.disallowedTools).toEqual(expect.arrayContaining(["Task", "WebFetch", "WebSearch"]));
  });

  it("denial wins over an allow of the same tool", () => {
    const p = resolvePermissions({ readOnly: false, allowTools: ["WebFetch"], denyTools: ["WebFetch"] });
    expect(p.allowedTools).not.toContain("WebFetch");
    expect(p.disallowedTools).toContain("WebFetch");
  });
});
