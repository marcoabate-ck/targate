import { describe, expect, it } from "vitest";
import { diffDependencies, rangeToVersion } from "../src/ci.js";

describe("diffDependencies", () => {
  it("detects added dependencies", () => {
    const changes = diffDependencies(
      { dependencies: { react: "^18.0.0" } },
      { dependencies: { react: "^18.0.0", "left-pad": "^1.3.0" } },
    );
    expect(changes).toEqual([
      { name: "left-pad", range: "^1.3.0", kind: "added", section: "dependencies" },
    ]);
  });

  it("detects updated ranges", () => {
    const changes = diffDependencies(
      { dependencies: { axios: "^1.0.0" } },
      { dependencies: { axios: "^1.7.0" } },
    );
    expect(changes[0]).toMatchObject({
      name: "axios",
      kind: "updated",
      previousRange: "^1.0.0",
      range: "^1.7.0",
    });
  });

  it("covers devDependencies too", () => {
    const changes = diffDependencies(
      {},
      { devDependencies: { vitest: "^4.0.0" } },
    );
    expect(changes[0]).toMatchObject({ name: "vitest", section: "devDependencies" });
  });

  it("ignores removals and unchanged deps", () => {
    const changes = diffDependencies(
      { dependencies: { a: "1.0.0", b: "2.0.0" } },
      { dependencies: { a: "1.0.0" } },
    );
    expect(changes).toEqual([]);
  });

  it("treats an empty base as all-added", () => {
    const changes = diffDependencies({}, { dependencies: { a: "1.0.0" } });
    expect(changes).toHaveLength(1);
    expect(changes[0].kind).toBe("added");
  });
});

describe("rangeToVersion", () => {
  it("strips caret and tilde", () => {
    expect(rangeToVersion("^1.2.3")).toBe("1.2.3");
    expect(rangeToVersion("~1.2.3")).toBe("1.2.3");
    expect(rangeToVersion("1.2.3")).toBe("1.2.3");
    expect(rangeToVersion("^1.2.3-beta.1")).toBe("1.2.3-beta.1");
  });

  it("returns undefined for non-pinnable ranges", () => {
    expect(rangeToVersion("*")).toBeUndefined();
    expect(rangeToVersion(">=1.0.0 <2.0.0")).toBeUndefined();
    expect(rangeToVersion("latest")).toBeUndefined();
    expect(rangeToVersion("workspace:*")).toBeUndefined();
  });
});
