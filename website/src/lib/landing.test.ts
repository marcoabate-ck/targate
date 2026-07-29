import { describe, expect, it } from "vitest";
import {
  COPY,
  LINKS,
  NPM_LINES,
  STAGE_MARKS,
  TARGATE_LINES,
  TOTAL_MS,
  stageStart,
  stateAt,
} from "./landing.js";

describe("landing timeline model", () => {
  it("stage marks are ordered by time", () => {
    for (let i = 1; i < STAGE_MARKS.length; i++) {
      expect(STAGE_MARKS[i].at).toBeGreaterThan(STAGE_MARKS[i - 1].at);
    }
  });

  it("reveals no lines at t=0 and every line by the end", () => {
    expect(stateAt(0).npmVisible).toBe(0);
    expect(stateAt(0).targateVisible).toBe(0);
    const end = stateAt(TOTAL_MS);
    expect(end.npmVisible).toBe(NPM_LINES.length);
    expect(end.targateVisible).toBe(TARGATE_LINES.length);
    expect(end.done).toBe(true);
  });

  it("reveals lines monotonically as time advances", () => {
    let prevNpm = 0;
    let prevTar = 0;
    for (let ms = 0; ms <= TOTAL_MS; ms += 200) {
      const s = stateAt(ms);
      expect(s.npmVisible).toBeGreaterThanOrEqual(prevNpm);
      expect(s.targateVisible).toBeGreaterThanOrEqual(prevTar);
      prevNpm = s.npmVisible;
      prevTar = s.targateVisible;
    }
  });

  it("npm breaches at the executing stage; targate blocks at the verdict stage", () => {
    expect(stateAt(stageStart("executing")).npmBreached).toBe(true);
    expect(stateAt(stageStart("executing") - 1).npmBreached).toBe(false);
    expect(stateAt(stageStart("verdict")).targateBlocked).toBe(true);
    expect(stateAt(stageStart("verdict") - 1).targateBlocked).toBe(false);
  });

  it("both transcripts carry the two commands and the final outcomes", () => {
    expect(NPM_LINES[0].text).toContain("npm install night-owl-kit");
    expect(TARGATE_LINES[0].text).toContain("targate add night-owl-kit");
    // npm executed untrusted code; targate reached a BLOCK verdict.
    expect(NPM_LINES.some((l) => /Untrusted code already executed/i.test(l.text))).toBe(true);
    expect(TARGATE_LINES.some((l) => /Decision: BLOCK/.test(l.text))).toBe(true);
  });

  it("stays faithful to the CLI vocabulary (no invented risk levels)", () => {
    const targate = TARGATE_LINES.map((l) => l.text).join("\n");
    expect(targate).toContain("risk: high"); // real RiskLevel, not "CRITICAL"
    expect(targate).not.toMatch(/CRITICAL/);
    expect(targate).not.toMatch(/\b\d{1,3}\/100\b/); // no fabricated score
  });

  it("does not ship a fake npm link while the package is unpublished", () => {
    expect(LINKS.npm).toBeNull();
    expect(LINKS.github).toMatch(/^https:\/\/github\.com\//);
    expect(COPY.payoff).toBe("Inspect first. Install second.");
  });
});
