import { describe, expect, it } from "vitest";
import { clean } from "../src/report/colors.js";
import { renderReport } from "../src/report/assessment.js";
import { makeMetadata, makeSignals } from "./helpers.js";
import type { RiskAssessment } from "../src/types.js";

const ESC = String.fromCharCode(27); // U+001B
const BEL = String.fromCharCode(7); // U+0007
const NEL = String.fromCharCode(0x85); // C1 newline
const DEL = String.fromCharCode(0x7f);

// Regression (v4 #1): attacker-controlled metadata is rendered to the terminal;
// raw ANSI escapes / CR / LF would let a package forge reassuring lines, scroll
// away the verdict, or hide findings. `clean` must neutralize them.
describe("clean (terminal sanitizer)", () => {
  it("strips ANSI CSI colour sequences", () => {
    expect(clean(`${ESC}[31mred${ESC}[0m`)).toBe("red");
  });

  it("strips ANSI OSC sequences", () => {
    expect(clean(`${ESC}]0;title${BEL}rest`)).toBe("rest");
  });

  it("flattens CR/LF and other controls to spaces", () => {
    expect(clean("a\r\nb\tc")).toBe("a  b c");
    expect(clean(`a${ESC}b`)).toBe("a b"); // lone ESC
  });

  it("neutralizes C1 (NEL) and DEL", () => {
    expect(clean(`a${NEL}b${DEL}c`)).toBe("a b c");
  });

  it("passes ordinary text through unchanged", () => {
    expect(clean("lodash 4.17.21 — utilities")).toBe(
      "lodash 4.17.21 — utilities",
    );
  });
});

describe("renderReport does not let hostile metadata forge output", () => {
  it("sanitizes a description carrying ANSI + a fake checklist line", () => {
    const metadata = makeMetadata({
      name: "evil",
      version: "1.0.0",
      description: `x\r\n  ${ESC}[32m✓ TOTALLY SAFE (forged)${ESC}[0m\r\nmore`,
    });
    const assessment: RiskAssessment = {
      risk: "high",
      decision: "block",
      summary: "blocked",
      reasons: ["remote code execution"],
      recommendedAction: "do not install",
      source: "rules",
    };
    const out = renderReport(
      metadata,
      makeSignals({ package: "evil" }),
      assessment,
    );
    // No raw ESC and no bare CR injected by the description survive.
    expect(out).not.toContain(ESC + "[32m");
    expect(out).not.toContain("\r");
    // The forged text never becomes its own standalone line.
    expect(
      out.split("\n").some((l) => l.trim() === "✓ TOTALLY SAFE (forged)"),
    ).toBe(false);
  });
});

// Regression (review): a shallow ALLOW must not read as "the whole install is
// safe" — surface that only the named package was analyzed. A --deep run vets
// the tree, so the note is suppressed; non-allow verdicts don't get it either.
describe("renderReport transitive-coverage caveat", () => {
  const NOTE =
    /only lodash was analyzed — its transitive dependencies were not/;
  const metadata = makeMetadata({ name: "lodash", version: "4.17.21" });
  const signals = makeSignals({ package: "lodash" });
  const assess = (decision: RiskAssessment["decision"]): RiskAssessment => ({
    risk: decision === "block" ? "high" : "low",
    decision,
    summary: "s",
    reasons: ["r"],
    recommendedAction: "a",
    source: "rules",
  });

  it("shows the note on a shallow ALLOW", () => {
    expect(renderReport(metadata, signals, assess("allow"), undefined)).toMatch(
      NOTE,
    );
  });

  it("shows the note on a shallow ALLOW WITH WARNINGS", () => {
    expect(
      renderReport(metadata, signals, assess("allow_with_warnings"), undefined),
    ).toMatch(NOTE);
  });

  it("suppresses the note under --deep", () => {
    expect(
      renderReport(metadata, signals, assess("allow"), undefined, {
        deep: true,
      }),
    ).not.toMatch(NOTE);
  });

  it("does not show it on non-allow verdicts", () => {
    expect(
      renderReport(metadata, signals, assess("require_approval"), undefined),
    ).not.toMatch(NOTE);
    expect(
      renderReport(metadata, signals, assess("block"), undefined),
    ).not.toMatch(NOTE);
  });
});

describe("renderReport last-updated line", () => {
  const assess: RiskAssessment = {
    risk: "low",
    decision: "allow",
    summary: "s",
    reasons: ["r"],
    recommendedAction: "a",
    source: "rules",
  };

  it("shows 'last updated' when the analyzed version is not the latest", () => {
    const metadata = makeMetadata({ name: "lodash", version: "4.17.10" });
    const signals = makeSignals({ package: "lodash" });
    signals.reputation.latestVersion = "4.17.21";
    signals.reputation.latestVersionAgeDays = 42;
    const out = renderReport(metadata, signals, assess);
    expect(out).toMatch(/last updated: 42 days ago \(latest 4\.17\.21\)/);
  });

  it("omits it when the analyzed version IS the latest (no redundant line)", () => {
    const metadata = makeMetadata({ name: "lodash", version: "4.17.21" });
    const signals = makeSignals({ package: "lodash" });
    signals.reputation.latestVersion = "4.17.21";
    signals.reputation.latestVersionAgeDays = 42;
    expect(renderReport(metadata, signals, assess)).not.toMatch(/last updated/);
  });

  it("omits it when no latest-release data is available", () => {
    const metadata = makeMetadata({ name: "lodash", version: "4.17.10" });
    const signals = makeSignals({ package: "lodash" }); // no latestVersion set
    expect(renderReport(metadata, signals, assess)).not.toMatch(/last updated/);
  });
});
