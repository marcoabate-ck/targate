/**
 * Single source of truth for the landing page: external links, the headline
 * claims, and the two terminal transcripts + the animation timeline. Keeping it
 * here (framework-free, no DOM) lets the hero animation, the reduced-motion
 * static fallback, and the unit tests all read the exact same data.
 *
 * Terminal output mirrors the real CLI: `targate add`, a `Decision: BLOCK`
 * verdict at `risk: high`, the real hard-block reason, and ✓/✗/⚠/✋ glyphs.
 * `night-owl-kit` is a fictional package (never a real npm name); example
 * endpoints use the reserved `.invalid` TLD.
 */

export const LINKS = {
  docs: "/docs/",
  gettingStarted: "/docs/getting-started/",
  howItWorks: "/docs/how-it-works/",
  useCases: "#use-cases",
  github: "https://github.com/marcoabate-ck/targate",
  /** npm package is not published yet — keep null so no fake install/badge is shown. */
  npm: null as string | null,
} as const;

export const COPY = {
  eyebrow: "Install-time supply-chain security",
  headline: "Stop untrusted code before it runs.",
  subhead:
    "targate inspects npm packages in quarantine and runs the real installation only when they pass.",
  supporting: "Open source · Deterministic by default · AI optional",
  comparisonKicker: "Same package. Different outcome.",
  payoff: "Inspect first. Install second.",
  closing: {
    npm: "npm installed it.",
    targate: "targate interrogated it.",
  },
} as const;

/** Animation stages, in order. A single clock maps elapsed time to a stage. */
export type Stage =
  | "idle"
  | "typing"
  | "fetching"
  | "diverging"
  | "executing"
  | "analyzing"
  | "evaluating"
  | "verdict";

export type Tone = "cmd" | "neutral" | "info" | "warn" | "danger" | "success";

export interface Line {
  /** Milliseconds from timeline start at which this line appears. */
  at: number;
  tone: Tone;
  text: string;
}

export const PACKAGE = {
  name: "night-owl-kit",
  version: "2.4.1",
  tarball: "night-owl-kit-2.4.1.tgz",
  size: "38.4 kB",
} as const;

/** Left terminal: a plain `npm install` that runs a malicious postinstall. */
export const NPM_LINES: Line[] = [
  { at: 600, tone: "cmd", text: "$ npm install night-owl-kit" },
  { at: 2000, tone: "neutral", text: "npm http fetch GET 200 registry.npmjs.org/night-owl-kit" },
  { at: 2400, tone: "neutral", text: "npm http fetch GET 200 night-owl-kit-2.4.1.tgz" },
  { at: 3600, tone: "info", text: "npm info run night-owl-kit@2.4.1 postinstall" },
  { at: 3900, tone: "neutral", text: "> node scripts/setup.js" },
  { at: 4800, tone: "danger", text: "postinstall › reading process.env" },
  { at: 5200, tone: "danger", text: "postinstall › accessing ~/.ssh" },
  { at: 5600, tone: "danger", text: "postinstall › spawning child process" },
  { at: 6000, tone: "danger", text: "postinstall › fetching remote payload" },
  { at: 6600, tone: "danger", text: "POST https://collect.invalid/telemetry  200 OK" },
  { at: 8200, tone: "neutral", text: "added 28 packages in 2s" },
  { at: 9000, tone: "danger", text: "⚠ Untrusted code already executed" },
];

/** Right terminal: `targate add` quarantines, inspects, and blocks. */
export const TARGATE_LINES: Line[] = [
  { at: 600, tone: "cmd", text: "$ targate add night-owl-kit" },
  { at: 2000, tone: "info", text: "◆ Resolving night-owl-kit@2.4.1" },
  { at: 2400, tone: "info", text: "◆ Downloading tarball to quarantine" },
  { at: 3600, tone: "info", text: "◆ Verifying tarball integrity" },
  { at: 3900, tone: "info", text: "◆ Extracting package safely" },
  { at: 4300, tone: "info", text: "◆ Scanning lifecycle scripts" },
  { at: 5200, tone: "warn", text: "! postinstall script detected" },
  { at: 5600, tone: "warn", text: "! child_process usage detected" },
  { at: 6000, tone: "warn", text: "! sensitive environment access detected" },
  { at: 6400, tone: "warn", text: "! remote payload retrieval detected" },
  { at: 7800, tone: "info", text: "◆ Evaluating deterministic policy" },
  { at: 9000, tone: "danger", text: "✗ Decision: BLOCK   (risk: high, source: rules)" },
  { at: 9400, tone: "neutral", text: "  Lifecycle command downloads and executes remote code." },
  { at: 9700, tone: "success", text: "  The package was not installed. No package code was executed." },
];

/** Ordered stage marks (ms from start). `stateAt` resolves the active stage. */
export const STAGE_MARKS: { stage: Stage; at: number }[] = [
  { stage: "idle", at: 0 },
  { stage: "typing", at: 400 },
  { stage: "fetching", at: 1900 },
  { stage: "diverging", at: 3500 },
  { stage: "executing", at: 4700 },
  { stage: "analyzing", at: 5100 },
  { stage: "evaluating", at: 7700 },
  { stage: "verdict", at: 8900 },
];

/** Total run length; the animation holds on the verdict after this. */
export const TOTAL_MS = 10500;

export interface FrameState {
  stage: Stage;
  /** How many lines of each transcript are revealed at `ms`. */
  npmVisible: number;
  targateVisible: number;
  /** npm has crossed the system boundary (code executing). */
  npmBreached: boolean;
  /** targate reached its terminal BLOCK verdict. */
  targateBlocked: boolean;
  /** whole run finished (used to stop the loop / show closing copy). */
  done: boolean;
}

/** Pure mapping from elapsed milliseconds to the frame state. Deterministic. */
export function stateAt(ms: number): FrameState {
  const clamped = Math.max(0, ms);
  let stage: Stage = "idle";
  for (const mark of STAGE_MARKS) if (clamped >= mark.at) stage = mark.stage;
  return {
    stage,
    npmVisible: NPM_LINES.filter((l) => clamped >= l.at).length,
    targateVisible: TARGATE_LINES.filter((l) => clamped >= l.at).length,
    npmBreached: stage === "executing" || clamped >= stageStart("executing"),
    targateBlocked: clamped >= stageStart("verdict"),
    done: clamped >= TOTAL_MS,
  };
}

/** Start time (ms) of a stage, or Infinity if unknown. */
export function stageStart(stage: Stage): number {
  const mark = STAGE_MARKS.find((m) => m.stage === stage);
  return mark ? mark.at : Infinity;
}

/** Diagnostic finding badges shown on the targate side. */
export const FINDING_BADGES = [
  "POSTINSTALL",
  "CHILD_PROCESS",
  "ENV_ACCESS",
  "REMOTE_FETCH",
  "SENSITIVE_PATH",
] as const;
