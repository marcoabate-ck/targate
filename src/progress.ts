/**
 * Live progress feedback for the tree walk (`--deep`, `targate install`).
 * Three modes, picked automatically:
 *  - json:    completely silent (stdout must stay a single JSON document);
 *  - TTY:     one continuously re-drawn line on stderr with a spinner,
 *             done/total counters, elapsed time and an ETA;
 *  - non-TTY: plain milestone lines (25% steps) so CI logs still show life.
 */

export type ProgressPhase = "scan" | "assess" | "analyze";

const PHASE_LABEL: Record<ProgressPhase, string> = {
  scan: "downloading & scanning",
  assess: "AI risk assessment",
  analyze: "analyzing packages",
};

const FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const REDRAW_MS = 120;

function formatSeconds(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 100) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

/** Pure line formatter — exported for tests. */
export function formatProgressLine(
  phase: ProgressPhase,
  done: number,
  total: number,
  elapsedMs: number,
  frame = FRAMES[0],
): string {
  const parts = [`${frame} ${PHASE_LABEL[phase]}  ${done}/${total}`, formatSeconds(elapsedMs)];
  // An ETA from fewer than 2 completions or <2s of data is noise, not signal.
  if (done >= 2 && elapsedMs >= 2000 && done < total) {
    const eta = (elapsedMs / done) * (total - done);
    parts.push(`~${formatSeconds(eta)} left`);
  }
  return parts.join(" · ");
}

export interface TreeProgress {
  /** Report progress within a phase; switching phase resets the ETA clock. */
  update(phase: ProgressPhase, done: number, total: number): void;
  /** Print a normal output line without corrupting the live progress line. */
  log(line: string): void;
  /** Clear the live line, stop the timer, optionally print a summary line. */
  done(summary?: string): void;
}

const NOOP: TreeProgress = { update() {}, log() {}, done() {} };

export function createTreeProgress(opts: {
  json: boolean;
  stream?: NodeJS.WriteStream;
}): TreeProgress {
  if (opts.json) return NOOP;
  const stream = opts.stream ?? process.stderr;

  if (!stream.isTTY) {
    // Milestone mode: one plain line per quartile, so non-interactive logs
    // (CI, piped output) still show that work is progressing.
    let lastMilestone = 0;
    return {
      update(phase, done, total) {
        const milestone = total > 0 ? Math.floor((done / total) * 4) : 0;
        if (milestone > lastMilestone || done === total) {
          lastMilestone = milestone;
          console.log(`  … ${PHASE_LABEL[phase]}: ${done}/${total}`);
        }
      },
      log(line) {
        console.log(line);
      },
      done(summary) {
        if (summary) console.log(summary);
      },
    };
  }

  let phase: ProgressPhase = "scan";
  let done = 0;
  let total = 0;
  let phaseStart = Date.now();
  let frameIdx = 0;
  let active = false;

  const draw = (): void => {
    frameIdx = (frameIdx + 1) % FRAMES.length;
    const line = formatProgressLine(phase, done, total, Date.now() - phaseStart, FRAMES[frameIdx]);
    stream.write(`\r\x1b[2K${line}`);
    active = true;
  };
  const clear = (): void => {
    if (active) stream.write("\r\x1b[2K");
    active = false;
  };

  // The timer keeps the spinner/clock alive between events (a long AI batch
  // can take tens of seconds without a single progress event).
  const timer = setInterval(draw, REDRAW_MS);
  timer.unref();

  return {
    update(nextPhase, nextDone, nextTotal) {
      if (nextPhase !== phase) {
        phase = nextPhase;
        phaseStart = Date.now();
      }
      done = nextDone;
      total = nextTotal;
      draw();
    },
    log(line) {
      clear();
      console.log(line);
      draw();
    },
    done(summary) {
      clearInterval(timer);
      clear();
      if (summary) console.log(summary);
    },
  };
}
