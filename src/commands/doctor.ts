import type { AssessOptions } from "../ai.js";
import { runDoctor, type DoctorStatus } from "../doctor.js";
import { printJson } from "../json-output.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";

export interface DoctorCommandOptions {
  json: boolean;
  /** Send one real (paid) test completion to the resolved AI provider. */
  ping: boolean;
  assess: AssessOptions;
}

const ICON: Record<DoctorStatus, string> = {
  pass: "✓",
  warn: "⚠",
  fail: "✖",
  info: "ℹ",
};

const PAINT: Record<DoctorStatus, (t: string) => string> = {
  pass: green,
  warn: yellow,
  fail: red,
  info: cyan,
};

/** `targate doctor` — check that the environment is ready for targate. */
export async function doctorCommand(opts: DoctorCommandOptions): Promise<number> {
  const report = await runDoctor({
    cwd: process.cwd(),
    env: process.env,
    networkTimeoutMs: 5_000,
    ping: opts.ping,
    provider: opts.assess,
  });

  if (opts.json) {
    printJson("doctor", report);
    return report.exitCode;
  }

  console.log(bold("\ntargate doctor\n"));
  const width = Math.max(...report.checks.map((c) => c.label.length));
  for (const c of report.checks) {
    const paint = PAINT[c.status];
    console.log(`  ${paint(ICON[c.status])} ${c.label.padEnd(width + 2)}${paint(c.message)}`);
  }

  const { fail, warn } = report.summary;
  console.log("");
  if (fail > 0) {
    console.log(red(bold(`${fail} failure(s), ${warn} warning(s) — fix the ✖ items above.`)));
  } else if (warn > 0) {
    console.log(yellow(`targate is usable — ${warn} warning(s) above.`));
  } else {
    console.log(green(bold("targate is ready.")));
  }
  console.log(dim("Run with --ping to also test a live AI completion (costs one request)."));
  return report.exitCode;
}
