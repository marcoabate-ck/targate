import { isDockerAvailable, runSandbox } from "../sandbox.js";
import { bold, cyan, dim, green, red, yellow } from "../report.js";

export interface SandboxCommandOptions {
  spec: string;
  image?: string;
  timeoutMs?: number;
}

/** Phase 4 — `bye sandbox <pkg>`: trial install in a disposable container. */
export async function sandboxCommand(opts: SandboxCommandOptions): Promise<number> {
  if (!(await isDockerAvailable())) {
    console.error(
      red("Docker is required for sandboxed installs but was not found (or the daemon is not running)."),
    );
    console.error(dim("Install Docker Desktop / colima, or use `bye <pkg> --dry-run` for static analysis only."));
    return 1;
  }

  console.log(bold(`\nSandboxed trial install of ${opts.spec}`));
  console.log(
    dim(
      "Disposable container: no host env vars, no SSH agent, no npm/GitHub tokens,\n" +
        "no host filesystem, capabilities dropped, 1 CPU / 1 GB memory cap.\n",
    ),
  );

  const result = await runSandbox(opts.spec, {
    image: opts.image,
    timeoutMs: opts.timeoutMs,
  });

  console.log("");
  if (result.timedOut) {
    console.log(red(bold("Sandbox timed out — the install did not finish in time.")));
    console.log(yellow("A hanging install can itself be a signal (waiting on a network hole-punch, mining, …)."));
    return 2;
  }

  if (result.exitCode !== 0) {
    console.log(yellow(bold(`Sandbox install exited with code ${result.exitCode}.`)));
  } else {
    console.log(green(bold("Sandbox install completed.")));
  }

  if (result.suspiciousLines.length > 0) {
    console.log(red(bold("\nSuspicious lines in the script execution log:")));
    for (const line of result.suspiciousLines) console.log(red(`  ! ${line}`));
    console.log(
      yellow("\nReview the full log above before deciding to install this package on your machine."),
    );
    return 2;
  }

  console.log(cyan("\nNo suspicious activity spotted in the script log."));
  console.log(
    dim("Note: the sandbox observes install-time behavior only — runtime behavior still needs code review."),
  );
  return result.exitCode === 0 ? 0 : 1;
}
