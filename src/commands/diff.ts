import type { AssessOptions } from "../ai.js";
import { diffPackageVersions } from "../diff.js";
import { detectPackageManager } from "../installer.js";
import { printJson } from "../json-output.js";
import { extractLockfileEntries, snapshotLockfile } from "../lockfile.js";
import { buildPackageSignals } from "../pipeline.js";
import { loadPolicy } from "../policy.js";
import { PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, dim, red, renderVersionDiff } from "../report.js";
import { highestSemver } from "../semver.js";
import type { PackageManager, RiskLevel } from "../types.js";

export interface DiffOptions {
  /** First spec, "pkg@version" (version required in two-spec form). */
  specA: string;
  /** Second spec; omit → latest of the same package. */
  specB?: string;
  packageManager?: string;
  json: boolean;
  failOnOsvError?: boolean;
  noReputation?: boolean;
  /** Diff-risk level at or above which the command exits 2. */
  failOn: RiskLevel;
  assess: AssessOptions;
}

const RISK_RANK: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

/**
 * `targate diff` — deterministic comparison of two versions of a package.
 * Forms: `diff pkg@v1 pkg[@v2]` (v2 omitted → latest) or bare `diff pkg`
 * (lockfile-installed version → latest). No install, no AI.
 */
export async function diffCommand(opts: DiffOptions): Promise<number> {
  const a = parsePackageSpec(opts.specA);
  let fromVersion = a.version;
  let toVersion: string | undefined;

  if (opts.specB) {
    const b = parsePackageSpec(opts.specB);
    if (b.name !== a.name) {
      console.error(red(`targate diff compares two versions of ONE package — got "${a.name}" and "${b.name}".`));
      return 1;
    }
    if (!fromVersion) {
      console.error(red(`In the two-spec form the first spec needs a version: targate diff ${a.name}@<v1> ${a.name}[@<v2>]`));
      return 1;
    }
    toVersion = b.version; // may be undefined → latest
  } else {
    // Bare form: installed (from the lockfile) → latest.
    if (fromVersion) {
      // `diff pkg@v1` with no second spec → v1 vs latest.
      toVersion = undefined;
    } else {
      const pm = (opts.packageManager as PackageManager) ?? detectPackageManager();
      const content = await snapshotLockfile(pm);
      const installed = content
        ? [...extractLockfileEntries(pm, content)]
            .filter((e) => e.startsWith(`${a.name}@`))
            .map((e) => e.slice(a.name.length + 1))
        : [];
      if (installed.length === 0) {
        console.error(
          red(
            `${a.name} is not in the ${pm} lockfile. Pass two explicit versions: targate diff ${a.name}@<v1> ${a.name}@<v2>`,
          ),
        );
        return 1;
      }
      fromVersion = highestSemver(installed);
      if (installed.length > 1 && !opts.json) {
        console.log(dim(`  (${a.name} appears at ${installed.length} versions in the lockfile — using ${fromVersion})`));
      }
    }
  }

  const note = (line: string): void => {
    if (!opts.json) console.log(line);
  };
  note(dim(`\nDiffing ${bold(a.name)} ${fromVersion ?? "?"} → ${toVersion ?? "latest"} ...`));

  // Policy is loaded for its internalScopes (so a private name is not sent to
  // OSV even by a diff); diff applies no policy escalation — it reports facts.
  const policy = await loadPolicy();
  const lookupOpts = {
    failOnOsvError: opts.failOnOsvError,
    noReputation: opts.noReputation,
    policy,
  };
  let from, to;
  try {
    [from, to] = await Promise.all([
      buildPackageSignals(a.name, fromVersion, { ...lookupOpts, maintainerIntel: true }),
      buildPackageSignals(a.name, toVersion, { ...lookupOpts, maintainerIntel: true }),
    ]);
  } catch (err) {
    if (err instanceof PackageNotFoundError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }

  if (from.metadata.version === to.metadata.version) {
    note(dim(`\n${a.name}@${from.metadata.version}: identical versions — nothing to diff.`));
    if (opts.json) {
      printJson("diff", { diff: diffPackageVersions(from, to), failOn: opts.failOn, exitCode: 0 });
    }
    return 0;
  }

  const diff = diffPackageVersions(from, to);
  const exitCode = RISK_RANK[diff.diffRisk] >= RISK_RANK[opts.failOn] ? 2 : 0;

  if (opts.json) {
    printJson("diff", { diff, failOn: opts.failOn, exitCode });
  } else {
    console.log(renderVersionDiff(diff));
    if (exitCode === 2) {
      console.log(red(bold(`Diff risk ${diff.diffRisk.toUpperCase()} is at or above --fail-on ${opts.failOn}.`)));
    }
  }
  return exitCode;
}
