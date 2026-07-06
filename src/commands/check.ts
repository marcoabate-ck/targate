import path from "node:path";
import { buildSignals } from "../analyze/index.js";
import { getApproval, loadApprovals, recordApproval } from "../approvals.js";
import { assessRisk, type AssessOptions } from "../ai.js";
import { detectPackageManager, gateInstall } from "../installer.js";
import { diffLockfiles, snapshotLockfile } from "../lockfile.js";
import { queryOsv, type OsvResult } from "../osv.js";
import { applyPolicy, loadPolicy } from "../policy.js";
import { recordBuildApproval } from "../pnpm-builds.js";
import { quarantineTarball } from "../quarantine.js";
import { fetchPackageMetadata, PackageNotFoundError, parsePackageSpec } from "../registry.js";
import { bold, cyan, dim, green, red, renderReport, yellow } from "../report.js";
import type { PackageManager } from "../types.js";

export interface CheckOptions {
  spec: string;
  packageManager?: string;
  json: boolean;
  dryRun: boolean;
  assumeYes: boolean;
  assess: AssessOptions;
}

/** The original `bye <package>` flow: analyze, decide, gate the install. */
export async function checkCommand(opts: CheckOptions): Promise<number> {
  const { name, version } = parsePackageSpec(opts.spec);

  const pm = (opts.packageManager as PackageManager) ?? detectPackageManager();
  if (!["pnpm", "npm", "yarn"].includes(pm)) {
    console.error(red(`Unknown package manager: ${pm}`));
    return 1;
  }

  console.log(dim(`\nPre-install review started for ${bold(name)}${version ? `@${version}` : ""} ...`));

  let metadata;
  try {
    metadata = await fetchPackageMetadata(name, version);
  } catch (err) {
    if (err instanceof PackageNotFoundError) {
      console.error(red(`\n${err.message}`));
      return 1;
    }
    throw err;
  }
  console.log(dim(`  ✓ npm metadata resolved (${metadata.name}@${metadata.version})`));

  const quarantine = await quarantineTarball(metadata.tarballUrl);
  console.log(dim(`  ✓ tarball downloaded to quarantine`));

  try {
    let osv: OsvResult;
    try {
      osv = await queryOsv(metadata.name, metadata.version);
      console.log(dim(`  ✓ OSV/OpenSSF malicious-package lookup done`));
    } catch {
      osv = { knownMalicious: false, maliciousRecords: [], advisories: [] };
      console.log(yellow(`  ⚠ OSV lookup failed — continuing without it`));
    }

    const signals = await buildSignals(metadata, quarantine.packageDir, osv);
    console.log(dim(`  ✓ package contents inspected (scripts, native surface, RN hardening)`));

    let assessment = await assessRisk(signals, opts.assess);
    console.log(dim(`  ✓ risk assessment complete (${assessment.source})`));

    // Phase 6 — team policy on top of the AI/rules assessment
    const loaded = await loadPolicy();
    if (loaded) {
      assessment = applyPolicy(assessment, signals, loaded.policy);
      console.log(dim(`  ✓ team policy applied (${path.basename(loaded.file)})`));
    }

    // Phase 2 — committed approval cache: a version already reviewed by the
    // team doesn't need a second human approval.
    const approvals = await loadApprovals();
    const priorApproval = getApproval(approvals, metadata.name, metadata.version);
    if (priorApproval && assessment.decision === "require_approval") {
      assessment = {
        ...assessment,
        decision: "allow_with_warnings",
        reasons: [
          ...assessment.reasons,
          `[team] ${metadata.name}@${metadata.version} already approved${priorApproval.approvedBy ? ` by ${priorApproval.approvedBy}` : ""} on ${priorApproval.approvedAt.slice(0, 10)} (${priorApproval.mode}).`,
        ],
      };
    }

    if (opts.json) {
      console.log(JSON.stringify({ metadata, signals, assessment }, null, 2));
    } else {
      console.log(renderReport(metadata, signals, assessment));
    }

    const lockBefore = await snapshotLockfile(pm);

    const result = await gateInstall(assessment.decision, pm, `${metadata.name}@${metadata.version}`, {
      assumeYes: opts.assumeYes,
      dryRun: opts.dryRun,
    });

    switch (result.mode) {
      case "blocked":
        console.log(red(bold("\nInstallation blocked. This package was not installed.")));
        return 2;
      case "skipped":
        if (opts.dryRun && result.command) {
          console.log(dim(`\nDry run — recommended command: ${result.command.join(" ")}`));
        } else {
          console.log(dim("\nNothing installed."));
        }
        return 0;
      case "no-scripts":
      case "normal": {
        console.log(
          green(result.mode === "no-scripts" ? "\nInstalled with lifecycle scripts disabled." : "\nInstalled."),
        );

        // Phase 2 — record the human approval so the team doesn't re-review
        if (assessment.decision === "require_approval") {
          await recordApproval(metadata.name, metadata.version, result.mode);
          console.log(dim(`  ✓ approval recorded in .bye/approvals.json (commit it to share)`));
          if (pm === "pnpm" && signals.hasLifecycleScripts) {
            const written = await recordBuildApproval(
              metadata.name,
              result.mode === "normal" ? "approved" : "ignored",
            );
            if (written) {
              console.log(
                dim(`  ✓ pnpm approve-builds updated (${written}): scripts ${result.mode === "normal" ? "allowed" : "ignored"}`),
              );
            }
          }
        }

        // Phase 2 — lockfile diff preview: what did this install actually add?
        const lockAfter = await snapshotLockfile(pm);
        const diff = diffLockfiles(pm, lockBefore, lockAfter);
        if (diff.added.length > 0) {
          console.log(cyan(`\nLockfile diff — ${diff.added.length} package(s) added:`));
          for (const entry of diff.added.slice(0, 25)) console.log(dim(`  + ${entry}`));
          if (diff.added.length > 25) console.log(dim(`  … and ${diff.added.length - 25} more`));
        }
        return 0;
      }
    }
  } finally {
    await quarantine.cleanup();
  }
}
