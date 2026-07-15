import type { VersionDiff } from "../diff.js";
import type { RiskLevel } from "../types.js";
import { bold, dim, green, red, yellow } from "./colors.js";

const RISK_COLOR: Record<RiskLevel, (text: string) => string> = { low: green, medium: yellow, high: red };

export function renderVersionDiff(diff: VersionDiff): string {
  const lines: string[] = [];
  const push = (line = "") => lines.push(line);
  push("");
  push(bold(`Version diff — ${diff.package} ${diff.from.version} → ${diff.to.version}`) + dim(` (${diff.direction})`));
  const dates = [
    diff.from.publishDate ? `from: ${diff.from.publishDate.slice(0, 10)}` : null,
    diff.to.publishDate ? `to: ${diff.to.publishDate.slice(0, 10)}` : null,
  ].filter(Boolean);
  if (dates.length) push(dim(dates.join("  ·  ")));
  push(dim("─".repeat(60)));
  const lifecycle = diff.lifecycleScripts;
  if (lifecycle.added.length || lifecycle.removed.length || lifecycle.changed.length) {
    push(bold("Lifecycle scripts"));
    for (const script of lifecycle.added) push(red(`  + ${script.hook}: ${script.after}`));
    for (const script of lifecycle.changed) push(yellow(`  ~ ${script.hook}: ${script.before}  →  ${script.after}`));
    for (const script of lifecycle.removed) push(dim(`  - ${script.hook}: ${script.before}`));
    push();
  }
  if (diff.newScriptFindings.length) {
    push(bold("New suspicious script commands"));
    for (const finding of diff.newScriptFindings) push(red(`  ! ${finding}`));
    push();
  }
  const dependencies = diff.dependencies;
  if (dependencies.added.length || dependencies.removed.length || dependencies.changed.length) {
    push(bold("Dependencies"));
    for (const dependency of dependencies.added) push((dependency.nonRegistrySpec ? red : green)(`  + ${dependency.name}${dependency.afterRange ? `@${dependency.afterRange}` : ""}`));
    for (const dependency of dependencies.changed) push((dependency.nonRegistrySpec ? red : yellow)(`  ~ ${dependency.name}: ${dependency.beforeRange}  →  ${dependency.afterRange}`));
    for (const dependency of dependencies.removed) push(dim(`  - ${dependency.name}${dependency.beforeRange ? `@${dependency.beforeRange}` : ""}`));
    push();
  }
  if (diff.maintainers.added.length || diff.maintainers.removed.length) {
    push(bold("Maintainers"));
    for (const maintainer of diff.maintainers.added) push(yellow(`  + ${maintainer}`));
    for (const maintainer of diff.maintainers.removed) push(dim(`  - ${maintainer}`));
    push();
  }
  if (diff.repositoryChanged) {
    push(bold("Repository"));
    push(yellow(`  ${diff.repositoryChanged.before ?? "(none)"}  →  ${diff.repositoryChanged.after ?? "(none)"}`));
    push();
  }
  const native = diff.nativeSurface;
  if (native.added.length || native.newBinaries.length || native.newAndroidPermissions.length) {
    push(bold("Native surface"));
    for (const label of native.added) push(yellow(`  + ${label}`));
    for (const binary of native.newBinaries) push(red(`  + binary: ${binary}`));
    for (const permission of native.newAndroidPermissions) push(red(`  + permission: ${permission}`));
    push();
  }
  if (diff.advisories.added.length || diff.advisories.resolved.length) {
    push(bold("Advisories"));
    for (const advisory of diff.advisories.added) push(yellow(`  + ${advisory.id}${advisory.summary ? ` — ${advisory.summary}` : ""}`));
    for (const advisory of diff.advisories.resolved) push(green(`  - resolved: ${advisory.id}`));
    push();
  }
  if (diff.provenanceLost || diff.deprecatedAdded) {
    push(bold("Reputation"));
    if (diff.provenanceLost) push(yellow("  ! npm provenance attestation lost"));
    if (diff.deprecatedAdded) push(yellow(`  ! now deprecated: ${diff.deprecatedAdded}`));
    push();
  }
  if (diff.size && (diff.size.unpackedSizeDelta ?? 0) !== 0) {
    const kilobytes = Math.round((diff.size.unpackedSizeDelta ?? 0) / 1024);
    push(bold("Size") + dim(`  unpacked ${kilobytes >= 0 ? "+" : ""}${kilobytes.toLocaleString("en-US")} kB${diff.size.fileCountDelta !== undefined ? `, ${diff.size.fileCountDelta >= 0 ? "+" : ""}${diff.size.fileCountDelta} files` : ""}`));
    push();
  }
  if (diff.score.delta !== 0) {
    const paint = diff.score.delta < 0 ? red : green;
    push(bold("Security score") + dim(`  ${diff.score.before} → `) + paint(`${diff.score.after}`) + dim(` (${diff.score.delta >= 0 ? "+" : ""}${diff.score.delta})`));
    push();
  }
  const anyChange = lifecycle.added.length || lifecycle.removed.length || lifecycle.changed.length || diff.newScriptFindings.length || dependencies.added.length || dependencies.removed.length || dependencies.changed.length || diff.maintainers.added.length || diff.maintainers.removed.length || diff.repositoryChanged || native.added.length || native.newBinaries.length || native.newAndroidPermissions.length || diff.advisories.added.length || diff.advisories.resolved.length || diff.provenanceLost || diff.deprecatedAdded || diff.score.delta !== 0;
  if (!anyChange) push(dim("No noteworthy changes between these versions."));
  push(bold("Diff risk: ") + RISK_COLOR[diff.diffRisk](bold(diff.diffRisk.toUpperCase())));
  for (const reason of diff.riskReasons) push(`  • ${reason.replace(/^\[(high|medium)\] /, "")}`);
  push();
  return lines.join("\n");
}

