import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { parseDocument } from "yaml";

const WORKSPACE_FILE = "pnpm-workspace.yaml";

export type BuildApproval = "approved" | "ignored";

/**
 * Persist a build-script decision through pnpm's native approve-builds
 * mechanism: approved packages go to onlyBuiltDependencies (their scripts
 * run), ignored ones to ignoredBuiltDependencies (installed, scripts
 * skipped, no interactive prompt). Editing pnpm-workspace.yaml is exactly
 * what `pnpm approve-builds` does — bye just decides WITH the analysis.
 *
 * Returns the file path written, or null when the project has no
 * pnpm-workspace.yaml and none should be created (non-pnpm projects).
 */
export async function recordBuildApproval(
  packageName: string,
  approval: BuildApproval,
  cwd: string = process.cwd(),
  opts: { createWorkspaceFile?: boolean } = {},
): Promise<string | null> {
  const file = path.join(cwd, WORKSPACE_FILE);
  const exists = existsSync(file);
  if (!exists && !opts.createWorkspaceFile) return null;

  const doc = parseDocument(exists ? await readFile(file, "utf8") : "{}\n");
  const key = approval === "approved" ? "onlyBuiltDependencies" : "ignoredBuiltDependencies";
  const otherKey = approval === "approved" ? "ignoredBuiltDependencies" : "onlyBuiltDependencies";

  const current = (doc.get(key) as { items?: unknown[] } | undefined)?.items ?? [];
  const values = new Set(
    (Array.isArray(current) ? current : []).map((n) => String((n as { value?: unknown }).value ?? n)),
  );
  if (!values.has(packageName)) {
    values.add(packageName);
    doc.set(key, [...values].sort());
  }

  // A package cannot be both approved and ignored — drop it from the other list.
  const other = (doc.get(otherKey) as { items?: unknown[] } | undefined)?.items;
  if (Array.isArray(other)) {
    const remaining = other
      .map((n) => String((n as { value?: unknown }).value ?? n))
      .filter((n) => n !== packageName);
    if (remaining.length !== other.length) doc.set(otherKey, remaining.sort());
  }

  await writeFile(file, doc.toString());
  return file;
}
