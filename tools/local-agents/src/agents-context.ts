/**
 * Repository-instruction delivery.
 *
 * Each worker gets the AGENTS.md that apply to its working directory, honouring
 * the nested-scope convention: files closer to the working directory are more
 * specific and listed last (they win on conflict, same as most agent tools
 * resolve nested instruction files). Unrelated AGENTS.md elsewhere in the tree
 * are not loaded. Optional repo-specific per-role instructions live under
 * `.claude/local-agents/roles/<role>.md` and are loaded verbatim.
 *
 * This never duplicates the full instruction bodies into a generic prompt — it
 * assembles exactly the in-scope files and lets native Claude Code discovery
 * (workers run non-`--bare`) reinforce it.
 */

import { readFile, stat } from "node:fs/promises";
import path from "node:path";

const AGENTS_FILENAME = "AGENTS.md";
/** Cap so a huge AGENTS.md cannot blow the worker's context budget. */
const MAX_TOTAL_BYTES = 24 * 1024;

async function readIfExists(file: string): Promise<string | null> {
  try {
    const s = await stat(file);
    if (!s.isFile()) return null;
    return await readFile(file, "utf8");
  } catch {
    return null;
  }
}

/**
 * Collect AGENTS.md from `repoRoot` down to `workingDir` (inclusive), ordered
 * root-first so nearer, more specific files appear last. `workingDir` must be
 * inside `repoRoot`; otherwise only the repo root is considered.
 */
export async function collectAgentsFiles(
  repoRoot: string,
  workingDir: string,
): Promise<{ path: string; content: string }[]> {
  const root = path.resolve(repoRoot);
  const work = path.resolve(workingDir);
  const chain: string[] = [];

  // Build the directory chain root → work.
  const rel = path.relative(root, work);
  if (rel === "" ) {
    chain.push(root);
  } else if (!rel.startsWith("..") && !path.isAbsolute(rel)) {
    let current = root;
    chain.push(current);
    for (const segment of rel.split(path.sep)) {
      current = path.join(current, segment);
      chain.push(current);
    }
  } else {
    // Working dir outside the repo: only honour the repo-root instructions.
    chain.push(root);
  }

  const files: { path: string; content: string }[] = [];
  for (const dir of chain) {
    const file = path.join(dir, AGENTS_FILENAME);
    const content = await readIfExists(file);
    if (content !== null) {
      files.push({ path: path.relative(root, file) || AGENTS_FILENAME, content });
    }
  }
  return files;
}

/** Render the in-scope AGENTS.md into a single, size-bounded digest string. */
export function renderAgentsDigest(files: { path: string; content: string }[]): string {
  if (files.length === 0) return "";
  const blocks: string[] = [];
  let used = 0;
  for (const f of files) {
    const header = `--- ${f.path} ---\n`;
    const remaining = MAX_TOTAL_BYTES - used - header.length;
    if (remaining <= 0) {
      blocks.push(`(remaining AGENTS.md omitted for length)`);
      break;
    }
    const body =
      f.content.length > remaining
        ? f.content.slice(0, remaining) + "\n…(truncated)"
        : f.content;
    blocks.push(header + body.trim());
    used += header.length + body.length;
  }
  return blocks.join("\n\n");
}

/** Load optional repo-specific per-role instructions (data, not executed). */
export async function loadRepoRoleInstructions(
  repoRoot: string,
  role: string,
): Promise<string | null> {
  if (!/^[a-z][a-z0-9-]*$/.test(role)) return null; // guard the filename
  const file = path.join(repoRoot, ".claude", "local-agents", "roles", `${role}.md`);
  return readIfExists(file);
}

/** Convenience: the digest string for a worker's working directory. */
export async function agentsContextFor(
  repoRoot: string,
  workingDir: string,
): Promise<string> {
  const files = await collectAgentsFiles(repoRoot, workingDir);
  return renderAgentsDigest(files);
}
