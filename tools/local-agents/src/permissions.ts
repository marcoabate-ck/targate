/**
 * Per-role tool permissions.
 *
 * Translates a role definition into the concrete `--allowedTools` /
 * `--disallowedTools` lists passed to the Claude Code worker. Tool-level
 * denial is the coarse layer; the PreToolUse command guard is the fine layer.
 * Read-only roles hard-deny every write tool so a classifier gap can never let
 * a discovery/reviewer worker mutate the tree.
 */

import type { RoleConfig } from "./config.js";

/** Write tools that a read-only role must never receive. */
export const WRITE_TOOLS = ["Edit", "Write", "MultiEdit", "NotebookEdit"] as const;

/** Tools no worker gets by default: no nested agents, no network. */
export const ALWAYS_DENY = ["Task", "WebFetch", "WebSearch"] as const;

/** Read/search tools every worker may use. */
export const READ_TOOLS = ["Read", "Grep", "Glob", "TodoWrite"] as const;

export interface ResolvedPermissions {
  allowedTools: string[];
  disallowedTools: string[];
}

/**
 * Compute the allow/deny tool lists for a role. `Bash` is always allowed at
 * the tool level (the command guard decides per-command); write tools are
 * granted only to writer roles.
 */
export function resolvePermissions(role: RoleConfig): ResolvedPermissions {
  const allowed = new Set<string>([...READ_TOOLS, "Bash"]);
  const disallowed = new Set<string>([...ALWAYS_DENY]);

  if (role.readOnly) {
    for (const t of WRITE_TOOLS) disallowed.add(t);
  } else {
    for (const t of WRITE_TOOLS) allowed.add(t);
  }

  for (const t of role.allowTools ?? []) {
    allowed.add(t);
    disallowed.delete(t);
  }
  for (const t of role.denyTools ?? []) {
    disallowed.add(t);
    allowed.delete(t);
  }

  // Denial always wins over an accidental allow of the same tool name.
  for (const t of disallowed) allowed.delete(t);

  return {
    allowedTools: [...allowed].sort(),
    disallowedTools: [...disallowed].sort(),
  };
}
