/**
 * Path containment checks.
 *
 * A worker may only touch files inside its assigned scope: the repository
 * (or an isolated worktree) and the run-artifact directory. These helpers
 * resolve symlinks where the target exists and normalise relative traversal so
 * that `../../etc/passwd` or a symlink escape is rejected before any write.
 */

import { realpathSync } from "node:fs";
import path from "node:path";

/** Resolve a path to an absolute, symlink-expanded form (best effort). */
function canonical(p: string): string {
  const abs = path.resolve(p);
  try {
    // realpath the deepest existing ancestor, then re-append the tail so that
    // not-yet-created files are still checked against a real parent directory.
    return resolveExistingPrefix(abs);
  } catch {
    return abs;
  }
}

function resolveExistingPrefix(abs: string): string {
  let current = abs;
  const tail: string[] = [];
  // Walk up until we hit a path that exists, realpath it, then rejoin.
  for (;;) {
    try {
      const real = realpathSync(current);
      return tail.length ? path.join(real, ...tail.reverse()) : real;
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return abs; // reached filesystem root
      tail.push(path.basename(current));
      current = parent;
    }
  }
}

/** True when `child` is inside (or equal to) `parent` after canonicalisation. */
export function isInside(parent: string, child: string): boolean {
  const p = canonical(parent);
  const c = canonical(child);
  if (c === p) return true;
  const rel = path.relative(p, c);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

/** True when `target` lies within ANY of the allowed scope roots. */
export function isWithinScopes(scopes: readonly string[], target: string): boolean {
  return scopes.some((scope) => isInside(scope, target));
}

/**
 * Validate that every changed path stays within scope. Returns the list of
 * offending paths (empty when all are contained).
 */
export function violatingPaths(
  scopes: readonly string[],
  targets: readonly string[],
): string[] {
  return targets.filter((t) => !isWithinScopes(scopes, t));
}
