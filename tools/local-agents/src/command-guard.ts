/**
 * Command classification for the Bash tool guard.
 *
 * This is ONE layer of defense in depth, not the only one. It runs inside the
 * PreToolUse hook (see hook-guard.ts) and decides whether a shell command a
 * worker wants to run is permitted. It is deliberately conservative: unknown
 * or ambiguous commands are denied for read-only roles, and a fixed family of
 * dangerous commands is denied for every role regardless of parsing success.
 *
 * The guard is backed by env-var credential isolation, per-role tool denial,
 * and post-hoc path validation — so a classifier miss degrades to those layers
 * rather than to a free-for-all.
 */

export type GuardDecision = "allow" | "deny";

export interface GuardResult {
  decision: GuardDecision;
  reason: string;
}

/** Shell operators that separate independent commands within one string. */
const SEGMENT_SPLIT = /(?:\|\||&&|\||;|\n)/;

/** Leading VAR=value assignments to skip when finding the command word. */
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=[^\s]*$/;

/**
 * Commands denied for EVERY role, matched against the whole command string so
 * they cannot be evaded by splitting. Each entry pairs a matcher with a reason.
 */
const HARD_DENY: { test: RegExp; reason: string }[] = [
  { test: /\b(npm|pnpm|yarn|bun)\s+(install|i|add|ci)\b/, reason: "dependency install is forbidden for workers" },
  { test: /\bnpm\s+(exec|x)\b/, reason: "npm exec runs arbitrary packages" },
  { test: /\bpnpm\s+dlx\b/, reason: "pnpm dlx runs arbitrary packages" },
  { test: /\byarn\s+dlx\b/, reason: "yarn dlx runs arbitrary packages" },
  { test: /\b(npx|bunx)\b/, reason: "npx/bunx runs arbitrary packages" },
  { test: /\b(npm|pnpm|yarn)\s+publish\b/, reason: "publishing is forbidden for workers" },
  { test: /\b(curl|wget)\b[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash)\b/, reason: "piping a download into a shell is forbidden" },
  { test: /\b(curl|wget|nc|ncat|telnet)\b/, reason: "network fetch tools are forbidden for workers" },
  { test: /\bsudo\b/, reason: "sudo is forbidden" },
  { test: /\bgit\s+push\b/, reason: "git push is forbidden for workers" },
  { test: /\bgit\s+reset\s+--hard\b/, reason: "git reset --hard is destructive" },
  { test: /\bgit\s+clean\b/, reason: "git clean is destructive" },
  { test: /\bgit\s+checkout\s+--\s/, reason: "git checkout -- discards changes" },
  { test: /\bgit\s+restore\b/, reason: "git restore discards changes" },
  { test: /\bgit\s+(commit|rebase|merge|cherry-pick|tag)\b/, reason: "git history changes are the human's responsibility" },
  { test: /\brm\s+(-[a-zA-Z]*r|-[a-zA-Z]*f|--recursive|--force)/, reason: "recursive/forced rm is destructive" },
  { test: /\bchmod\s+[0-7]*777\b/, reason: "chmod 777 is unsafe" },
  { test: /:\(\)\s*\{.*\|.*&.*\}/, reason: "fork bomb pattern" },
  { test: /\bmkfs\b|\bdd\s+if=/, reason: "raw disk operation is forbidden" },
];

/** Command heads a read-only worker may run. Anything else is denied. */
const READ_ONLY_HEADS = new Set<string>([
  "git", "ls", "cat", "head", "tail", "wc", "rg", "grep", "egrep", "fgrep",
  "find", "pwd", "echo", "printf", "jq", "sort", "uniq", "cut", "tr",
  "tree", "stat", "file", "which", "type", "basename", "dirname", "realpath",
  "node", "diff", "cmp", "date", "env", "true", "false", "test",
]);

/** git subcommands a read-only worker may run. */
const GIT_READ_ONLY = new Set<string>([
  "status", "diff", "log", "show", "rev-parse", "ls-files", "ls-tree",
  "branch", "remote", "config", "describe", "blame", "shortlog", "cat-file",
  "worktree", "for-each-ref", "symbolic-ref", "rev-list", "name-rev",
]);

/** Split a compound command into its independent segments. */
export function splitSegments(command: string): string[] {
  return command
    .split(SEGMENT_SPLIT)
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Extract the command word of a segment, skipping leading VAR=value pairs. */
export function commandHead(segment: string): string | null {
  const tokens = segment.split(/\s+/).filter(Boolean);
  let i = 0;
  while (i < tokens.length && ENV_ASSIGNMENT.test(tokens[i])) i++;
  const head = tokens[i];
  if (!head) return null;
  // Strip a path prefix: /usr/bin/git -> git, ./node -> node.
  const base = head.replace(/^.*\//, "");
  return base;
}

/** Second token (subcommand) of a segment, ignoring env assignments/flags. */
function subcommand(segment: string): string | null {
  const tokens = segment.split(/\s+/).filter(Boolean);
  let i = 0;
  while (i < tokens.length && ENV_ASSIGNMENT.test(tokens[i])) i++;
  i++; // skip the head
  while (i < tokens.length && tokens[i].startsWith("-")) i++;
  return tokens[i] ?? null;
}

export interface ClassifyOptions {
  /** Read-only roles use an allowlist; writers use the hard-deny list only. */
  readOnly: boolean;
}

/**
 * Classify a shell command. Denies on the first failing rule. A command that
 * cannot be parsed into segments is denied (fail closed).
 */
export function classifyCommand(command: string, options: ClassifyOptions): GuardResult {
  const trimmed = command.trim();
  if (!trimmed) return { decision: "deny", reason: "empty command" };

  // Hard-deny families first — matched against the full string.
  for (const rule of HARD_DENY) {
    if (rule.test.test(trimmed)) return { decision: "deny", reason: rule.reason };
  }

  // Reject shell-level tricks that defeat per-segment parsing.
  if (/\$\(|\`|<\(/.test(trimmed) && options.readOnly) {
    return { decision: "deny", reason: "command substitution is not allowed for read-only roles" };
  }

  const segments = splitSegments(trimmed);
  if (segments.length === 0) return { decision: "deny", reason: "no runnable command found" };

  if (!options.readOnly) {
    // Writers: hard-deny list already applied; allow the rest.
    return { decision: "allow", reason: "permitted for writer role" };
  }

  // Read-only roles: every segment must be a known read-only command.
  for (const segment of segments) {
    const head = commandHead(segment);
    if (!head) return { decision: "deny", reason: `unparseable segment: ${segment}` };
    if (!READ_ONLY_HEADS.has(head)) {
      return { decision: "deny", reason: `command "${head}" is not read-only` };
    }
    if (head === "git") {
      const sub = subcommand(segment);
      if (!sub || !GIT_READ_ONLY.has(sub)) {
        return { decision: "deny", reason: `git ${sub ?? "?"} is not a read-only subcommand` };
      }
    }
    // A read-only worker must not write via shell redirection.
    if (/>>?\s*\S/.test(segment)) {
      return { decision: "deny", reason: `output redirection is not allowed: ${segment}` };
    }
    // node/test may not run scripts that mutate; block obvious write flags.
    if (head === "node" && /\s-e\b|\s--eval\b/.test(segment)) {
      return { decision: "deny", reason: "node -e can run arbitrary code" };
    }
  }

  return { decision: "allow", reason: "read-only command" };
}
