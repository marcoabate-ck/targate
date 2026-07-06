export const LIFECYCLE_SCRIPT_NAMES = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepack",
  "postpack",
] as const;

/** Extract only install-relevant lifecycle scripts from a scripts map. */
export function extractLifecycleScripts(
  scripts: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of LIFECYCLE_SCRIPT_NAMES) {
    if (scripts[name]) out[name] = scripts[name];
  }
  return out;
}

const SUSPICIOUS_COMMAND_PATTERNS: Array<[RegExp, string]> = [
  [/curl|wget/i, "downloads content from the network"],
  [/\bbash\b|\bsh\s+-c\b/, "invokes a shell"],
  [/base64/i, "uses base64 encoding/decoding"],
  [/\beval\b/, "uses eval"],
  [/\$\(.*\)/, "uses command substitution"],
  [/>\s*\/|>>\s*\//, "writes to absolute filesystem paths"],
  [/\.ssh|id_rsa|\.npmrc|\.aws|\.env\b/i, "references credential or config files"],
  [/powershell|cmd\s+\/c/i, "invokes a Windows shell"],
  [/node\s+-e\s/, "runs inline node code"],
];

/**
 * Statically inspect a lifecycle script command string and describe
 * suspicious behaviors. Returns human-readable findings.
 */
export function inspectScriptCommand(name: string, command: string): string[] {
  const findings: string[] = [];
  for (const [pattern, description] of SUSPICIOUS_COMMAND_PATTERNS) {
    if (pattern.test(command)) {
      findings.push(`${name} script ${description}: \`${command}\``);
    }
  }
  return findings;
}

/**
 * Find the local files referenced by a lifecycle script command
 * (e.g. "node scripts/setup.js" -> ["scripts/setup.js"]) so content
 * analysis can prioritize install-time code.
 */
export function referencedScriptFiles(command: string): string[] {
  const matches = command.match(/[\w./-]+\.(?:js|cjs|mjs|sh)\b/g) ?? [];
  return matches.filter((m) => !m.startsWith("/"));
}
