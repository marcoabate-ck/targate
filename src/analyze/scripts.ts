/**
 * Hooks npm runs when a dependency is installed FROM THE REGISTRY tarball —
 * i.e. code that executes on the consumer's machine during `install`. These
 * are the ones that gate as require_approval.
 */
export const INSTALL_TIME_SCRIPT_NAMES = [
  "preinstall",
  "install",
  "postinstall",
] as const;

/**
 * Pack/publish-time hooks. `prepare` runs on `npm publish`/`npm pack` and when
 * installing a git or local dependency, but NOT when installing a published
 * registry tarball; `prepack`/`postpack` only run on pack/publish. For a
 * registry-resolved dependency these never execute on the consumer's machine,
 * so their mere presence is informational, not an install-time risk.
 */
export const PACK_TIME_SCRIPT_NAMES = ["prepare", "prepack", "postpack"] as const;

export const LIFECYCLE_SCRIPT_NAMES = [
  ...INSTALL_TIME_SCRIPT_NAMES,
  ...PACK_TIME_SCRIPT_NAMES,
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

/** True for a hook npm runs when installing this package from the registry. */
export function isInstallTimeScript(name: string): boolean {
  return (INSTALL_TIME_SCRIPT_NAMES as readonly string[]).includes(name);
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
