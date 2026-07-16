import path from "node:path";
import type { ContentFindings } from "../types.js";
import { referencedScriptFiles } from "./scripts.js";
import { resolveResourceLimits, type ResolvedResourceLimits } from "../resource-limits.js";
import { readIndexedFile, resolveFileIndex, type PackageFileIndex } from "./file-index.js";

const CODE_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".ts", ".sh"]);
interface FileScan {
  relPath: string;
  processEnv: boolean;
  childProcess: boolean;
  network: boolean;
  evalUsage: boolean;
  minified: boolean;
}

// These patterns are DELIBERATELY loose (e.g. the bare "axios" substring
// flags any file that merely mentions the library): the scanner is a recall-
// oriented heuristic whose hits become weak signals for the rules/AI layers,
// not verdicts on their own. False positives cost a warning line; false
// negatives cost a missed exfiltration path. See "Scope and limitations" in
// the README before tightening these.
function scanSource(relPath: string, source: string): FileScan {
  const lines = source.split("\n");
  const avgLineLength = source.length / Math.max(lines.length, 1);
  return {
    relPath,
    processEnv: /process\.env\b/.test(source),
    childProcess:
      /child_process|execSync|spawnSync|\bexecFile\b/.test(source),
    network:
      /https?\.request|\bfetch\s*\(|require\(['"]https?['"]\)|net\.connect|axios|XMLHttpRequest|\bdns\.[a-z]/i.test(
        source,
      ),
    evalUsage: /\beval\s*\(|new Function\s*\(/.test(source),
    minified: source.length > 5000 && avgLineLength > 500,
  };
}

/**
 * Scan the extracted package for suspicious code patterns without executing
 * anything. Install-time files (referenced by lifecycle scripts) get
 * dedicated findings since code running at install time is the riskiest.
 */
export async function analyzeContent(
  packageInput: string | PackageFileIndex,
  lifecycleScripts: Record<string, string>,
  limits: ResolvedResourceLimits = resolveResourceLimits(),
): Promise<ContentFindings> {
  const index = await resolveFileIndex(packageInput, limits);
  const files = index.files.filter((file) => CODE_EXTENSIONS.has(file.extension));

  const installTimeFiles = new Set<string>();
  for (const command of Object.values(lifecycleScripts)) {
    for (const ref of referencedScriptFiles(command)) {
      // relPath is POSIX-separated; normalize refs the same way so matching is
      // host-independent (path.normalize would introduce `\` on Windows).
      installTimeFiles.add(path.posix.normalize(ref));
    }
  }

  const findings: ContentFindings = {
    hasProcessEnvAccess: false,
    hasChildProcessUsage: false,
    hasNetworkCalls: false,
    hasEvalUsage: false,
    hasMinifiedCode: false,
    suspiciousFiles: [],
    installTimeFindings: [],
  };

  for (const file of files) {
    const source = await readIndexedFile(file);
    if (!source) continue;

    const relPath = file.relPath;
    const scan = scanSource(relPath, source);

    findings.hasProcessEnvAccess ||= scan.processEnv;
    findings.hasChildProcessUsage ||= scan.childProcess;
    findings.hasNetworkCalls ||= scan.network;
    findings.hasEvalUsage ||= scan.evalUsage;
    findings.hasMinifiedCode ||= scan.minified;

    const flags: string[] = [];
    if (scan.processEnv) flags.push("reads process.env");
    if (scan.childProcess) flags.push("spawns child processes");
    if (scan.network) flags.push("performs network calls");
    if (scan.evalUsage) flags.push("uses eval/Function");
    if (scan.minified) flags.push("appears minified/obfuscated");

    if (flags.length > 0) {
      findings.suspiciousFiles.push(`${relPath}: ${flags.join(", ")}`);
    }
    if (installTimeFiles.has(path.posix.normalize(relPath)) && flags.length > 0) {
      findings.installTimeFindings.push(
        `install-time file ${relPath} ${flags.join(", ")}`,
      );
    }
  }

  // Keep the report readable
  findings.suspiciousFiles = findings.suspiciousFiles.slice(0, 20);
  return findings;
}
