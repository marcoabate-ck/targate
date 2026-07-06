import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import type { ContentFindings } from "../types.js";
import { referencedScriptFiles } from "./scripts.js";

const CODE_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".ts", ".sh"]);
const MAX_FILE_SIZE = 2 * 1024 * 1024; // skip files > 2MB
const MAX_FILES = 2000;

interface FileScan {
  relPath: string;
  processEnv: boolean;
  childProcess: boolean;
  network: boolean;
  evalUsage: boolean;
  minified: boolean;
}

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

async function collectFiles(dir: string, base: string, acc: string[]): Promise<void> {
  if (acc.length >= MAX_FILES) return;
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    if (acc.length >= MAX_FILES) return;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      await collectFiles(full, base, acc);
    } else if (entry.isFile() && CODE_EXTENSIONS.has(path.extname(entry.name))) {
      acc.push(full);
    }
  }
}

/**
 * Scan the extracted package for suspicious code patterns without executing
 * anything. Install-time files (referenced by lifecycle scripts) get
 * dedicated findings since code running at install time is the riskiest.
 */
export async function analyzeContent(
  packageDir: string,
  lifecycleScripts: Record<string, string>,
): Promise<ContentFindings> {
  const files: string[] = [];
  await collectFiles(packageDir, packageDir, files);

  const installTimeFiles = new Set<string>();
  for (const command of Object.values(lifecycleScripts)) {
    for (const ref of referencedScriptFiles(command)) {
      installTimeFiles.add(path.normalize(ref));
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
    let info;
    try {
      info = await stat(file);
    } catch {
      continue;
    }
    if (info.size > MAX_FILE_SIZE) continue;

    const source = await readFile(file, "utf8").catch(() => "");
    if (!source) continue;

    const relPath = path.relative(packageDir, file);
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
    if (installTimeFiles.has(path.normalize(relPath)) && flags.length > 0) {
      findings.installTimeFindings.push(
        `install-time file ${relPath} ${flags.join(", ")}`,
      );
    }
  }

  // Keep the report readable
  findings.suspiciousFiles = findings.suspiciousFiles.slice(0, 20);
  return findings;
}
