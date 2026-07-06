import { readdir, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";

/** Phase-3 deep React Native checks (workshop proposal §9). */
export interface RnHardening {
  /** Suspicious constructs in *.podspec files. */
  podspecFindings: string[];
  /** Suspicious constructs in Gradle build files. */
  gradleFindings: string[];
  /** Android permissions classified as dangerous. */
  dangerousPermissions: string[];
  /** Pre-built iOS frameworks / vendored binaries. */
  iosFrameworkFindings: string[];
  /** react-native.config.js contents that deserve review. */
  autolinkingFindings: string[];
  /** Hermes / New Architecture / Expo compatibility notes (informational). */
  compatNotes: string[];
}

/** Android permissions that gate access to sensitive user data or hardware. */
const DANGEROUS_ANDROID_PERMISSIONS = new Set([
  "android.permission.CAMERA",
  "android.permission.RECORD_AUDIO",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_BACKGROUND_LOCATION",
  "android.permission.READ_CONTACTS",
  "android.permission.WRITE_CONTACTS",
  "android.permission.READ_SMS",
  "android.permission.SEND_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.READ_CALL_LOG",
  "android.permission.WRITE_CALL_LOG",
  "android.permission.READ_PHONE_STATE",
  "android.permission.CALL_PHONE",
  "android.permission.READ_CALENDAR",
  "android.permission.WRITE_CALENDAR",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.MANAGE_EXTERNAL_STORAGE",
  "android.permission.BODY_SENSORS",
  "android.permission.ACTIVITY_RECOGNITION",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.QUERY_ALL_PACKAGES",
]);

export function classifyDangerousPermissions(permissions: string[]): string[] {
  return permissions.filter((p) => DANGEROUS_ANDROID_PERMISSIONS.has(p));
}

const PODSPEC_PATTERNS: Array<[RegExp, string]> = [
  [/prepare_command/, "runs a prepare_command (arbitrary shell at pod install time)"],
  [/script_phase/, "adds a script_phase (arbitrary shell during Xcode build)"],
  [/\bcurl\b|\bwget\b/, "downloads content from the network"],
  [/vendored_frameworks/, "ships pre-built (vendored) frameworks — binary code you cannot read"],
  [/vendored_libraries/, "ships pre-built (vendored) libraries"],
  [/http:\/\//, "references an insecure http:// URL"],
];

export function reviewPodspec(fileName: string, content: string): string[] {
  const findings: string[] = [];
  for (const [pattern, description] of PODSPEC_PATTERNS) {
    if (pattern.test(content)) findings.push(`${fileName}: ${description}`);
  }
  return findings;
}

const GRADLE_PATTERNS: Array<[RegExp, string]> = [
  [/Runtime\.getRuntime\(\)\.exec|ProcessBuilder|commandLine\s|\bexec\s*\{/, "executes external commands during the build"],
  [/^(?!\s*\/\/).*maven\s*\{[^}]*url[^}]*http:\/\//ms, "uses an insecure http:// Maven repository"],
  [/url\s+['"]http:\/\//, "downloads from an insecure http:// URL"],
  [/download(File)?\s*\(|new URL\(.*openStream/i, "downloads files during the build"],
  [/apply\s+from:\s*['"]https?:\/\//, "applies a remote Gradle script (executes remote code at build time)"],
];

export function reviewGradle(fileName: string, content: string): string[] {
  const findings: string[] = [];
  for (const [pattern, description] of GRADLE_PATTERNS) {
    if (pattern.test(content)) findings.push(`${fileName}: ${description}`);
  }
  return findings;
}

const AUTOLINKING_PATTERNS: Array<[RegExp, string]> = [
  [/commands\s*:/, "registers custom CLI commands (run with developer privileges)"],
  [/child_process|execSync|spawn/, "spawns processes from the autolinking config"],
  [/https?:\/\//, "references remote URLs"],
];

export function reviewAutolinkingConfig(content: string): string[] {
  const findings: string[] = [];
  for (const [pattern, description] of AUTOLINKING_PATTERNS) {
    if (pattern.test(content)) findings.push(`react-native.config.js: ${description}`);
  }
  return findings;
}

interface CompatInputs {
  packageJson: {
    codegenConfig?: unknown;
    peerDependencies?: Record<string, string>;
    dependencies?: Record<string, string>;
  };
  hasExpoModuleConfig: boolean;
  hasAppPlugin: boolean;
  usesJsi: boolean;
  hasNativeCode: boolean;
}

export function buildCompatNotes(inputs: CompatInputs): string[] {
  const notes: string[] = [];
  const { packageJson } = inputs;

  if (packageJson.codegenConfig) {
    notes.push("Declares codegenConfig — built for the New Architecture (Turbo Module / Fabric).");
  } else if (inputs.usesJsi) {
    notes.push(
      "Uses JSI directly without codegenConfig — verify New Architecture compatibility with the maintainer.",
    );
  } else if (inputs.hasNativeCode) {
    notes.push(
      "Native module without codegenConfig — likely an old-architecture bridge module; check New Architecture interop.",
    );
  }

  if (inputs.hasExpoModuleConfig) {
    notes.push("Ships an expo-module.config.json — installable as an Expo module.");
  } else if (inputs.hasNativeCode && inputs.hasAppPlugin) {
    notes.push("Native code with an Expo config plugin (app.plugin.js) — works in Expo prebuild.");
  } else if (inputs.hasNativeCode) {
    notes.push(
      "Native code without an Expo config plugin — requires a bare workflow or a custom dev client in Expo projects.",
    );
  }

  return notes;
}

async function walk(dir: string, base: string, acc: string[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      await walk(full, base, acc);
    } else {
      acc.push(path.relative(base, full));
    }
  }
}

/**
 * Run the phase-3 React Native hardening review over an extracted package.
 * Everything is static — nothing is compiled or executed.
 */
export async function analyzeRnHardening(
  packageDir: string,
  androidPermissions: string[],
  hasNativeCode: boolean,
): Promise<RnHardening> {
  const files: string[] = [];
  await walk(packageDir, packageDir, files);

  const result: RnHardening = {
    podspecFindings: [],
    gradleFindings: [],
    dangerousPermissions: classifyDangerousPermissions(androidPermissions),
    iosFrameworkFindings: [],
    autolinkingFindings: [],
    compatNotes: [],
  };

  let usesJsi = false;

  for (const rel of files) {
    const basename = path.basename(rel);
    const full = path.join(packageDir, rel);

    if (basename.endsWith(".podspec")) {
      result.podspecFindings.push(...reviewPodspec(rel, await readFile(full, "utf8").catch(() => "")));
    }
    if (basename === "build.gradle" || basename === "build.gradle.kts" || basename === "settings.gradle") {
      result.gradleFindings.push(...reviewGradle(rel, await readFile(full, "utf8").catch(() => "")));
    }
    if (basename === "react-native.config.js") {
      result.autolinkingFindings.push(
        ...reviewAutolinkingConfig(await readFile(full, "utf8").catch(() => "")),
      );
    }
    if (/\.(framework|xcframework)(\/|$)/.test(rel)) {
      const root = rel.match(/^.*?\.(?:framework|xcframework)/)?.[0];
      if (root && !result.iosFrameworkFindings.includes(root)) {
        result.iosFrameworkFindings.push(root);
      }
    }
    if (/\.(h|hpp|cpp|mm)$/.test(basename) && !usesJsi) {
      const content = await readFile(full, "utf8").catch(() => "");
      if (/jsi\/jsi\.h|facebook::jsi/.test(content)) usesJsi = true;
    }
  }

  let packageJson: CompatInputs["packageJson"] = {};
  try {
    packageJson = JSON.parse(await readFile(path.join(packageDir, "package.json"), "utf8"));
  } catch {
    /* tolerate broken package.json — other analyzers already flag it */
  }

  result.compatNotes = buildCompatNotes({
    packageJson,
    hasExpoModuleConfig: existsSync(path.join(packageDir, "expo-module.config.json")),
    hasAppPlugin: existsSync(path.join(packageDir, "app.plugin.js")),
    usesJsi,
    hasNativeCode,
  });

  return result;
}

export function hasHardeningFindings(rn: RnHardening): boolean {
  return (
    rn.podspecFindings.length > 0 ||
    rn.gradleFindings.length > 0 ||
    rn.dangerousPermissions.length > 0 ||
    rn.autolinkingFindings.length > 0
  );
}
