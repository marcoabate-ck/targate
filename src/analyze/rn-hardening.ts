import { readIndexedFile, resolveFileIndex, type PackageFileIndex } from "./file-index.js";
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
  // A SINGLE `[^{}]*?` bounded to one brace block — no nested quantifier, so
  // no O(n²) backtracking (the `\burl\b` gate was dropped: after comment
  // stripping, any http:// inside a maven { } block is the insecure-repo
  // signal). Comment stripping removes the dotall false positive.
  [/maven\s*\{[^{}]*?http:\/\//is, "uses an insecure http:// Maven repository"],
  [/url\s+['"]http:\/\//, "downloads from an insecure http:// URL"],
  [/download(File)?\s*\(|new URL\(.*openStream/i, "downloads files during the build"],
  [/apply\s+from:\s*['"]https?:\/\//, "applies a remote Gradle script (executes remote code at build time)"],
];

/**
 * Remove Gradle/Groovy comments so a commented-out line can't trip a finding —
 * WITHOUT ever treating comment syntax that lives inside a string literal as a
 * comment. A regex stripper could be fooled by an attacker wrapping the
 * block-comment open/close markers in string literals around a real finding,
 * deleting the region in between and hiding it. This single-pass scanner tracks
 * string state, so comment markers inside a quote are preserved (and a genuine
 * `http://` in a URL string survives too). O(n), no backtracking.
 */
function stripGradleComments(content: string): string {
  let out = "";
  let quote: string | null = null;
  for (let i = 0; i < content.length; i++) {
    const c = content[i];
    const next = content[i + 1];
    if (quote) {
      out += c;
      if (c === "\\") {
        out += next ?? "";
        i++;
      } else if (c === quote) {
        quote = null;
      }
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      out += c;
      continue;
    }
    if (c === "/" && next === "/") {
      while (i < content.length && content[i] !== "\n") i++;
      i--; // let the loop's i++ land on the newline so it is preserved
      continue;
    }
    if (c === "/" && next === "*") {
      i += 2;
      while (i < content.length && !(content[i] === "*" && content[i + 1] === "/")) i++;
      i++; // skip the closing '/', loop's i++ skips the '*'
      out += " ";
      continue;
    }
    out += c;
  }
  return out;
}

export function reviewGradle(fileName: string, content: string): string[] {
  const stripped = stripGradleComments(content);
  const findings: string[] = [];
  for (const [pattern, description] of GRADLE_PATTERNS) {
    if (pattern.test(stripped)) findings.push(`${fileName}: ${description}`);
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
  /**
   * True only when the package is actually a React Native module (real RN
   * signals — a `react-native` dependency, codegenConfig, RN/Expo config files,
   * a React-dependent podspec, or RN bridge/JSI symbols in native source), NOT
   * merely because it ships iOS/Android files. Gates the RN/Expo-specific
   * "interop" notes so a plain native package (e.g. a CLI with helper native
   * files) does not get React-Native-framework guidance that does not apply to
   * it. Marketing `keywords` are deliberately NOT a signal.
   */
  isReactNative: boolean;
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
  } else if (inputs.hasNativeCode && inputs.isReactNative) {
    notes.push(
      "Native module without codegenConfig — likely an old-architecture bridge module; check New Architecture interop.",
    );
  }

  if (inputs.hasExpoModuleConfig) {
    notes.push("Ships an expo-module.config.json — installable as an Expo module.");
  } else if (inputs.hasNativeCode && inputs.hasAppPlugin) {
    notes.push("Native code with an Expo config plugin (app.plugin.js) — works in Expo prebuild.");
  } else if (inputs.hasNativeCode && inputs.isReactNative) {
    notes.push(
      "Native code without an Expo config plugin — requires a bare workflow or a custom dev client in Expo projects.",
    );
  }

  return notes;
}

/** Native-source symbols that mean "this is a React Native bridge/native module"
 *  (iOS ObjC/Swift, Android Java/Kotlin, or C++ TurboModule/JSI). */
const RN_BRIDGE_PATTERN =
  /RCTBridgeModule|RCTEventEmitter|RCTViewManager|#import\s*<React\/|com\.facebook\.react|ReactContextBaseJavaModule|\bReactPackage\b|\bTurboModule\b|facebook::react/;

/** A podspec that declares a dependency on a React Native pod. */
const PODSPEC_REACT_DEP =
  /\bdependency\b[^\n#]*['"](?:React|React-Core|ReactCommon|React-jsi|hermes-engine)\b/;

/** Native source extensions scanned for RN bridge / JSI symbols. */
const NATIVE_SOURCE_RE = /\.(h|hpp|cpp|mm|m|swift|java|kt)$/;

/** Whether `react-native` is declared in any dependency field of a manifest. */
function dependsOnReactNative(manifest: Record<string, unknown>): boolean {
  for (const field of [
    "dependencies",
    "peerDependencies",
    "devDependencies",
    "optionalDependencies",
  ]) {
    const deps = manifest[field];
    if (deps && typeof deps === "object" && !Array.isArray(deps) && "react-native" in deps) {
      return true;
    }
  }
  return false;
}

/**
 * Run the phase-3 React Native hardening review over an extracted package.
 * Everything is static — nothing is compiled or executed.
 */
export async function analyzeRnHardening(
  packageInput: string | PackageFileIndex,
  androidPermissions: string[],
  hasNativeCode: boolean,
): Promise<RnHardening> {
  const index = await resolveFileIndex(packageInput);

  const result: RnHardening = {
    podspecFindings: [],
    gradleFindings: [],
    dangerousPermissions: classifyDangerousPermissions(androidPermissions),
    iosFrameworkFindings: [],
    autolinkingFindings: [],
    compatNotes: [],
  };

  let usesJsi = false;
  let rnBridge = false;
  let podspecUsesReact = false;

  for (const file of index.files) {
    const rel = file.relPath;
    const basename = file.basename;

    if (basename.endsWith(".podspec")) {
      const content = await readIndexedFile(file);
      result.podspecFindings.push(...reviewPodspec(rel, content));
      if (PODSPEC_REACT_DEP.test(content)) podspecUsesReact = true;
    }
    if (basename === "build.gradle" || basename === "build.gradle.kts" || basename === "settings.gradle") {
      result.gradleFindings.push(...reviewGradle(rel, await readIndexedFile(file)));
    }
    if (basename === "react-native.config.js") {
      result.autolinkingFindings.push(
        ...reviewAutolinkingConfig(await readIndexedFile(file)),
      );
    }
    if (/\.(framework|xcframework)(\/|$)/.test(rel)) {
      const root = rel.match(/^.*?\.(?:framework|xcframework)/)?.[0];
      if (root && !result.iosFrameworkFindings.includes(root)) {
        result.iosFrameworkFindings.push(root);
      }
    }
    if (NATIVE_SOURCE_RE.test(basename) && (!usesJsi || !rnBridge)) {
      const content = await readIndexedFile(file);
      if (!usesJsi && /jsi\/jsi\.h|facebook::jsi/.test(content)) usesJsi = true;
      if (!rnBridge && RN_BRIDGE_PATTERN.test(content)) rnBridge = true;
    }
  }

  let manifest: Record<string, unknown> = {};
  try {
    const manifestFile = index.byBasename.get("package.json")?.find(
      (file) => path.posix.dirname(file.relPath) === ".",
    );
    if (manifestFile) manifest = JSON.parse(await readIndexedFile(manifestFile));
  } catch {
    /* tolerate broken package.json — other analyzers already flag it */
  }
  const packageJson = manifest as CompatInputs["packageJson"];

  const hasExpoModuleConfig = index.byBasename.has("expo-module.config.json");
  const hasAppPlugin = index.byBasename.has("app.plugin.js");
  const hasRnConfigFile =
    index.byBasename.has("react-native.config.js") || hasExpoModuleConfig || hasAppPlugin;

  // A package is treated as React Native ONLY on real RN signals — never on
  // marketing `keywords`. A plain native package (iOS/Android files but no RN
  // relationship) gets no RN/Expo-framework guidance.
  const isReactNative =
    dependsOnReactNative(manifest) ||
    Boolean(packageJson.codegenConfig) ||
    hasRnConfigFile ||
    usesJsi ||
    podspecUsesReact ||
    rnBridge;

  result.compatNotes = buildCompatNotes({
    packageJson,
    hasExpoModuleConfig,
    hasAppPlugin,
    usesJsi,
    hasNativeCode,
    isReactNative,
  });

  return result;
}
