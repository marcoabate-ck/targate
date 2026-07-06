import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { NativeSurface } from "../types.js";

const BINARY_EXTENSIONS = new Set([
  ".so",
  ".a",
  ".jar",
  ".aar",
  ".dylib",
  ".node",
  ".dll",
  ".exe",
  ".bin",
]);

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
 * Detect the React Native native surface of an extracted package:
 * iOS/Android sources, Podspecs, Gradle files, CMake, binaries and
 * Android permissions requested in manifests.
 */
export async function analyzeNativeSurface(packageDir: string): Promise<NativeSurface> {
  const files: string[] = [];
  await walk(packageDir, packageDir, files);

  const surface: NativeSurface = {
    hasIos: false,
    hasAndroid: false,
    hasPodspec: false,
    hasGradle: false,
    hasCMake: false,
    hasRnConfig: false,
    binaryArtifacts: [],
    androidPermissions: [],
  };

  const manifests: string[] = [];

  for (const rel of files) {
    const segments = rel.split(path.sep);
    const basename = path.basename(rel);

    if (segments[0] === "ios" || /\.(m|mm|swift|h)$/.test(basename)) {
      if (segments[0] === "ios") surface.hasIos = true;
    }
    if (segments.includes("ios")) surface.hasIos = true;
    if (segments.includes("android")) surface.hasAndroid = true;
    if (basename.endsWith(".podspec")) surface.hasPodspec = true;
    if (basename === "build.gradle" || basename === "build.gradle.kts") {
      surface.hasGradle = true;
    }
    if (basename === "CMakeLists.txt") surface.hasCMake = true;
    if (basename === "react-native.config.js") surface.hasRnConfig = true;
    if (BINARY_EXTENSIONS.has(path.extname(basename))) {
      surface.binaryArtifacts.push(rel);
    }
    if (basename === "AndroidManifest.xml") manifests.push(rel);
  }

  for (const manifest of manifests) {
    const content = await readFile(path.join(packageDir, manifest), "utf8").catch(
      () => "",
    );
    const permissions = [
      ...content.matchAll(/<uses-permission[^>]*android:name="([^"]+)"/g),
    ].map((m) => m[1]);
    surface.androidPermissions.push(...permissions);
  }
  surface.androidPermissions = [...new Set(surface.androidPermissions)];
  surface.binaryArtifacts = surface.binaryArtifacts.slice(0, 20);

  return surface;
}

export function hasNativeCode(surface: NativeSurface): boolean {
  return (
    surface.hasIos ||
    surface.hasAndroid ||
    surface.hasPodspec ||
    surface.hasGradle ||
    surface.hasCMake ||
    surface.binaryArtifacts.length > 0
  );
}
