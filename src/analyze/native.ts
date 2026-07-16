import path from "node:path";
import type { NativeSurface } from "../types.js";
import { readIndexedFile, resolveFileIndex, type PackageFileIndex } from "./file-index.js";

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

/**
 * Detect the React Native native surface of an extracted package:
 * iOS/Android sources, Podspecs, Gradle files, CMake, binaries and
 * Android permissions requested in manifests.
 */
export async function analyzeNativeSurface(packageInput: string | PackageFileIndex): Promise<NativeSurface> {
  const index = await resolveFileIndex(packageInput);

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

  const manifests = [];

  for (const file of index.files) {
    const rel = file.relPath;
    const segments = rel.split("/"); // relPath is POSIX-separated, host-independent
    const basename = file.basename;

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
    if (basename === "AndroidManifest.xml") manifests.push(file);
  }

  for (const manifest of manifests) {
    const content = await readIndexedFile(manifest);
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
