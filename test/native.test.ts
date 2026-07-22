import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { analyzeNativeSurface, hasNativeCode } from "../src/analyze/native.js";

let dir: string;

async function fixture(files: Record<string, string>): Promise<string> {
  dir = await mkdtemp(path.join(tmpdir(), "targate-test-"));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
});

describe("analyzeNativeSurface", () => {
  it("detects a JS-only package as non-native", async () => {
    const pkg = await fixture({
      "package.json": "{}",
      "index.js": "module.exports = {}",
    });
    const surface = await analyzeNativeSurface(pkg);
    expect(hasNativeCode(surface)).toBe(false);
  });

  // Regression (P2): iOS source at the package root (not under ios/) must set
  // hasIos — the old code had a dead extension branch that only fired for ios/.
  it("detects iOS source files outside an ios/ directory", async () => {
    const pkg = await fixture({
      "package.json": "{}",
      "MyView.swift": "import UIKit",
      "Helper.mm": "@implementation Helper @end",
    });
    const surface = await analyzeNativeSurface(pkg);
    expect(surface.hasIos).toBe(true);
  });

  // Regression (v3 P3): the iOS extension match must be case-insensitive.
  it("detects iOS source with uppercase extensions", async () => {
    const pkg = await fixture({ "package.json": "{}", "Legacy.MM": "@implementation X @end" });
    const surface = await analyzeNativeSurface(pkg);
    expect(surface.hasIos).toBe(true);
  });

  it("detects a typical React Native native module", async () => {
    const pkg = await fixture({
      "package.json": "{}",
      "MyModule.podspec": "Pod::Spec.new do |s| end",
      "ios/MyModule.swift": "import Foundation",
      "android/build.gradle": "apply plugin: 'com.android.library'",
      "android/src/main/AndroidManifest.xml": `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
        <uses-permission android:name="android.permission.INTERNET" />
        <uses-permission android:name="android.permission.CAMERA" />
      </manifest>`,
    });
    const surface = await analyzeNativeSurface(pkg);
    expect(surface.hasIos).toBe(true);
    expect(surface.hasAndroid).toBe(true);
    expect(surface.hasPodspec).toBe(true);
    expect(surface.hasGradle).toBe(true);
    expect(surface.androidPermissions).toEqual([
      "android.permission.INTERNET",
      "android.permission.CAMERA",
    ]);
    expect(hasNativeCode(surface)).toBe(true);
  });

  it("detects binary artifacts", async () => {
    const pkg = await fixture({
      "package.json": "{}",
      "prebuilt/lib.so": "binary",
    });
    const surface = await analyzeNativeSurface(pkg);
    // binaryArtifacts use POSIX-separated relPaths, host-independent.
    expect(surface.binaryArtifacts).toContain("prebuilt/lib.so");
    expect(hasNativeCode(surface)).toBe(true);
  });
});
