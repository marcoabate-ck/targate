import type { Signals } from "../src/types.js";

export function makeSignals(overrides: Partial<Signals> = {}): Signals {
  return {
    package: "example-package",
    version: "1.0.0",
    lifecycleScripts: {},
    hasLifecycleScripts: false,
    hasNativeCode: false,
    nativeSurface: {
      hasIos: false,
      hasAndroid: false,
      hasPodspec: false,
      hasGradle: false,
      hasCMake: false,
      hasRnConfig: false,
      binaryArtifacts: [],
      androidPermissions: [],
    },
    rnHardening: {
      podspecFindings: [],
      gradleFindings: [],
      dangerousPermissions: [],
      iosFrameworkFindings: [],
      autolinkingFindings: [],
      compatNotes: [],
    },
    content: {
      hasProcessEnvAccess: false,
      hasChildProcessUsage: false,
      hasNetworkCalls: false,
      hasEvalUsage: false,
      hasMinifiedCode: false,
      suspiciousFiles: [],
      installTimeFindings: [],
    },
    knownMalicious: false,
    maliciousRecords: [],
    advisories: [],
    repositoryMissing: false,
    recentPublish: false,
    ageInDays: 800,
    nameSimilarity: null,
    dependencyCount: 2,
    ...overrides,
  };
}
