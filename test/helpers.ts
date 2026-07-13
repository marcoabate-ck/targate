import type { PackageMetadata, ReputationSignals, Signals } from "../src/types.js";

/** A minimal, valid PackageMetadata — override per test. */
export function makeMetadata(overrides: Partial<PackageMetadata> = {}): PackageMetadata {
  return {
    name: "example-package",
    version: "1.0.0",
    maintainers: ["alice"],
    tarballUrl: "https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz",
    scripts: {},
    dependencyCount: 0,
    directDependencies: [],
    registryReputation: { hasProvenance: false },
    ...overrides,
  };
}

/** A healthy, lookup-skipped reputation block — override per test. */
export function makeReputation(overrides: Partial<ReputationSignals> = {}): ReputationSignals {
  return {
    versionAgeDays: 200,
    releaseAfterInactivityDays: 30,
    releaseGapAnomaly: false,
    maintainerCount: 2,
    maintainerChange: null,
    repositoryMismatch: false,
    hasProvenance: false,
    deprecated: false,
    downloads: { status: "skipped" },
    repo: { status: "skipped" },
    ...overrides,
  };
}

export function makeSignals(overrides: Partial<Signals> = {}): Signals {
  return {
    package: "example-package",
    version: "1.0.0",
    artifact: {
      trust: "registry-consistent",
      digest: "sha512-dGVzdA==",
      registryUrl: "https://registry.npmjs.org",
      tarballUrl: "https://registry.npmjs.org/example-package/-/example-package-1.0.0.tgz",
      registryIntegrity: "sha512-dGVzdA==",
      reasons: ["test fixture"],
    },
    lifecycleScripts: {},
    hasLifecycleScripts: false,
    scriptCommandFindings: [],
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
    osvUnavailable: false,
    repositoryMissing: false,
    recentPublish: false,
    ageInDays: 800,
    nameSimilarity: null,
    dependencyCount: 2,
    directDependencies: [],
    reputation: makeReputation(),
    ...overrides,
  };
}
