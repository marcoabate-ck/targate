# Policy reference

The team policy is an optional file in your project root that is applied **on top of** every targate assessment. It is **escalation-only** — it can make a decision stricter, never more permissive — with a single, deliberate exception: `allowKnownPackages` can pre-clear a _soft_ block. It can never override a **hard** block.

Scaffold one with `targate policy init [--format yaml|json]`. This page is the complete reference; for the workflow around it (approvals, pnpm builds) see [Team workflow](team-workflow.md).

## File location & formats

The policy lives in the project root under the basename `targate.policy`. Configuration is **declarative only** — parsed, never executed. Lookup order (first existing file wins):

```text
targate.policy.yaml   →  .yml   →  .json
```

- `.yaml` / `.yml` / `.json` are **parsed, never executed** — always safe.
- Executable `.ts` / `.js` / `.mjs` / `.cjs` config (and the `jiti` runtime) was **removed**: a repository cannot run code through a config file. A leftover legacy file is ignored and flagged by `targate doctor` — convert it to YAML/JSON.
- Every format goes through the same schema validation.

## Schema

```ts
interface PolicyFile {
  dependencyPolicy: DependencyPolicy; // required
  aiCache?: AiCachePolicy; // optional — see ai-cache.md
  registries?: Record<string, { mirrorOf: string }>;
  resourceLimits?: ResourceLimits;
}

interface ResourceLimits {
  networkTimeoutMs?: number;
  maxResponseBytes?: number;
  maxTarballBytes?: number;
  maxExtractedBytes?: number;
  maxFiles?: number;
  maxFileBytes?: number;
  maxScanDuration?: number;
  maxAuditFiles?: number;
  maxAuditBytes?: number;
}

interface DependencyPolicy {
  blockRecentlyPublishedPackages?: boolean;
  minPackageAgeDays?: number;
  requireApprovalForNativeCode?: boolean;
  requireApprovalForLifecycleScripts?: boolean;
  blockMissingRepositoryForRuntimeDeps?: boolean;
  allowKnownPackages?: string[];
  blockPackages?: string[];
  requireSignedApprovals?: boolean;
  requirePublicMirrorVerification?: boolean;
  trustBehaviorFingerprint?: boolean;
  internalScopes?: string[];
  codeAudit?: "off" | "flagged" | "direct" | "all";
  requireApprovalForAdvisorySeverity?: "low" | "moderate" | "high" | "critical";
  blockForAdvisorySeverity?: "low" | "moderate" | "high" | "critical";
}
```

### `registries` fields

Use this mapping when a scoped/private registry is an exact mirror of another registry. Targate fetches the exact version's checksum independently from `mirrorOf` and hard-blocks any divergence. Global `.npmrc` `registry=` overrides default to `https://registry.npmjs.org`; scoped registries require this explicit declaration. Policy `internalScopes` are never compared publicly.

```yaml
registries:
  https://packages.example.com:
    mirrorOf: https://registry.npmjs.org
```

### `dependencyPolicy` fields

| Field                                  | Type                                            | Default¹                     | Effect                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------- | ----------------------------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `blockRecentlyPublishedPackages`       | boolean                                         | `false`                      | If a package is younger than `minPackageAgeDays` (7 if unset), **block** it.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `minPackageAgeDays`                    | number ≥ 0                                      | `7`²                         | Minimum package age. Younger packages are escalated to **require_approval** (or **block** if `blockRecentlyPublishedPackages` is also set).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `requireApprovalForNativeCode`         | boolean                                         | `false`                      | Any package with native code (iOS/Android/Podspec/Gradle/CMake) → **require_approval**.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `requireApprovalForLifecycleScripts`   | boolean                                         | `true`¹                      | Any package with an **install-time** lifecycle script (`preinstall`/`install`/`postinstall`) → **require_approval**. Pack/publish-time hooks (`prepare`/`prepack`/`postpack`) don't run on a registry install and don't trigger this.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `blockMissingRepositoryForRuntimeDeps` | boolean                                         | `false`                      | Package with no repository metadata → **block**.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `allowKnownPackages`                   | string[]                                        | `["react", "react-native"]`¹ | Pre-approved names. Clears **soft** (heuristic) blocks to `allow`; **cannot** clear a hard block.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `blockPackages`                        | string[]                                        | `[]`                         | Names that are always **blocked**, evaluated before the allow list.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `requireSignedApprovals`               | boolean                                         | `false`                      | Only honor approvals whose SSH signature verifies against the committed `.targate/allowed-signers`; unsigned/invalid entries are ignored (the package asks again). See [signed approvals](team-workflow.md#signed-approvals--targate-approve---sign).                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `requirePublicMirrorVerification`      | boolean                                         | `false`                      | A mirrored package whose upstream registry cannot be reached becomes `require_approval` instead of `allow_with_warnings`. Divergence is always a hard block regardless of this setting. Enabled by the `strict`, `ci`, and `ai-agent` presets.                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `trustBehaviorFingerprint`             | boolean                                         | `false`                      | Reuse a prior approval of a **different version** of the same package when the new version's **behavior fingerprint** is unchanged — so a routine bump of an already-vetted dependency does not re-prompt. A match can only clear a **soft** verdict; an install-script change, a new dangerous capability (network/child_process/eval), a provenance downgrade, an incomplete analysis, or any **hard** block all still re-prompt, and a legacy approval with no recorded fingerprint is never reused. Off by default (approvals stay strictly version-exact). Packages with install scripts (e.g. esbuild) still re-prompt on every release by design — their install code changes each version. |
| `internalScopes`                       | string[] (each starting `@`)                    | `[]`                         | Scopes whose package **names must not leak**: OSV, npm downloads, maintainer search and GitHub lookups are skipped, typosquat similarity is not applied, and every skip is shown in the report/score. See [private registries](private-registries.md#internalscopes--name-privacy).                                                                                                                                                                                                                                                                                                                                                                                                                |
| `codeAudit`                            | `"off"` \| `"flagged"` \| `"direct"` \| `"all"` | `"off"`                      | Scope of the AI **source-code audit** (`--audit-code`): `flagged` audits only packages the deterministic pass flagged, `direct` the project's direct dependencies, `all` every analyzed package. Findings only ever **escalate** the verdict (clamped — a hard block can never be audited into an approval). The `--audit-code` flag turns it on ad-hoc (at least `flagged`); `strict`/`ai-agent` enable `flagged`, `ci` forces `off`.                                                                                                                                                                                                                                                             |
| `requireApprovalForAdvisorySeverity`   | `"low"` \| `"moderate"` \| `"high"` \| `"critical"` | unset | A package whose worst known-vulnerability advisory (OSV) is **at or above** this severity → **require_approval**. `unknown`-severity advisories never trigger it (still scored and surfaced). The `ai-agent` preset sets `high`. |
| `blockForAdvisorySeverity`             | `"low"` \| `"moderate"` \| `"high"` \| `"critical"` | unset | As above, but **block** at or above the level. If both thresholds match, block wins. |

¹ Defaults shown are the values `targate policy init` scaffolds. A field you omit from your file simply doesn't apply — there is no hidden default beyond note ².
² `minPackageAgeDays` only takes effect when it is set, or when `blockRecentlyPublishedPackages` is `true` (in which case an unset `minPackageAgeDays` falls back to `7`).

### `aiCache` fields

Controls reuse of AI assessments between runs (never used in CI). Full detail in [AI response cache](ai-cache.md).

| Field      | Type                    | Default  | Effect                                    |
| ---------- | ----------------------- | -------- | ----------------------------------------- |
| `enabled`  | boolean                 | `true`   | Turn the AI response cache on/off.        |
| `scope`    | `"user"` \| `"project"` | `"user"` | Where the cache lives.                    |
| `ttlHours` | number > 0              | `24`     | How long a cached assessment stays fresh. |
| `exclude`  | string[]                | `[]`     | Package names never served from cache.    |

### `resourceLimits` fields

Every value is a positive integer. Durations are milliseconds; sizes are bytes. Defaults are deliberately generous enough for normal npm packages but finite.

| Field               |     Default | Effect                                                                                                                         |
| ------------------- | ----------: | ------------------------------------------------------------------------------------------------------------------------------ |
| `networkTimeoutMs`  |     `15000` | Whole-response timeout for untrusted network requests, including body streaming.                                               |
| `maxResponseBytes`  |  `16777216` | Maximum body size for registry, OSV, npm search/downloads, maintainer, and GitHub JSON responses.                              |
| `maxTarballBytes`   |  `67108864` | Maximum compressed tarball download.                                                                                           |
| `maxExtractedBytes` | `268435456` | Maximum total uncompressed bytes extracted for one package.                                                                    |
| `maxFiles`          |     `20000` | Maximum archive entries and extracted filesystem objects; also bounds the shared file index consumed by every static analyzer. |
| `maxFileBytes`      |  `33554432` | Maximum size of one extracted/scanned file.                                                                                    |
| `maxScanDuration`   |     `20000` | Maximum static-analysis duration for one package.                                                                              |
| `maxAuditFiles`     |        `15` | Maximum source files sent to the AI code audit (`--audit-code`) for one package.                                               |
| `maxAuditBytes`     |    `262144` | Maximum total source bytes sent to the AI code audit for one package; larger files are sliced.                                 |

Crossing a package-analysis limit is not a clean result: targate renders the missing evidence as `UNKNOWN` and deterministically requires approval. Network-only reputation/OSV failures retain their documented degraded-state policy.

## Examples

```yaml
# targate.policy.yaml
dependencyPolicy:
  blockRecentlyPublishedPackages: false
  minPackageAgeDays: 7
  requireApprovalForNativeCode: false
  requireApprovalForLifecycleScripts: true
  requirePublicMirrorVerification: false
  blockMissingRepositoryForRuntimeDeps: false
  allowKnownPackages: [react, react-native]
  blockPackages: []
aiCache:
  enabled: true
  scope: user
  ttlHours: 24
  exclude: []
registries:
  https://packages.example.com:
    mirrorOf: https://registry.npmjs.org
resourceLimits:
  networkTimeoutMs: 15000
  maxTarballBytes: 67108864
  maxExtractedBytes: 268435456
  maxFiles: 20000
  maxFileBytes: 33554432
  maxScanDuration: 20000
```

`targate.policy.json` — the same schema in JSON (declarative, parsed never executed):

```json
{
  "dependencyPolicy": {
    "minPackageAgeDays": 14,
    "requireApprovalForLifecycleScripts": true,
    "blockPackages": ["left-pad"]
  }
}
```

## Decision values

targate emits one of four decisions, ordered by strictness (the single source of truth for "which is stricter"):

| Decision              | Strictness | Install behaviour                                                      |
| --------------------- | ---------- | ---------------------------------------------------------------------- |
| `allow`               | 0          | Installs (confirmation prompt unless `--yes`).                         |
| `allow_with_warnings` | 1          | Installs after surfacing warnings (confirmation unless `--yes`).       |
| `require_approval`    | 2          | Defaults to installing with `--ignore-scripts`, or record an approval. |
| `block`               | 3          | Never installs; exits `2`.                                             |

"Escalation" means moving _up_ this scale; the policy engine never moves a decision down it — except `allowKnownPackages`, which sets `allow` directly.

## Precedence

The order in which effects are resolved. Higher entries win over lower ones.

```text
1. Hard deterministic block   — artifact-identity mismatch, known-malicious
                                 OSV/OpenSSF record, or a lifecycle command that
                                 downloads AND executes remote code.
                                 Immune to the AI, the allow list, approvals, and policy.
2. Team blockPackages         — an explicit block-list entry (evaluated before the allow list).
3. Team allowKnownPackages    — clears a SOFT block to `allow`; ignored against a hard block.
4. Rules-engine verdict       — the deterministic floor.
5. AI reviewer                — advisory; can only escalate, never downgrade the rules verdict (the clamp).
6. Remaining policy rules     — age / native-code / lifecycle-script / missing-repository escalations.
```

Within the policy stage specifically, `applyPolicy` resolves in this order: known-malicious short-circuit → `blockPackages` → incomplete-analysis floor → `allowKnownPackages` → age → native code → lifecycle scripts → mirror availability → missing repository. `blockPackages` is checked **before** `allowKnownPackages`, so a name on both lists stays blocked; missing analysis evidence is also never converted to allow-list trust.

### Allowed vs. disallowed overrides

- **Allowed:** `allowKnownPackages` clearing a **soft/heuristic** block (e.g. esbuild's install script that reads env + hits the network to fetch a platform binary) — a deliberate, committed decision to trust that package. It cannot clear an incomplete/resource-limited analysis because missing evidence is not a heuristic finding. Prefer a version-pinned `.targate/approvals.json` entry when you want to trust one exact version rather than all future ones.
- **Disallowed:** nothing clears a **hard** block. A known-malicious record or a `curl … | bash`-style download-and-execute stays blocked even if the package is on `allowKnownPackages`; the report notes the allow list was ignored. See [Hard vs soft blocks](decisions.md#hard-vs-soft-blocks).

## Validation & errors

The policy is schema-validated on load (a `PolicyError` aborts the run with a clear message):

- the document must contain (or export) a `dependencyPolicy` mapping;
- `blockRecentlyPublishedPackages`, `requireApprovalForNativeCode`, `requireApprovalForLifecycleScripts`, `blockMissingRepositoryForRuntimeDeps` must be booleans;
- `minPackageAgeDays` must be a non-negative finite number;
- `allowKnownPackages` and `blockPackages` must be lists of strings;
- `aiCache.enabled` boolean, `aiCache.scope` one of `"user"`/`"project"`, `aiCache.ttlHours` a positive number, `aiCache.exclude` a list of strings.
- every `registries` key and `mirrorOf` value must be an absolute URL.
- every `resourceLimits` field must be a recognized positive integer.

Invalid YAML/JSON is reported as an `Invalid YAML: …` error rather than silently ignored.

## CI vs. local behaviour

- **Local:** all fields apply; `aiCache` speeds up re-reviews.
- **CI (the `CI` env var is set):** the `aiCache` is **not** used — CI always recomputes so a stale cached assessment can't mask a change. Policy escalations still apply. `targate approve` refuses to run in CI entirely; approvals reach CI only through the reviewed, committed `.targate/approvals.json`. Pair with `--fail-on-osv-error` so an unreachable OSV lookup fails closed. See [CI integration](ci.md).
- **Untrusted repos:** no action is needed; config is declarative only (`.yaml`/`.yml`/`.json`, parsed never executed), so a cloned repo cannot run code through a targate policy file. Any leftover legacy executable `targate.policy.{ts,js,…}` is ignored and flagged by `targate doctor`.

## Related

- [Team workflow](team-workflow.md) — approvals, the approval cache, pnpm `approve-builds`.
- [Decision policy](decisions.md) — how a verdict is chosen and the hard-vs-soft-block distinction.
- [AI response cache](ai-cache.md) — the `aiCache` section in depth.
