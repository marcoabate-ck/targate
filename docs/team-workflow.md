# Team workflow

## Approving a package — `targate approve`

There are two ways to record an approval, and both write the same committable entry:

```bash
targate approve esbuild@0.27.3          # review + record, WITHOUT installing
targate add esbuild@0.27.3              # review + record + install (interactive)
```

Use **`targate approve`** when you want to clear a `require_approval` / [soft block](decisions.md#hard-vs-soft-blocks) ahead of time — e.g. so a teammate's `targate add` or a CI run passes without stopping — but you don't want to install the package into your working tree right now. It analyzes the package, shows the report, and asks for a single confirmation before recording the approval. The approval is recorded as **scripts-disabled** (`no-scripts`) by default; add `--allow-scripts` to record it as scripts-allowed. Other flags: `--yes` skips the confirmation prompt, `--deep` also vets the transitive tree, `--json` prints the assessment plus the recorded `approval`.

Recording requires **explicit human intent**, by design:

- `--json` alone **never records** — a machine parsing the verdict must not create an approval as a side effect. To record non-interactively, pass `--yes` explicitly.
- `targate approve` **refuses to run in CI** (the `CI` env var): approvals reach CI through the reviewed, committed `.targate/approvals.json`, never by being created there.
- A **hard block** can never be approved — `targate approve` on a known-malicious / remote-exec package refuses and exits `2`. An already-`allow` package needs no approval and records nothing.

The recorded mode is **binding at install time**: a `no-scripts` approval makes the later `targate add` install run with `--ignore-scripts`, and on pnpm projects `approve` also writes the decision to `pnpm-workspace.yaml` (`ignoredBuiltDependencies` / `onlyBuiltDependencies`) so even a raw `pnpm install` honors it.

**Triaging several packages at once.** When `targate install` (including `--dry-run`) flags multiple packages, an interactive terminal offers an **arrow-key triage picker** (↑/↓ move, `a` approve, `d` deny, `s` toggle scripts, enter confirm) with a live per-package detail panel — see [Transitive dependencies & full-tree install](transitive-and-install.md). Approvals default to `no-scripts` (press `s`, or use `targate approve <pkg> --allow-scripts`, when a package genuinely needs its lifecycle scripts); denials are written to `.targate/denials.json` so the rejected version is never re-offered. **Commit both files** — approvals and denials travel with the repo the same way. A denial can be reversed later with `targate approve <pkg>@<version>` (which clears the denial).

`--dry-run` is *not* how you approve: it is a pure preview (analyze + report, no prompt, no install, nothing recorded).

## Approval cache — `.targate/approvals.*`

Either path above records the approval (name@version, mode, who, when) in `.targate/approvals.json`. **Commit the file**: the rest of the team — and CI — treat that exact version as already reviewed. A new version requires a new approval.

Approvals can also be hand-curated declaratively in `.targate/approvals.{yaml,yml,json}`. Existing declarative files are **merged**, with the tool-managed `approvals.json` winning on conflicts (a fresh interactive approval must always take effect). Automatic recording only ever writes `approvals.json`; the other formats are read-only sources. Legacy typed/JavaScript sources are ignored by default and require the same explicit `TARGATE_ALLOW_EXEC_CONFIG=1` migration opt-in as policy files. For a trusted legacy typed file:

```ts
// .targate/approvals.ts
import { defineApprovals } from "targate";

export default defineApprovals({
  "core-js@3.49.0": { mode: "no-scripts", approvedAt: "2026-07-07T00:00:00Z", approvedBy: "marco" },
});
```

Every entry is validated at runtime: `mode` must be exactly `normal` or `no-scripts`, `approvedAt` must be a valid ISO timestamp, and `approvedBy`, when present, must be a string. Invalid records are ignored with a warning naming the file and key; an unknown mode never defaults to scripts-enabled approval.

## pnpm `approve-builds` integration

On pnpm projects, an interactive approval also updates `pnpm-workspace.yaml` through pnpm's native mechanism:

- approved **with** scripts → the package is added to `onlyBuiltDependencies`
- approved **without** scripts → added to `ignoredBuiltDependencies` (installed, scripts silently skipped, no interactive pnpm prompt)

## Lockfile diff preview

After every real install, `targate` prints which packages the install actually added to the lockfile (direct + transitive), so surprise transitive dependencies are visible immediately.

## Artifact ledger — `.targate/artifacts.json`

Every successful real `targate add` / `targate install` records the SHA-512 digest of the exact reviewed artifact, keyed by registry origin and `name@version`. Commit `.targate/artifacts.json` to share that historical identity with teammates and CI. A later same-version digest change is a hard block; targate never overwrites the old value and the normal approval flow cannot clear it. The ledger is evidence of prior observation, not proof that a first-seen private artifact was authentic.

## Team policy — `targate.policy.*`

`targate policy init [--format yaml|json|js|ts]` scaffolds the policy file (YAML by default). Declarative YAML/JSON loads by default; executable JS/TS is migration-only and opt-in. For the complete field-by-field schema, defaults, precedence, resource limits, and validation rules, see the [Policy reference](policy-reference.md); this section is the workflow-level summary.

```yaml
# targate.policy.yaml
dependencyPolicy:
  blockRecentlyPublishedPackages: false
  minPackageAgeDays: 7
  requireApprovalForNativeCode: false
  requireApprovalForLifecycleScripts: true
  blockMissingRepositoryForRuntimeDeps: false
  allowKnownPackages: [react, react-native]
  blockPackages: []
aiCache: # see ai-cache.md
  enabled: true
  scope: user
  ttlHours: 24
  exclude: []
```

```ts
// targate.policy.ts — fully typed
import type { PolicyFile } from "targate";

const policy: PolicyFile = {
  dependencyPolicy: { minPackageAgeDays: 7, requireApprovalForLifecycleScripts: true },
};

export default policy;
```

`.yaml`/`.json` files are declarative and load by default. Legacy `.ts`/`.js` files are ignored unless a trusted operator sets **`TARGATE_ALLOW_EXEC_CONFIG=1`**; only then are they executed through [jiti](https://github.com/unjs/jiti), with a strong warning. Every loaded format goes through the same schema validation. Prefer the generated YAML policy, especially in repositories agents may clone. The policy is applied **on top of** the AI/rules assessment and can only make decisions stricter — with one exception: `allowKnownPackages` pre-approves packages. Its power is bounded by the [hard/soft block](decisions.md#hard-vs-soft-blocks) distinction:

- a **hard block** (known-malicious record, or a `curl … | bash`-style download-and-execute) can never be overridden — the package stays blocked, and the report notes the allow list was ignored;
- a **soft/heuristic block** (e.g. an install script that reads env + hits the network, like esbuild) **is** cleared to `allow` by an allow-list entry — a deliberate, committed decision to trust that package. Prefer a version-pinned `.targate/approvals.json` entry (recorded automatically when you approve interactively) when you want to trust one exact version rather than all future ones.

## Trust history — `targate history`

Every recorded approval carries its circumstances — the **trust history**: who approved, when, what the analysis concluded at that moment (decision, risk, score, top reasons), which targate version and AI provider/model produced the verdict, and which policy file (name + sha256) was in force. It is written into the same committed `.targate/approvals.json`, so git history on that file is the audit trail of *who committed which trust decision*.

```bash
targate history                 # every approval, newest first
targate history esbuild         # one package (or esbuild@0.27.3 for one version)
targate history --verify        # additionally verify signatures (see below)
targate history --json          # machine-readable (schemaVersion 1)
```

```text
Trust history — 2 approval(s), newest first

  esbuild@0.27.3  (no-scripts)
      marco on 2026-07-10 23:33:05  ✓ signature valid (marco@acme.com)
      decision at review: require_approval · risk medium · score 69/100
      targate 0.1.0 · anthropic/claude-opus-4-8 · policy targate.policy.yaml#a1b2c3d4e5f6
      - Install-time code reads environment variables AND performs network calls …
```

Old entries (recorded before trust history existed, or hand-curated in `approvals.ts`/`.yaml`) simply have no context — they still load and still clear approvals.

## Signed approvals — `targate approve --sign`

An approvals file is only as trustworthy as the last person with write access to it. `--sign` makes each entry **cryptographically verifiable**:

```bash
targate approve esbuild@0.27.3 --sign
```

- **Mechanism:** OpenSSH signatures (`ssh-keygen -Y`) — the same scheme git uses for SSH commit signing, so developers already have the keys and no extra tooling is installed. The key is resolved from `TARGATE_SIGNING_KEY`, then `git config user.signingkey` (a key file path, or a literal `ssh-ed25519 …` public key signed via ssh-agent), then `~/.ssh/id_ed25519`/`id_ecdsa`/`id_rsa`. *GPG and Sigstore/SLSA attestations are deliberately out of scope for now.*
- **What is signed:** the canonical JSON of the whole entry — package\@version, mode, date, approver, and the trust-history context — in the dedicated `targate-approval` namespace (a signature can never be replayed from another context, even with the same key). Changing **any** covered field invalidates it: flipping a `no-scripts` approval to `normal` is exactly the tampering the signature catches.
- **Trust anchor:** the committed `.targate/allowed-signers` file, standard OpenSSH [ALLOWED SIGNERS](https://man.openbsd.org/ssh-keygen#ALLOWED_SIGNERS) format:

```text
# .targate/allowed-signers — commit this file
marco@acme.com namespaces="targate-approval" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5…
```

- **Verification:** `targate history --verify` checks every entry (exit `2` on any invalid signature). A signing failure aborts the recording — an approval requested as signed is never silently written unsigned.
- **Enforcement:** set `requireSignedApprovals: true` in the team policy and every consumer of approvals (`targate add`, `targate install`, `targate ci`) ignores entries that are unsigned or fail verification — the affected package simply asks for approval again, and stderr says which entry was dropped and why. In CI this is the property that matters: pushing a hand-edited `approvals.json` can no longer green a poisoned dependency.

## Policy packs — `targate policy init --preset`

Ready-made policies to start from instead of a blank default:

| Preset | Intent |
|---|---|
| `default` | Balanced: lifecycle scripts need approval, everything else warns |
| `strict` | Young packages block, native code + scripts need approval, `requireSignedApprovals` on, empty allow list |
| `react-native` | Native code (Podspec / Gradle / permissions) always gets a human; missing repos block |
| `ci` | Approvals only from the committed file; scripts and missing repos stop the build; AI cache off |
| `ai-agent` | For unattended agents: anything needing judgment stops the agent — a human approves out-of-band |

```bash
targate policy init --preset strict            # yaml by default
targate policy init --preset ai-agent --format ts
```

The generated file's header names the preset, and every preset passes the same schema validation as a hand-written policy — it is a starting point to edit, not a hidden mode.

## Monitoring risk over time — `targate monitor`

Approving a package vouches for it *at a point in time*. `targate monitor` re-checks the packages you already trust and reports what got worse since a stored baseline — a new vulnerability, a maintainer change, a deprecation, an archived repository, lost provenance, a suspicious new release, or a download drop. It is a light, metadata-only pass (no tarball download, no AI), so it is cheap to run on a schedule.

```bash
targate monitor            # approvals + direct dependencies
targate monitor --all      # the entire lockfile tree
```

The first run writes `.targate/monitor-baseline.json` and reports only always-true risks (a known-malicious record, a deprecation). Later runs diff against that baseline, then advance it (`--no-update` to peek without advancing). Exit code `2` means risk increased — wire it into a scheduled CI job to get alerted when a dependency you already approved turns risky.

**Baseline in CI.** `.targate/monitor-baseline.json` is gitignored by default (like the AI cache). For cross-run evolution detection on ephemeral CI runners, either commit the baseline or cache it between runs — it is stable, sorted JSON written for exactly that purpose. Without a persisted baseline, every CI run starts fresh and only the always-on checks fire.
