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

**Approving several packages at once.** When a `--deep` run or `targate install` flags multiple packages, an interactive terminal offers an **arrow-key picker** (↑/↓ move, space select, `a` all, enter confirm) that records the selected approvals in one step — see [Transitive dependencies & full-tree install](transitive-and-install.md). Approvals from the picker are always `no-scripts`; use `targate approve <pkg> --allow-scripts` when a package genuinely needs its lifecycle scripts.

`--dry-run` is *not* how you approve: it is a pure preview (analyze + report, no prompt, no install, nothing recorded).

## Approval cache — `.targate/approvals.*`

Either path above records the approval (name@version, mode, who, when) in `.targate/approvals.json`. **Commit the file**: the rest of the team — and CI — treat that exact version as already reviewed. A new version requires a new approval.

Approvals can also be hand-curated in `.targate/approvals.{ts,js,mjs,cjs,yaml,yml,json}` — all existing files are read and **merged**, with the tool-managed `approvals.json` winning on conflicts (a fresh interactive approval must always take effect). Automatic recording only ever writes `approvals.json`; the other formats are read-only sources. For typed files:

```ts
// .targate/approvals.ts
import { defineApprovals } from "targate";

export default defineApprovals({
  "core-js@3.49.0": { mode: "no-scripts", approvedAt: "2026-07-07T00:00:00Z", approvedBy: "marco" },
});
```

## pnpm `approve-builds` integration

On pnpm projects, an interactive approval also updates `pnpm-workspace.yaml` through pnpm's native mechanism:

- approved **with** scripts → the package is added to `onlyBuiltDependencies`
- approved **without** scripts → added to `ignoredBuiltDependencies` (installed, scripts silently skipped, no interactive pnpm prompt)

## Lockfile diff preview

After every real install, `targate` prints which packages the install actually added to the lockfile (direct + transitive), so surprise transitive dependencies are visible immediately.

## Team policy — `targate.policy.*`

`targate policy init [--format yaml|json|js|ts]` scaffolds the policy file. Supported formats, first match wins: `targate.policy.{ts,js,mjs,cjs,yaml,yml,json}`. For the complete field-by-field schema, defaults, precedence, and validation rules, see the [Policy reference](policy-reference.md); this section is the workflow-level summary.

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

`.ts`/`.js` files are executed through [jiti](https://github.com/unjs/jiti) (default export; the type import is erased at runtime, so the file loads even where `targate` isn't installed as a dependency), and every format goes through the same schema validation. Because executable config runs repo-controlled code at targate startup, set **`TARGATE_NO_EXEC_CONFIG=1`** before running targate in a repo you don't yet trust — executable policy/approvals sources are then skipped with a warning and only `.yaml`/`.json` loads (see [Security model](security.md#scope-and-limitations)). The policy is applied **on top of** the AI/rules assessment and can only make decisions stricter — with one exception: `allowKnownPackages` pre-approves packages. Its power is bounded by the [hard/soft block](decisions.md#hard-vs-soft-blocks) distinction:

- a **hard block** (known-malicious record, or a `curl … | bash`-style download-and-execute) can never be overridden — the package stays blocked, and the report notes the allow list was ignored;
- a **soft/heuristic block** (e.g. an install script that reads env + hits the network, like esbuild) **is** cleared to `allow` by an allow-list entry — a deliberate, committed decision to trust that package. Prefer a version-pinned `.targate/approvals.json` entry (recorded automatically when you approve interactively) when you want to trust one exact version rather than all future ones.

## Monitoring risk over time — `targate monitor`

Approving a package vouches for it *at a point in time*. `targate monitor` re-checks the packages you already trust and reports what got worse since a stored baseline — a new vulnerability, a maintainer change, a deprecation, an archived repository, lost provenance, a suspicious new release, or a download drop. It is a light, metadata-only pass (no tarball download, no AI), so it is cheap to run on a schedule.

```bash
targate monitor            # approvals + direct dependencies
targate monitor --all      # the entire lockfile tree
```

The first run writes `.targate/monitor-baseline.json` and reports only always-true risks (a known-malicious record, a deprecation). Later runs diff against that baseline, then advance it (`--no-update` to peek without advancing). Exit code `2` means risk increased — wire it into a scheduled CI job to get alerted when a dependency you already approved turns risky.

**Baseline in CI.** `.targate/monitor-baseline.json` is gitignored by default (like the AI cache). For cross-run evolution detection on ephemeral CI runners, either commit the baseline or cache it between runs — it is stable, sorted JSON written for exactly that purpose. Without a persisted baseline, every CI run starts fresh and only the always-on checks fire.
