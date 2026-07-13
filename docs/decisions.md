# Decision policy

| Decision | Trigger (rules engine) |
|---|---|
| **BLOCK** | Known malicious record (OSV/OpenSSF); typosquat-like name + recent publish; a lifecycle command that fetches and executes remote code (`curl … \| bash`, `wget … \| sh`, `node -e`); install-time code reading `process.env` **and** calling the network; recent package with scripts and no repository |
| **REQUIRE APPROVAL** | Lifecycle scripts present; suspicious lifecycle command constructs (shell invocation, credential-file reads); name similar to a popular package; package created very recently; suspicious install-time findings |
| **ALLOW WITH WARNINGS** | Native code present; missing repository metadata; vulnerability advisories; large direct-dependency count; OSV lookup unavailable |
| **ALLOW** | No scripts, no records, consistent metadata |

With an AI provider configured, the model weighs the same signals contextually (e.g. "this postinstall just compiles native bindings"). The clamp is one-directional: **the AI can escalate but never de-escalate the deterministic verdict.** `clampDecision` compares both results through `DECISION_SEVERITY` and keeps the stricter one. A model that is jailbroken, prompt-injected, or simply wrong therefore cannot turn `allow_with_warnings`, `require_approval`, or `block` into a weaker result.

## Hard vs soft blocks

Not every BLOCK is equal. A **hard block** can never be overridden — by the AI, the allow list, or an approval:

- downloaded tarball bytes disagree with the reviewed lockfile, public mirror source, registry checksum, or historical artifact ledger;

- a known-malicious OSV/OpenSSF record, or
- a lifecycle command that **downloads and executes** remote code (`curl … | bash`, `wget … | sh`, `node -e`).

Every other block is **soft** (heuristic) — a strong signal a human may deliberately clear for a specific package. The common case is a native-binary installer whose install script reads `process.env` **and** hits the network to fetch its platform binary (esbuild, swc, sharp, playwright…): indistinguishable by pattern from credential exfiltration, but routinely legitimate. A soft block:

- can be **approved without installing** — `targate approve esbuild@0.27.3` reviews it and records a committable approval; a later `targate add` / `--yes` / CI run then passes on that exact version. This is the clean way to pre-clear a package. See [Team workflow](team-workflow.md#approving-a-package--targate-approve).
- can be **approved during an interactive install** — `targate add esbuild` (without `--yes`) prompts you to install it (with or without scripts) and records the same approval. It is **never** auto-installed with `--yes`.
- can be **pre-cleared** by adding the package to `allowKnownPackages` in the [team policy](team-workflow.md#team-policy--targatepolicy).

A hard block does none of that — it stays blocked, and the allow list explicitly reports that it was ignored.
