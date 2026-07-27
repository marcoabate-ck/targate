# Transitive dependencies & full-tree install

`targate add <pkg>` gates a single new package. Two flows extend coverage to more of the tree.

## Transitive dependencies — `--deep`

```bash
targate add glob --deep --dry-run
```

> **Strongly recommended before you actually install.** A shallow `ALLOW` only vouches
> for the package you named — and a malicious dependency almost always hides **deeper**
> in the tree, not in the name you typed. Run `targate add <pkg> --deep` (or
> `targate install` for the whole project) before adding a dependency to a real project
> or in CI.
>
> **Why it isn't the default:** a deep run resolves and analyzes the *entire* transitive
> tree — more registry/tarball/OSV traffic and, with an AI provider configured, more
> model calls — so the common quick "is this package OK?" check stays fast and cheap by
> default. The cost is amortized by the [response cache](ai-cache.md) on repeated and
> shared dependencies, and bounded with `--concurrency`. A shallow run also prints a
> reminder that the transitive tree was not analyzed.

By default targate analyzes only the package you named. With `--deep` it asks the project's actual package manager (npm, pnpm, or Yarn) to produce a staged manifest and lockfile with lifecycle scripts disabled. It analyzes **every unique `name@version` from that exact lockfile**, including the lockfile's tarball URL/integrity where the format exposes them, applies the reviewed files only after the gate passes, and installs in frozen/immutable mode. Both the lockfile and canonical artifact-list fingerprints must match the reviewed plan, so installation cannot silently resolve a different version or tarball identity.

The final decision is the **strictest verdict across the whole tree**: a blocked transitive dependency blocks the install exactly like a blocked root; a `require_approval` anywhere in the tree escalates the run. Flagged packages are listed in the reasons (`--json` includes the full per-package results under `deep`).

Cost: a deep run downloads and analyzes N tarballs. To keep a cold run fast, the whole tree is processed in parallel (`--concurrency`, default 16), OSV is queried for the entire tree in **one batched request** instead of one per package, and — with an AI provider configured — several packages are assessed per model request (batched; see [AI providers](ai-providers.md#batched-assessment-on-large-trees)). The [AI response cache](ai-cache.md) makes repeated and shared dependencies cheaper still: full-tree cache hits are loaded in one read and fresh batch results land in one atomic write. If npm cannot resolve the tree, the run fails loudly rather than silently degrading to top-level-only coverage.

Tuning flags (also apply to `targate install`):

- `--concurrency <n>` — how many packages are analyzed in parallel (default 16). Lower it if a cloud AI provider rate-limits you.
- `--no-ai-batch` — assess each package in its own AI request instead of batching several per request. Stricter per-package isolation (see the security note in [AI providers](ai-providers.md#batched-assessment-on-large-trees)) at the cost of speed and tokens.

While the tree is being analyzed, an interactive terminal shows a **live progress line** — phase (downloading & scanning → AI risk assessment), done/total counters, elapsed time and an ETA; non-interactive output (CI logs) gets plain milestone lines instead, and `--json` stays silent.

**Interactive triage.** When the walk finds packages that need a decision (`require_approval` or a [soft block](decisions.md#hard-vs-soft-blocks)), an interactive run offers an **arrow-key triage picker** instead of pointing you at `targate approve` once per package: move with ↑/↓, and for the highlighted package press `a` to **approve**, `d` to **deny**, or leave it to **skip** (decide later); `s` toggles lifecycle **scripts** on an approved item; enter confirms, `q` cancels. A **live detail panel** shows the highlighted package's verdict — decision, risk, summary, reasons and recommended action — so the choice is informed without leaving the picker. Approvals are recorded to `.targate/approvals.json` (as `no-scripts` unless you pressed `s`); denials are recorded to `.targate/denials.json` so that version is **never re-offered** and the rejection travels with the repo. Approvals and denials are mutually exclusive per `name@version` — recording one clears the other. Hard blocks are listed but can be neither approved nor denied. The picker runs in **`--dry-run` too** (it records the committable approvals/denials but still installs nothing, exactly like `targate approve`); it never appears with `--yes`, `--json`, or in CI. The same picker appears when `targate install` refuses a tree: approve the flagged packages and the install continues immediately if nothing unresolved remains.

`--deep` also works with `targate approve`: a hard block anywhere in the tree makes the whole package un-approvable.

## Full-tree install — `targate install`

`targate add` gates a single new package; `targate ci` gates the deps a change touches. Neither covers the highest-exposure moment: a plain `pnpm install` / `npm install` on a fresh clone or in CI, which restores the **entire** tree and runs **every** package's lifecycle scripts at once. `targate install` is the gate for that.

```bash
targate install                 # vet the whole tree, then install (scripts disabled)
targate install --dry-run       # vet only; print the recommended install command
targate install --update-lockfile   # explicitly re-resolve, review, then apply a lock update
targate install --allow-scripts     # run scripts only if no approval denies them
```

What it does:

1. **Builds an immutable install plan.** A committed lockfile is reviewed as-is. `--update-lockfile` asks the project's actual package manager to produce a staged update with scripts disabled; the working tree is untouched until review passes. Without a lockfile, this explicit flag is required.
2. **Vets every unique `name@version`** through the same pipeline as `--deep` (quarantine, OSV, signals, AI/rules, team policy), a few at a time, reusing the [AI response cache](ai-cache.md).
3. **Gates the install.** If any package is `block`, or `require_approval` and not in the committed `.targate/approvals.json`, targate **refuses** and exits `2`. Otherwise it applies the reviewed staged files when needed and runs npm `ci` or pnpm/Yarn with `--frozen-lockfile`.
4. **Records installed identities.** After a successful real install, targate writes the observed SHA-512 values to `.targate/artifacts.json`. Commit this ledger to detect same-version replacement across machines and CI; targate refuses to overwrite a conflicting historical digest.
4. **Scripts off by default.** The actual install runs with `--ignore-scripts`. `--allow-scripts` can enable them only when the reviewed tree contains no binding `no-scripts` approval; one such approval keeps scripts disabled globally. On pnpm, picker approvals also update `ignoredBuiltDependencies` (see [Team workflow](team-workflow.md#pnpm-approve-builds-integration)).

5. **Verifies the result.** The final lockfile SHA-256 fingerprint must equal the reviewed plan. Changes during review or installation fail with exit `1` and require a new review.

Exit codes: `0` vetted (and installed, unless `--dry-run`), `2` refused (blocked/unapproved package in the tree), `1` error or lockfile drift. `--json` includes `planFingerprint` and the final `install` outcome.

**Caveats.** A first cold scan of a large tree is heavy (N tarballs + OSV lookups; the cache amortizes re-runs). Targate cannot retroactively un-run scripts for packages already present in `node_modules`.
