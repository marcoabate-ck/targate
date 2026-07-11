# Transitive dependencies & full-tree install

`targate add <pkg>` gates a single new package. Two flows extend coverage to more of the tree.

## Transitive dependencies — `--deep`

```bash
targate add glob --deep --dry-run
```

By default targate analyzes only the package you named. With `--deep` it asks the project's actual package manager (npm, pnpm, or Yarn) to produce a staged manifest and lockfile with lifecycle scripts disabled. It analyzes **every unique `name@version` from that exact lockfile**, applies the reviewed files only after the gate passes, and installs in frozen/immutable mode. The final lockfile fingerprint must match the reviewed plan, so installation cannot silently resolve a different transitive version.

The final decision is the **strictest verdict across the whole tree**: a blocked transitive dependency blocks the install exactly like a blocked root; a `require_approval` anywhere in the tree escalates the run. Flagged packages are listed in the reasons (`--json` includes the full per-package results under `deep`).

Cost: a deep run downloads and analyzes N tarballs. To keep a cold run fast, the whole tree is processed in parallel (`--concurrency`, default 16), OSV is queried for the entire tree in **one batched request** instead of one per package, and — with an AI provider configured — several packages are assessed per model request (batched; see [AI providers](ai-providers.md#batched-assessment-on-large-trees)). The [AI response cache](ai-cache.md) makes repeated and shared dependencies cheaper still. If npm cannot resolve the tree, the run fails loudly rather than silently degrading to top-level-only coverage.

Tuning flags (also apply to `targate install`):

- `--concurrency <n>` — how many packages are analyzed in parallel (default 16). Lower it if a cloud AI provider rate-limits you.
- `--no-ai-batch` — assess each package in its own AI request instead of batching several per request. Stricter per-package isolation (see the security note in [AI providers](ai-providers.md#batched-assessment-on-large-trees)) at the cost of speed and tokens.

While the tree is being analyzed, an interactive terminal shows a **live progress line** — phase (downloading & scanning → AI risk assessment), done/total counters, elapsed time and an ETA; non-interactive output (CI logs) gets plain milestone lines instead, and `--json` stays silent.

**Interactive approval.** When the walk finds transitive dependencies that need approval (`require_approval` or a [soft block](decisions.md#hard-vs-soft-blocks)), an interactive run offers an **arrow-key picker**: move with ↑/↓, toggle with space (`a` = all), confirm with enter. Selected packages are recorded to `.targate/approvals.json` as `no-scripts` on the spot — no need to run `targate approve` once per package. Hard blocks are listed but cannot be selected. The picker never appears with `--yes`, `--json`, `--dry-run`, or in CI. The same picker appears when `targate install` refuses a tree: approve the flagged packages and the install continues immediately if nothing unresolved remains.

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
4. **Scripts off by default.** The actual install runs with `--ignore-scripts`. `--allow-scripts` can enable them only when the reviewed tree contains no binding `no-scripts` approval; one such approval keeps scripts disabled globally. On pnpm, picker approvals also update `ignoredBuiltDependencies` (see [Team workflow](team-workflow.md#pnpm-approve-builds-integration)).

5. **Verifies the result.** The final lockfile SHA-256 fingerprint must equal the reviewed plan. Changes during review or installation fail with exit `1` and require a new review.

Exit codes: `0` vetted (and installed, unless `--dry-run`), `2` refused (blocked/unapproved package in the tree), `1` error or lockfile drift. `--json` includes `planFingerprint` and the final `install` outcome.

**Caveats.** A first cold scan of a large tree is heavy (N tarballs + OSV lookups; the cache amortizes re-runs). Targate cannot retroactively un-run scripts for packages already present in `node_modules`.
