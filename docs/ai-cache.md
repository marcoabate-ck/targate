# AI response cache

Interactive runs cache the AI's assessment so re-reviewing the same dependency (re-runs, `--deep` trees sharing packages across projects) doesn't pay for a new completion. The cache key is the **full evaluation context**:

```
provider / model / reasoning flag / name@version / sha256(signals)
```

so the same lib checked with a different provider or model is always a fresh call. `signals` contains the canonical SHA-512 digest of the exact tarball, so **different bytes are always a cache miss even when both versions produce identical static findings**. A stale "allow" cannot survive a replaced artifact. Two further guarantees:

- **Entries are runtime-validated.** Invalid timestamps or incomplete/unknown assessment shapes are ignored with a warning containing the cache file and key; persisted JSON is never trusted through a TypeScript cast.
- **Cached answers are re-clamped on read.** The deterministic BLOCK floor is enforced at decision time, never trusted from disk — a hand-edited or poisoned cache entry cannot bypass it.
- **CI never uses the cache.** `targate ci` strips cache settings unconditionally; a CI verdict is always a fresh assessment.
- **Large trees use bulk cache I/O.** Batched analysis loads all candidate keys with one file read and commits fresh batch results with one atomic write. A fully warm tree therefore makes zero model calls without rereading the cache once per package.

Only successful AI responses are cached — rules-engine fallbacks are free to recompute and errors are never remembered. Configured through the `aiCache` section of the [team policy](team-workflow.md#team-policy--targatepolicy):

```yaml
# targate.policy.yaml
aiCache:
  enabled: true      # master switch (default: true)
  scope: user        # user: ~/.targate/ai-cache.json (default) | project: <repo>/.targate/ai-cache.json
  ttlHours: 24       # entries older than this are ignored and pruned (default: 24)
  exclude: []        # package names never cached (e.g. internal libs under review)
```

With `scope: project` the cache lives in the repo's `.targate/` directory — add `.targate/ai-cache.json` to `.gitignore` unless you deliberately want to share it.

## Invalidating the cache

Most invalidation is automatic:

- **TTL** — entries older than `ttlHours` (default 24) are ignored and pruned on the next write.
- **Evidence change** — because the key includes `sha256(signals)` (including `signals.artifact.digest`) and `provider/model/reasoning`, a new OSV record, any tarball-byte change, or a different model is a **cache miss by construction**.

To force it explicitly:

- **`--no-cache`** on `targate add` / `approve` / `install` — ignore any cached assessment for this run and recompute. Fresh results still refresh the cache, so the next run is fast again.

  ```bash
  targate add react-native-mmkv --no-cache        # re-review, ignoring the cache
  ```

- **`targate cache clear`** — delete the cache file. Use `--scope user|project` (defaults to the policy's scope); add `--json` for machine-readable output.

  ```bash
  targate cache info                 # where the cache lives + how many entries
  targate cache clear                # delete it (active scope)
  targate cache clear --scope project
  ```

- **Disable entirely** via the policy: `aiCache.enabled: false`, or exclude specific packages with `aiCache.exclude: [<name>]`. CI never reads the cache regardless.
