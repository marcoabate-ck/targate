# AI response cache

Interactive runs cache the AI's assessment so re-reviewing the same dependency (re-runs, `--deep` trees sharing packages across projects) doesn't pay for a new completion. The cache key is the **full evaluation context**:

```
provider / model / reasoning flag / name@version / sha256(signals)
```

so the same lib checked with a different provider or model is always a fresh call, and any change in the deterministic evidence (a new OSV record, different tarball findings) is a cache miss by construction — a stale "allow" cannot survive new evidence. Two further guarantees:

- **Cached answers are re-clamped on read.** The deterministic BLOCK floor is enforced at decision time, never trusted from disk — a hand-edited or poisoned cache entry cannot bypass it.
- **CI never uses the cache.** `targate ci` strips cache settings unconditionally; a CI verdict is always a fresh assessment.

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
