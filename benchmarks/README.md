# Performance benchmarks

Run the repeatable synthetic tree benchmark with:

```bash
pnpm benchmark
pnpm benchmark -- --json
```

It measures 10, 100, 500, and 1000-package/file fixtures. Every row records cold and warm elapsed time, peak RSS, compressed tarball bytes, provider calls, and warm-cache hit rate. The fake provider performs no network I/O, so results isolate targate's indexing, batching, and persistent-cache overhead.

The 1000-package targets intentionally leave CI headroom: cold under 20 seconds, warm under 5 seconds, peak RSS under 1 GiB, no more than one model call per eight cold misses, and zero model calls with a 100% warm-cache hit rate. The command exits non-zero when a target regresses.
