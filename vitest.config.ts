import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // `website/` is a separate pnpm project (Astro/Starlight) with its own
    // vitest and tsconfig (`extends: astro/tsconfigs/strict`, resolvable only
    // inside website/node_modules). Keep the root run out of it — the docs site
    // runs its own tests via `website/ pnpm test`.
    exclude: [...configDefaults.exclude, "website/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "text-summary"],
      // A TARGETED safety net, not a whole-repo vanity metric: enforce coverage
      // only on the highest-risk security primitives, where an untested branch is
      // a real supply-chain hazard (SSRF/redirect handling, signature checking).
      include: ["src/network.ts", "src/signing.ts"],
      thresholds: {
        // Set just under the measured baseline so CI fails on a REGRESSION, not
        // on normal drift. Baseline (v8): network 90/84/92/93, signing 81/62/100/82.
        "src/network.ts": { statements: 88, branches: 82, functions: 90, lines: 90 },
        "src/signing.ts": { statements: 78, branches: 58, functions: 95, lines: 80 },
      },
    },
  },
});
