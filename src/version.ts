import { createRequire } from "node:module";

/**
 * The running targate version.
 *
 * Normally read from package.json at load time — the single source of truth,
 * working from both src/ (tsx) and dist/ since both sit one level below it.
 *
 * Standalone binaries (bun --compile) have no package.json on disk, so the
 * release build injects the version via `--define process.env.TARGATE_VERSION`,
 * which is substituted at compile time. When that is unset (the normal npm/tsx
 * path) the package.json read is used, so behaviour is unchanged off the binary.
 */
function resolveVersion(): string {
  const injected = process.env.TARGATE_VERSION;
  if (injected && injected.length > 0) return injected;
  return createRequire(import.meta.url)("../package.json").version as string;
}

export const TARGATE_VERSION: string = resolveVersion();
