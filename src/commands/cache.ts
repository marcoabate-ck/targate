import { cacheStats, clearCache, resolveCacheSettings, type AiCacheSettings } from "../ai-cache.js";
import { loadPolicy } from "../policy.js";
import { bold, dim, green, red } from "../report.js";

export interface CacheCommandOptions {
  /** "clear" | "info". */
  action?: string;
  /** Override the cache scope; defaults to the team policy's (or "user"). */
  scope?: string;
  json: boolean;
}

/**
 * `targate cache clear|info` — manage the AI response cache. The cache also
 * expires by TTL and invalidates automatically when a package's signals
 * change; this command is the explicit escape hatch.
 */
export async function cacheCommand(opts: CacheCommandOptions): Promise<number> {
  if (opts.action !== "clear" && opts.action !== "info") {
    console.error(red("Usage: targate cache <clear|info> [--scope user|project]"));
    return 1;
  }
  if (opts.scope && opts.scope !== "user" && opts.scope !== "project") {
    console.error(red(`Unknown --scope: ${opts.scope}. Valid options: user, project`));
    return 1;
  }

  const policy = await loadPolicy();
  const base = resolveCacheSettings(policy?.policy.aiCache);
  const settings: AiCacheSettings = {
    ...base,
    scope: (opts.scope as "user" | "project" | undefined) ?? base.scope,
  };

  if (opts.action === "clear") {
    const { path: file, existed } = await clearCache(settings);
    if (opts.json) {
      console.log(JSON.stringify({ action: "clear", scope: settings.scope, path: file, cleared: existed }, null, 2));
    } else if (existed) {
      console.log(green(`Cleared the AI response cache (${settings.scope}): ${file}`));
    } else {
      console.log(dim(`No AI response cache to clear at ${file}`));
    }
    return 0;
  }

  // info
  const stats = await cacheStats(settings);
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          action: "info",
          scope: settings.scope,
          enabled: settings.enabled,
          ttlHours: settings.ttlHours,
          exclude: settings.exclude,
          ...stats,
        },
        null,
        2,
      ),
    );
    return 0;
  }
  console.log(bold("AI response cache"));
  console.log(dim(`  scope:    ${settings.scope}`));
  console.log(dim(`  path:     ${stats.path}`));
  console.log(dim(`  enabled:  ${settings.enabled}`));
  console.log(dim(`  ttlHours: ${settings.ttlHours}`));
  console.log(
    dim(
      `  entries:  ${stats.exists ? `${stats.fresh} fresh / ${stats.total} total` : "(no cache file yet)"}`,
    ),
  );
  console.log(dim("\nClear it with `targate cache clear`, or force a fresh run with `--no-cache`."));
  return 0;
}
