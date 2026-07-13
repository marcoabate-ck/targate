import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

export const CONFIG_EXTENSIONS = [".ts", ".js", ".mjs", ".cjs", ".yaml", ".yml", ".json"] as const;

/** Config formats that are EXECUTED (via jiti) rather than parsed. */
export const EXEC_CONFIG_EXTENSIONS = [".ts", ".js", ".mjs", ".cjs"] as const;

/** Executable repository configuration is opt-in. The legacy NO variable is
 * retained as a fail-safe override during migration. */
export function execConfigDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const denied = env.TARGATE_NO_EXEC_CONFIG;
  if (denied && denied !== "0" && denied !== "false") return true;
  return env.TARGATE_ALLOW_EXEC_CONFIG !== "1";
}

/** True when the file's extension means loading it would execute code. */
export function isExecConfigFile(file: string): boolean {
  return (EXEC_CONFIG_EXTENSIONS as readonly string[]).includes(path.extname(file));
}

/**
 * Load a config file by extension:
 * - .json          -> JSON.parse
 * - .yaml / .yml   -> yaml
 * - .ts / .js / .mjs / .cjs -> executed via jiti (TypeScript supported,
 *   `export default` or module.exports)
 *
 * Returns the parsed value; the caller is responsible for validation.
 */
export async function loadConfigFile(file: string): Promise<unknown> {
  const ext = path.extname(file);

  switch (ext) {
    case ".json":
      return JSON.parse(await readFile(file, "utf8"));
    case ".yaml":
    case ".yml":
      return parseYaml(await readFile(file, "utf8"));
    case ".ts":
    case ".js":
    case ".mjs":
    case ".cjs": {
      // Defense in depth: even if a call site forgets to filter candidates,
      // executable config never runs while the opt-out is set.
      if (execConfigDisabled()) {
        throw new Error(
          `refusing to execute ${path.basename(file)} by default. Use declarative YAML/JSON, or explicitly set TARGATE_ALLOW_EXEC_CONFIG=1.`,
        );
      }
      console.error(
        `[targate] WARNING: executing repository-controlled config ${file} because TARGATE_ALLOW_EXEC_CONFIG=1. Prefer YAML/JSON.`,
      );
      const { createJiti } = await import("jiti");
      const jiti = createJiti(pathToFileURL(file).href, {
        // Config files change between runs — never serve a stale cached copy.
        moduleCache: false,
      });
      return jiti.import(file, { default: true });
    }
    default:
      throw new Error(`Unsupported config format: ${file}`);
  }
}
