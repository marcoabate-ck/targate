import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

export const CONFIG_EXTENSIONS = [".ts", ".js", ".mjs", ".cjs", ".yaml", ".yml", ".json"] as const;

/** Config formats that are EXECUTED (via jiti) rather than parsed. */
export const EXEC_CONFIG_EXTENSIONS = [".ts", ".js", ".mjs", ".cjs"] as const;

/**
 * When TARGATE_NO_EXEC_CONFIG is set, .ts/.js/.mjs/.cjs policy and approvals
 * sources are skipped entirely — only declarative yaml/json is loaded. This
 * exists because executable config runs repo-controlled code on your machine
 * at targate startup (the same class of risk as jest/eslint JS configs, but
 * targate's whole point is "no code runs before you decide to trust it").
 * Set it before running targate inside a repo you do not yet trust.
 */
export function execConfigDisabled(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.TARGATE_NO_EXEC_CONFIG;
  return Boolean(value) && value !== "0" && value !== "false";
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
          `TARGATE_NO_EXEC_CONFIG is set — refusing to execute ${path.basename(file)}. Use a .yaml/.json config instead.`,
        );
      }
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
