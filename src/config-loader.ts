import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

export const CONFIG_EXTENSIONS = [".ts", ".js", ".mjs", ".cjs", ".yaml", ".yml", ".json"] as const;

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
