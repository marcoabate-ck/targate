import { readFile } from "node:fs/promises";
import path from "node:path";
import { parse as parseYaml } from "yaml";

/**
 * Supported config formats. All are DECLARATIVE and PARSED, never executed:
 * repository-controlled config is untrusted, so targate does not run it.
 * (Executable `.ts`/`.js`/`.mjs`/`.cjs` config was removed — see the changelog.)
 */
export const CONFIG_EXTENSIONS = [".yaml", ".yml", ".json"] as const;

/**
 * Load a declarative config file by extension:
 * - .json         -> JSON.parse
 * - .yaml / .yml  -> yaml
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
    default:
      throw new Error(
        `Unsupported config format: ${file} — targate reads only declarative .yaml/.yml/.json.`,
      );
  }
}
