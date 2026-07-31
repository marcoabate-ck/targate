import { describe, expect, it } from "vitest";
import { execEnv, sourceableEnvLines } from "../src/proxy-env.js";

const inputs = {
  registryUrl: "https://127.0.0.1:4873",
  caPath: "/home/u/.targate/proxy-tls/ca.pem",
  scopes: ["@acme", "@wts-paradigm"],
};

describe("sourceableEnvLines", () => {
  const lines = sourceableEnvLines(inputs);
  const text = lines.join("\n");

  it("exports the default registry for npm/pnpm and yarn-berry, plus the CA", () => {
    expect(text).toContain('export npm_config_registry="https://127.0.0.1:4873"');
    expect(text).toContain('export NPM_CONFIG_REGISTRY="https://127.0.0.1:4873"');
    expect(text).toContain('export YARN_NPM_REGISTRY_SERVER="https://127.0.0.1:4873"');
    expect(text).toContain('export NODE_EXTRA_CA_CERTS="/home/u/.targate/proxy-tls/ca.pem"');
  });

  it("contains ONLY shell-identifier-safe exports (no scoped @…:registry names)", () => {
    for (const line of lines.filter((l) => l.startsWith("export "))) {
      const name = line.slice("export ".length).split("=")[0];
      expect(name).toMatch(/^[A-Za-z_][A-Za-z0-9_]*$/); // a valid shell identifier
    }
    expect(text).not.toContain("@acme");
    expect(text).not.toContain("npm_config_@");
  });
});

describe("execEnv", () => {
  it("adds per-scope overrides that a sourced file cannot express", () => {
    const env = execEnv({ PATH: "/usr/bin" }, inputs);
    // base routing preserved
    expect(env.npm_config_registry).toBe("https://127.0.0.1:4873");
    expect(env.NODE_EXTRA_CA_CERTS).toBe("/home/u/.targate/proxy-tls/ca.pem");
    expect(env.PATH).toBe("/usr/bin"); // inherits the base env
    // npm/pnpm per-scope override — key with @ and : (invalid as a shell export)
    expect(env["npm_config_@acme:registry"]).toBe("https://127.0.0.1:4873");
    expect(env["npm_config_@wts-paradigm:registry"]).toBe("https://127.0.0.1:4873");
    // yarn-berry per-scope override — identifier-safe segment
    expect(env.YARN_NPM_SCOPES_ACME_NPM_REGISTRY_SERVER).toBe("https://127.0.0.1:4873");
    expect(env.YARN_NPM_SCOPES_WTS_PARADIGM_NPM_REGISTRY_SERVER).toBe("https://127.0.0.1:4873");
  });

  it("with no scopes, sets only the base routing", () => {
    const env = execEnv({}, { registryUrl: inputs.registryUrl, caPath: inputs.caPath });
    expect(env.npm_config_registry).toBe(inputs.registryUrl);
    expect(Object.keys(env).some((k) => k.includes("SCOPES"))).toBe(false);
  });
});
