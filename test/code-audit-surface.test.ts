import { describe, expect, it } from "vitest";
import {
  POLICY_PRESETS,
  PolicyError,
  resolveCodeAuditScope,
  validatePolicyObject,
} from "../src/policy.js";

describe("resolveCodeAuditScope", () => {
  it("defaults to off with no flag and no policy", () => {
    expect(resolveCodeAuditScope(false, undefined)).toBe("off");
  });

  it("honors the policy scope when the flag is absent", () => {
    expect(resolveCodeAuditScope(false, "direct")).toBe("direct");
    expect(resolveCodeAuditScope(false, "off")).toBe("off");
  });

  it("the flag turns it on at least to flagged", () => {
    expect(resolveCodeAuditScope(true, undefined)).toBe("flagged");
    expect(resolveCodeAuditScope(true, "off")).toBe("flagged");
  });

  it("the flag keeps a richer policy scope", () => {
    expect(resolveCodeAuditScope(true, "all")).toBe("all");
    expect(resolveCodeAuditScope(true, "direct")).toBe("direct");
  });
});

describe("policy codeAudit validation", () => {
  const withCodeAudit = (codeAudit: unknown) => ({ dependencyPolicy: { codeAudit } });

  it("accepts the four valid scopes", () => {
    for (const scope of ["off", "flagged", "direct", "all"]) {
      expect(validatePolicyObject(withCodeAudit(scope)).dependencyPolicy.codeAudit).toBe(scope);
    }
  });

  it("rejects an invalid scope", () => {
    expect(() => validatePolicyObject(withCodeAudit("sometimes"))).toThrow(PolicyError);
    expect(() => validatePolicyObject(withCodeAudit(true))).toThrow(/codeAudit/);
  });

  it("accepts the new audit resource limits", () => {
    const doc = { dependencyPolicy: {}, resourceLimits: { maxAuditFiles: 5, maxAuditBytes: 1000 } };
    expect(validatePolicyObject(doc).resourceLimits).toMatchObject({ maxAuditFiles: 5, maxAuditBytes: 1000 });
  });
});

describe("policy presets", () => {
  it("enable flagged audit under strict and ai-agent, off under ci, unset under default", () => {
    expect(POLICY_PRESETS.strict.policy.dependencyPolicy.codeAudit).toBe("flagged");
    expect(POLICY_PRESETS["ai-agent"].policy.dependencyPolicy.codeAudit).toBe("flagged");
    expect(POLICY_PRESETS.ci.policy.dependencyPolicy.codeAudit).toBe("off");
    expect(POLICY_PRESETS.default.policy.dependencyPolicy.codeAudit).toBeUndefined();
  });
});
