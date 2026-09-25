import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { validateTargetScope } from "../scripts/token-scope.mjs";

const base = { version: 1, holds: [], requiredChecks: ["test"] };

describe("target token scope", () => {
  it("binds the target identity", () => {
    expect(validateTargetScope(base, "cpheinrich/lakinacapital", "cpheinrich", "lakinacapital"))
      .toEqual({ target: "cpheinrich/lakinacapital" });
  });

  it("rejects missing explicit policy, identity drift, and external incident routing", () => {
    expect(() => validateTargetScope({ version: 1 }, "cpheinrich/lakinacapital", "cpheinrich", "lakinacapital"))
      .toThrow("explicitly define");
    expect(() => validateTargetScope(base, "cpheinrich/lakinacapital", "other", "lakinacapital"))
      .toThrow("do not match");
    expect(() => validateTargetScope(
      { ...base, incidentRepository: "cpheinrich/incidents" },
      "cpheinrich/morpheus", "cpheinrich", "morpheus",
    )).toThrow("filed in the target repository");
  });
});
