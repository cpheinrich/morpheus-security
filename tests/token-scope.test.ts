import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { validateTargetScope } from "../scripts/token-scope.mjs";

const base = { version: 1, holds: [], requiredChecks: ["test"], incidentRepository: null };

describe("target token scope", () => {
  it("binds identity and a centrally approved incident repository", () => {
    expect(validateTargetScope(base, "cpheinrich/lakinacapital", "cpheinrich", "lakinacapital"))
      .toEqual({ target: "cpheinrich/lakinacapital", incidentRepository: null });
    expect(validateTargetScope(
      { ...base, incidentRepository: "cpheinrich/incidents" },
      "cpheinrich/morpheus", "cpheinrich", "morpheus", "cpheinrich/incidents",
    )).toEqual({ target: "cpheinrich/morpheus", incidentRepository: "cpheinrich/incidents" });
  });

  it("rejects missing explicit policy, identity drift, and unapproved incident scope", () => {
    expect(() => validateTargetScope({ version: 1 }, "cpheinrich/lakinacapital", "cpheinrich", "lakinacapital"))
      .toThrow("explicitly define");
    expect(() => validateTargetScope(base, "cpheinrich/lakinacapital", "other", "lakinacapital"))
      .toThrow("do not match");
    expect(() => validateTargetScope(
      { ...base, incidentRepository: "cpheinrich/incidents" },
      "cpheinrich/morpheus", "cpheinrich", "morpheus", "",
    )).toThrow("centrally approved");
    expect(() => validateTargetScope(
      { ...base, incidentRepository: "other/incidents" },
      "cpheinrich/morpheus", "cpheinrich", "morpheus", "other/incidents",
    )).toThrow("target repository owner");
  });
});
