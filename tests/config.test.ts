import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { validateSecurityConfig } from "../scripts/config.mjs";

const base = { version: 1, holds: [], requiredChecks: ["node / check"] };

describe("repository compatibility opt-in", () => {
  it("defaults to disabled and accepts an explicit boolean", () => {
    expect(validateSecurityConfig(base).importOnlyCompatibility).toBe(false);
    expect(validateSecurityConfig({ ...base, importOnlyCompatibility: true }).importOnlyCompatibility).toBe(true);
    expect(validateSecurityConfig({ ...base, importOnlyCompatibility: false }).importOnlyCompatibility).toBe(false);
  });

  it("rejects an ambiguous option or malformed existing gates", () => {
    expect(() => validateSecurityConfig({ ...base, importOnlyCompatibility: "true" })).toThrow("boolean");
    expect(() => validateSecurityConfig({ ...base, requiredChecks: [""] })).toThrow("valid holds/requiredChecks");
    expect(() => validateSecurityConfig({ ...base, incidentRepository: "other/repo" })).toThrow("valid holds/requiredChecks");
  });
});
