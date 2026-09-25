import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { tokenRepositories } from "../scripts/token-scope.mjs";

describe("installation token scope", () => {
  it("limits a normal run to the target repository", () => {
    expect(tokenRepositories(
      { version: 1, holds: [], incidentRepository: null },
      "cpheinrich/morpheus",
    )).toEqual(["morpheus"]);
  });

  it("includes a configured incident repository under the same owner", () => {
    expect(tokenRepositories(
      { version: 1, holds: [], incidentRepository: "cpheinrich/security-incidents" },
      "cpheinrich/morpheus",
    )).toEqual(["morpheus", "security-incidents"]);
  });

  it("rejects a cross-installation incident repository", () => {
    expect(() => tokenRepositories(
      { version: 1, holds: [], incidentRepository: "darwin-health/security-incidents" },
      "cpheinrich/morpheus",
    )).toThrow("under the target repository owner");
  });

  it("rejects control characters before writing the workflow output", () => {
    expect(() => tokenRepositories(
      { version: 1, holds: [], incidentRepository: "cpheinrich/incidents\nsecret-repo" },
      "cpheinrich/morpheus",
    )).toThrow("under the target repository owner");
    expect(() => tokenRepositories(
      { version: 1, holds: [], incidentRepository: null },
      "cpheinrich/morpheus\r\nextra",
    )).toThrow("safe GitHub owner/name");
  });
});
