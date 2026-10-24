import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { compatibilityMappingFor, validateCompatibilityMappings } from "../scripts/compatibility-mappings.mjs";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { nextCompatibilityCandidate, verifiedIndependentReview } from "../scripts/security-remediation.mjs";

const mapping = { advisory: "GHSA-1234-5678-9012", dependency: "gray-matter", replacement: "@11ty/gray-matter", version: "3.0.0" };
const finding = { ecosystem: "npm", dependency: "gray-matter", advisory: mapping.advisory,
  aliases: [mapping.advisory], fixedVersion: null, malicious: false, sourcePath: "pnpm-lock.yaml" };

describe("reviewed compatibility mappings", () => {
  it("requires exact package and advisory identity with no duplicate mapping", () => {
    expect(validateCompatibilityMappings([mapping])).toEqual([mapping]);
    expect(compatibilityMappingFor(finding, [mapping])).toEqual(mapping);
    expect(compatibilityMappingFor({ ...finding, aliases: ["GHSA-other"] }, [mapping])).toBeNull();
    expect(() => validateCompatibilityMappings([mapping, mapping])).toThrow("Duplicate");
    expect(() => validateCompatibilityMappings([{ ...mapping, version: "latest" }])).toThrow("exact version");
    expect(() => validateCompatibilityMappings([{ ...mapping, replacement: "https://evil.example" }])).toThrow("registry packages");
  });

  it("selects only opted-in, unpatched, unheld, non-conflicting npm findings", () => {
    expect(nextCompatibilityCandidate([finding], [mapping], { holds: [], importOnlyCompatibility: true }, []))
      .toEqual({ finding, mapping });
    expect(nextCompatibilityCandidate([finding], [mapping], { holds: [], importOnlyCompatibility: false }, []))
      .toBeNull();
    expect(nextCompatibilityCandidate([finding], [mapping], { holds: [{ dependency: "gray-matter" }], importOnlyCompatibility: true }, []))
      .toBeNull();
    expect(nextCompatibilityCandidate([{ ...finding, fixedVersion: "4.0.0" }], [mapping], { holds: [], importOnlyCompatibility: true }, []))
      .toBeNull();
    expect(nextCompatibilityCandidate([finding], [mapping], { holds: [], importOnlyCompatibility: true },
      [{ body: "Lockfile: `pnpm-lock.yaml`" }])).toBeNull();
  });
});

describe("independent Manager App review receipt", () => {
  const repo = "cpheinrich/morpheus";
  const head = "a".repeat(40);
  const body = `Reviewed\n<!-- morpheus-security-review ${JSON.stringify({ version: 1, repository: repo, pr: 42, headSha: head, verdict: "clear" })} -->`;
  const comment = { user: { login: "morpheus-gh-manager[bot]" },
    performed_via_github_app: { slug: "morpheus-gh-manager" }, body };

  it("accepts only a distinct App's clear receipt for this PR and exact head", () => {
    expect(verifiedIndependentReview([comment], repo, 42, head)).toEqual(expect.objectContaining({ headSha: head }));
    expect(verifiedIndependentReview([comment], repo, 42, "b".repeat(40))).toBeNull();
    expect(verifiedIndependentReview([comment], repo, 43, head)).toBeNull();
    expect(verifiedIndependentReview([{ ...comment, performed_via_github_app: null }], repo, 42, head)).toBeNull();
    expect(verifiedIndependentReview([{ ...comment, user: { login: "cpheinrich" } }], repo, 42, head)).toBeNull();
    expect(verifiedIndependentReview([{ ...comment, body: body.replace('"clear"', '"findings"') }], repo, 42, head)).toBeNull();
    expect(verifiedIndependentReview([comment, { ...comment, body: body.replace('"clear"', '"findings"') }], repo, 42, head)).toBeNull();
    expect(verifiedIndependentReview([{ ...comment, body: body.replace('"clear"', '"findings"') }, comment], repo, 42, head))
      .toEqual(expect.objectContaining({ headSha: head }));
  });
});
