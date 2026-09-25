import { describe, expect, it } from "vitest";
import {
  compareVersions,
  findingsFromOsvJson,
  hasSecurityMarker,
  isSecurityDependencyOnly,
  smallestFixedVersion,
} from "../src/policy.js";

const scan = {
  results: [{
    source: { path: "apps/web/package-lock.json", type: "lockfile" },
    packages: [{
      package: { ecosystem: "npm", name: "uuid", version: "9.0.1" },
      vulnerabilities: [{
        id: "GHSA-example",
        aliases: ["CVE-example"],
        affected: [{ ranges: [{ type: "SEMVER", events: [
          { introduced: "0" }, { fixed: "11.1.1" },
          { introduced: "12.0.0" }, { fixed: "12.0.1" },
        ] }] }],
      }],
    }],
  }],
};

describe("security remediation policy", () => {
  it("selects the smallest fixed version above the installed version", () => {
    const vulnerability = scan.results[0]!.packages[0]!.vulnerabilities[0]!;
    expect(smallestFixedVersion(vulnerability, "9.0.1")).toBe("11.1.1");
    expect(compareVersions("11.1.1", "9.0.1")).toBeGreaterThan(0);
  });

  it("normalizes active OSV findings and keeps aliases", () => {
    expect(findingsFromOsvJson(scan)).toEqual([expect.objectContaining({
      ecosystem: "npm",
      dependency: "uuid",
      advisory: "GHSA-example",
      aliases: ["CVE-example", "GHSA-example"],
      fixedVersion: "11.1.1",
      sourcePath: "apps/web/package-lock.json",
      malicious: false,
    })]);
  });

  it("drops withdrawn advisories and prioritizes MAL findings", () => {
    const malicious = structuredClone(scan) as unknown as {
      results: Array<{ packages: Array<{ vulnerabilities: Array<{
        id: string;
        aliases: string[];
        affected: unknown[];
        withdrawn?: string;
      }> }> }>;
    };
    malicious.results[0]!.packages[0]!.vulnerabilities.unshift({
      id: "MAL-2026-1", aliases: [], affected: [],
    });
    malicious.results[0]!.packages[0]!.vulnerabilities.push({
      id: "GHSA-withdrawn", aliases: [], affected: [], withdrawn: "2026-01-01",
    });
    const findings = findingsFromOsvJson(malicious);
    expect(findings.map((finding) => finding.advisory)).toEqual(["MAL-2026-1", "GHSA-example"]);
  });

  it("requires the exact marker and dependency-only paths", () => {
    expect(hasSecurityMarker("<!-- morpheus-security-update -->")).toBe(true);
    expect(isSecurityDependencyOnly(["apps/web/package.json", "apps/web/package-lock.json"])).toBe(true);
    expect(isSecurityDependencyOnly(["pnpm-workspace.yaml", "pnpm-lock.yaml"])).toBe(true);
    expect(isSecurityDependencyOnly(["apps/web/package-lock.json", ".github/workflows/ci.yml"])).toBe(false);
  });

  it("fails closed on malformed scanner output", () => {
    expect(() => findingsFromOsvJson({})).toThrow("results array");
    expect(() => findingsFromOsvJson({ results: [{ source: {}, packages: [] }] })).toThrow("lockfile");
  });
});
