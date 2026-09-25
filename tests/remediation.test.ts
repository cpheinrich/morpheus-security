import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertOfficialNpmArtifacts,
  assertOfficialPnpmArtifacts,
  assertOfficialUvArtifacts,
  combineFindings,
  updatePnpm,
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
} from "../scripts/security-remediation.mjs";

const osv = {
  ecosystem: "npm", dependency: "uuid", version: "9.0.1", advisory: "GHSA-one",
  aliases: ["CVE-one", "GHSA-one"], fixedVersion: "11.1.1", sourcePath: "package-lock.json",
  malicious: false, withdrawn: false,
};

describe("security remediation inputs", () => {
  it("deduplicates GitHub alerts against OSV aliases", () => {
    const combined = combineFindings([structuredClone(osv)], [{
      ...structuredClone(osv), advisory: "GHSA-one", aliases: ["CVE-one", "GHSA-one"],
    }]);
    expect(combined).toHaveLength(1);
  });

  it("keeps an independent GitHub-reviewed advisory OSV did not return", () => {
    const combined = combineFindings([structuredClone(osv)], [{
      ...structuredClone(osv), dependency: "other", advisory: "GHSA-two", aliases: ["GHSA-two"],
    }]);
    expect(combined.map((finding: { dependency: string }) => finding.dependency).sort()).toEqual(["other", "uuid"]);
  });

  it("rejects changed npm entries without registry provenance", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-npm-"));
    const lockfile = join(dir, "package-lock.json");
    const before = JSON.stringify({ packages: {} });
    writeFileSync(lockfile, JSON.stringify({ packages: {
      "node_modules/unsafe": { version: "1.0.0" },
    } }));
    expect(() => assertOfficialNpmArtifacts(lockfile, before)).toThrow("without a registry URL");
  });

  it("requires changed uv artifacts to come from hashed PyPI releases", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-uv-"));
    const lockfile = join(dir, "uv.lock");
    const before = "version = 1\nrevision = 3\n";
    writeFileSync(lockfile, `${before}\n[[package]]\nname = "unsafe"\nversion = "1.0.0"\nsource = { git = "https://example.com/unsafe" }\n`);
    expect(() => assertOfficialUvArtifacts(lockfile, before)).toThrow("non-PyPI source");

    writeFileSync(lockfile, `${before}\n[[package]]\nname = "safe"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\n`);
    expect(() => assertOfficialUvArtifacts(lockfile, before)).toThrow("complete artifact metadata");

    writeFileSync(lockfile, `${readFileSync(lockfile, "utf8")}sdist = { url = "https://files.pythonhosted.org/safe.tar.gz" }\n`);
    expect(() => assertOfficialUvArtifacts(lockfile, before)).toThrow("without a sha256 hash");

    const hash = "a".repeat(64);
    writeFileSync(lockfile, `${before}\n[[package]]\nname = "safe"\nversion = "1.0.0"\nsource = { registry = "https://pypi.org/simple" }\nsdist = { url = "https://files.pythonhosted.org/safe.tar.gz", hash = "sha256:${hash}" }\n`);
    expect(() => assertOfficialUvArtifacts(lockfile, before)).not.toThrow();

    writeFileSync(lockfile, `${readFileSync(lockfile, "utf8")}wheels = [\n  { url = "https://evil.example/safe.whl" },\n]\n`);
    expect(() => assertOfficialUvArtifacts(lockfile, before)).toThrow("non-PyPI host");
  });

  it("requires changed pnpm artifacts to retain registry integrity", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-pnpm-"));
    const lockfile = join(dir, "pnpm-lock.yaml");
    const before = "lockfileVersion: '9.0'\npackages: {}\n";
    writeFileSync(lockfile, "lockfileVersion: '9.0'\npackages:\n  unsafe@1.0.0:\n    resolution: {}\n");
    expect(() => assertOfficialPnpmArtifacts(lockfile, before)).toThrow("without a recognized integrity hash");

    writeFileSync(lockfile, "lockfileVersion: '9.0'\npackages:\n  safe@1.0.0:\n    resolution:\n      integrity: sha512-abc\n");
    expect(() => assertOfficialPnpmArtifacts(lockfile, before)).not.toThrow();

    writeFileSync(lockfile, "lockfileVersion: '9.0'\npackages:\n  unsafe@1.0.0:\n    resolution:\n      tarball: https://evil.example/unsafe.tgz\n      integrity: sha512-abc\n");
    expect(() => assertOfficialPnpmArtifacts(lockfile, before)).toThrow("non-registry pnpm artifact");
  });

  it("updates a direct pnpm dependency through the native resolver", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-pnpm-update-"));
    try {
      writeFileSync(join(dir, "package.json"), `${JSON.stringify({
        name: "pnpm-security-fixture",
        private: true,
        packageManager: "pnpm@11.9.0",
        dependencies: { yaml: "2.9.0" },
      }, null, 2)}\n`);
      writeFileSync(join(dir, "pnpm-workspace.yaml"), "packages: []\n");
      execFileSync("pnpm", ["install", "--lockfile-only", "--ignore-scripts"], { cwd: dir, stdio: "ignore" });
      const lockfile = join(dir, "pnpm-lock.yaml");
      const result = updatePnpm({
        ecosystem: "npm",
        dependency: "yaml",
        version: "2.9.0",
        advisory: "GHSA-fixture",
        aliases: ["GHSA-fixture"],
        fixedVersion: "2.9.1",
        sourcePath: lockfile,
        malicious: false,
        withdrawn: false,
      });
      const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      expect(result.strategy).toBe("pnpm-direct");
      expect(manifest.dependencies.yaml).toBe("2.9.1");
      expect(readFileSync(lockfile, "utf8")).toContain("yaml@2.9.1");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
