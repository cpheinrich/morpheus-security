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
  requiredChecksReady,
  staleCandidateAction,
  updateNpm,
  updatePnpm,
  verifiedCandidateAttestation,
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
    expect(() => assertOfficialPnpmArtifacts(lockfile, before, () => ({
      integrity: "sha512-abc",
      tarball: "https://registry.npmjs.org/safe/-/safe-1.0.0.tgz",
    }))).not.toThrow();
    expect(() => assertOfficialPnpmArtifacts(lockfile, before, () => ({
      integrity: "sha512-other",
      tarball: "https://registry.npmjs.org/safe/-/safe-1.0.0.tgz",
    }))).toThrow("does not match registry.npmjs.org");

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
      const beforeLock = readFileSync(lockfile, "utf8");
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
      expect(() => assertOfficialPnpmArtifacts(lockfile, beforeLock)).not.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("rejects repository registry overrides and non-registry direct specs", () => {
    const pnpmDir = mkdtempSync(join(tmpdir(), "morpheus-security-pnpm-config-"));
    const npmDir = mkdtempSync(join(tmpdir(), "morpheus-security-npm-spec-"));
    try {
      writeFileSync(join(pnpmDir, "package.json"), `${JSON.stringify({
        name: "unsafe-pnpm-fixture", private: true, dependencies: { yaml: "2.9.0" },
      })}\n`);
      writeFileSync(join(pnpmDir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\nimporters:\n  .: {}\npackages: {}\n");
      writeFileSync(join(pnpmDir, ".npmrc"), "registry=https://evil.example/\n");
      expect(() => updatePnpm({ ...osv, dependency: "yaml", fixedVersion: "2.9.1", sourcePath: join(pnpmDir, "pnpm-lock.yaml") }))
        .toThrow("registry or credential configuration");

      writeFileSync(join(npmDir, "package.json"), `${JSON.stringify({
        name: "unsafe-npm-fixture", private: true, dependencies: { uuid: "git+https://example.com/uuid.git" },
      })}\n`);
      writeFileSync(join(npmDir, "package-lock.json"), `${JSON.stringify({ lockfileVersion: 3, packages: {} })}\n`);
      expect(() => updateNpm({ ...osv, sourcePath: join(npmDir, "package-lock.json") }))
        .toThrow("unsupported npm direct specifier");
    } finally {
      rmSync(pnpmDir, { recursive: true, force: true });
      rmSync(npmDir, { recursive: true, force: true });
    }
  });

  it("merges only after every explicitly named check passes", () => {
    const rollup = [
      { name: "test", status: "COMPLETED", conclusion: "SUCCESS" },
      { context: "policy", state: "SUCCESS" },
    ];
    expect(requiredChecksReady(rollup, [])).toEqual(expect.objectContaining({ ready: false }));
    expect(requiredChecksReady(rollup, ["missing"])).toEqual(expect.objectContaining({ ready: false }));
    expect(requiredChecksReady(rollup, ["test", "policy"])).toEqual(expect.objectContaining({ ready: true }));
    expect(requiredChecksReady([
      { name: "test", status: "IN_PROGRESS", conclusion: null },
    ], ["test"])).toEqual(expect.objectContaining({ ready: false }));
  });

  it("trusts only a successful attestation owned by the current App and head", () => {
    const headSha = "a".repeat(40);
    const receipt = {
      version: 1,
      repository: "cpheinrich/example",
      headSha,
      dependency: "yaml",
      advisory: "GHSA-example",
      aliases: ["GHSA-example"],
      sourcePath: "pnpm-lock.yaml",
    };
    const check = {
      id: 42,
      name: "Morpheus Security / candidate",
      head_sha: headSha,
      app: { slug: "example-security" },
      status: "completed",
      conclusion: "success",
      output: { summary: JSON.stringify(receipt) },
    };
    expect(verifiedCandidateAttestation([check], "example-security", headSha, "cpheinrich/example"))
      .toEqual(receipt);
    expect(verifiedCandidateAttestation([check], "other-app", headSha, "cpheinrich/example")).toBeNull();
    expect(verifiedCandidateAttestation([check], "example-security", "b".repeat(40), "cpheinrich/example"))
      .toBeNull();
    expect(verifiedCandidateAttestation([
      { ...check, output: { summary: JSON.stringify({ ...receipt, dependency: "other" }) }, app: { slug: "other-app" } },
    ], "example-security", headSha, "cpheinrich/example")).toBeNull();
  });

  it("recreates stale candidates instead of retrying an impossible strict merge", () => {
    expect(staleCandidateAction("BEHIND")).toBe("recreate");
    expect(staleCandidateAction("DIRTY")).toBe("recreate");
    expect(staleCandidateAction("UNKNOWN")).toBe("wait");
    expect(staleCandidateAction("CLEAN")).toBe("continue");
    expect(staleCandidateAction("BLOCKED")).toBe("continue");
  });

  it("refreshes live default-branch state after reconciliation and before scanning", () => {
    const workflow = readFileSync(".github/workflows/security-remediation.yml", "utf8");
    const reconcile = workflow.indexOf("name: Reconcile existing bot pull requests");
    const refresh = workflow.indexOf("name: Refresh the trusted default branch before scanning");
    const scan = workflow.indexOf("name: Scan trusted main with OSV");
    expect(reconcile).toBeGreaterThan(-1);
    expect(refresh).toBeGreaterThan(reconcile);
    expect(scan).toBeGreaterThan(refresh);
    expect(workflow).toContain('test "$(git rev-parse HEAD)" = "$LIVE_SHA"');
  });
});
