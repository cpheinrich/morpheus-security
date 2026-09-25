import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertOfficialNpmArtifacts,
  assertOfficialPnpmArtifacts,
  assertOfficialUvArtifacts,
  combineFindings,
  malwareIncidentBody,
  restCheckRollup,
  restMergeReadiness,
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
  it("keeps public incident text non-sensitive and lists every affected manifest", () => {
    const body = malwareIncidentBody("cpheinrich/public-repo", { ...osv, advisory: "MAL-2026-1" }, [
      { ...osv, advisory: "MAL-2026-1", sourcePath: "apps/one/package-lock.json", version: "1.0.0" },
      { ...osv, advisory: "MAL-2026-1", sourcePath: "apps/two/package-lock.json", version: "2.0.0" },
    ]);
    expect(body).toContain("apps/one/package-lock.json");
    expect(body).toContain("apps/two/package-lock.json");
    expect(body).toContain("Keep credentials, tokens, exposure details");
    expect(body).not.toContain("what credentials were exposed");
  });

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

  it("preserves unrelated pnpm transitive major lines", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-pnpm-lines-"));
    try {
      mkdirSync(join(dir, "packages", "legacy"), { recursive: true });
      mkdirSync(join(dir, "packages", "current"), { recursive: true });
      writeFileSync(join(dir, "package.json"), `${JSON.stringify({
        name: "pnpm-security-lines-fixture",
        private: true,
        packageManager: "pnpm@11.9.0",
      }, null, 2)}\n`);
      writeFileSync(join(dir, "pnpm-workspace.yaml"), [
        "packages:",
        "  - packages/*",
        "overrides:",
        "  brace-expansion@<2: 1.1.15",
        "  brace-expansion@>=5: 5.0.6",
        "",
      ].join("\n"));
      writeFileSync(join(dir, "packages", "legacy", "package.json"), `${JSON.stringify({
        name: "legacy", private: true, dependencies: { minimatch: "3.1.5" },
      })}\n`);
      writeFileSync(join(dir, "packages", "current", "package.json"), `${JSON.stringify({
        name: "current", private: true, dependencies: { minimatch: "10.2.5" },
      })}\n`);
      execFileSync("pnpm", ["install", "--lockfile-only", "--ignore-scripts"], { cwd: dir, stdio: "ignore" });
      const lockfile = join(dir, "pnpm-lock.yaml");
      expect(readFileSync(lockfile, "utf8")).toContain("brace-expansion@1.1.15");
      expect(readFileSync(lockfile, "utf8")).toContain("brace-expansion@5.0.6");
      writeFileSync(join(dir, "pnpm-workspace.yaml"), "packages:\n  - packages/*\n");

      const result = updatePnpm({
        ecosystem: "npm",
        dependency: "brace-expansion",
        version: "1.1.15",
        advisory: "GHSA-fixture",
        aliases: ["GHSA-fixture"],
        fixedVersion: "1.1.16",
        sourcePath: lockfile,
        malicious: false,
        withdrawn: false,
      });

      const updated = readFileSync(lockfile, "utf8");
      const packages = updated.split("\npackages:\n")[1];
      expect(result.strategy).toBe("pnpm-transitive-override");
      expect(packages).not.toContain("brace-expansion@1.1.15");
      expect(packages).toContain("brace-expansion@1.1.16");
      expect(packages).toContain("brace-expansion@5.0.6");
      expect(readFileSync(join(dir, "pnpm-workspace.yaml"), "utf8"))
        .toContain("brace-expansion@1.1.15: 1.1.16");

      const advanced = updatePnpm({
        ecosystem: "npm",
        dependency: "brace-expansion",
        version: "1.1.16",
        advisory: "GHSA-follow-up",
        aliases: ["GHSA-follow-up"],
        fixedVersion: "1.1.17",
        sourcePath: lockfile,
        malicious: false,
        withdrawn: false,
      });
      const advancedWorkspace = readFileSync(join(dir, "pnpm-workspace.yaml"), "utf8");
      expect(advanced.strategy).toBe("pnpm-transitive-override-advanced");
      expect(advancedWorkspace).toContain("brace-expansion@1.1.15: 1.1.17");
      expect(advancedWorkspace).not.toContain("brace-expansion@1.1.16:");
      expect(readFileSync(lockfile, "utf8").split("\npackages:\n")[1])
        .toContain("brace-expansion@1.1.17");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("advances an existing npm security override instead of chaining it", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-npm-advance-"));
    try {
      const manifestPath = join(dir, "package.json");
      writeFileSync(manifestPath, `${JSON.stringify({
        name: "npm-security-advance-fixture",
        private: true,
        dependencies: { mkdirp: "0.5.5" },
        overrides: { "minimist@1.2.5": "1.2.6" },
      }, null, 2)}\n`);
      execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], {
        cwd: dir,
        stdio: "ignore",
      });
      const lockfile = join(dir, "package-lock.json");
      expect(readFileSync(lockfile, "utf8")).toContain('"version": "1.2.6"');

      const result = updateNpm({
        ...osv,
        dependency: "minimist",
        version: "1.2.6",
        fixedVersion: "1.2.7",
        sourcePath: lockfile,
      });

      expect(result.strategy).toBe("transitive-override-advanced");
      expect(JSON.parse(readFileSync(manifestPath, "utf8")).overrides)
        .toEqual({ "minimist@1.2.5": "1.2.7" });
      const installed = JSON.parse(readFileSync(lockfile, "utf8")).packages["node_modules/minimist"].version;
      expect(["1.2.7", "1.2.8"]).toContain(installed);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("accepts an npm transitive update above the first patched version", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-npm-compatible-"));
    try {
      const manifestPath = join(dir, "package.json");
      const manifest = {
        name: "npm-security-compatible-fixture",
        private: true,
        dependencies: { mkdirp: "0.5.6" },
      };
      writeFileSync(manifestPath, `${JSON.stringify({
        ...manifest,
        overrides: { minimist: "1.2.6" },
      }, null, 2)}\n`);
      execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], {
        cwd: dir,
        stdio: "ignore",
      });
      const lockfile = join(dir, "package-lock.json");
      expect(readFileSync(lockfile, "utf8")).toContain('"version": "1.2.6"');
      writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

      const result = updateNpm({
        ecosystem: "npm",
        dependency: "minimist",
        version: "1.2.6",
        advisory: "GHSA-fixture",
        aliases: ["GHSA-fixture"],
        fixedVersion: "1.2.7",
        sourcePath: lockfile,
        malicious: false,
        withdrawn: false,
      });

      const updated = JSON.parse(readFileSync(lockfile, "utf8"));
      expect(result.strategy).toBe("transitive-compatible");
      expect(updated.packages["node_modules/minimist"].version).toBe("1.2.8");
      expect(JSON.parse(readFileSync(manifestPath, "utf8"))).not.toHaveProperty("overrides");
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
      writeFileSync(join(pnpmDir, ".npmrc"), "registry=https://evil.example/ # trailing comment\n");
      expect(() => updatePnpm({ ...osv, dependency: "yaml", fixedVersion: "2.9.1", sourcePath: join(pnpmDir, "pnpm-lock.yaml") }))
        .toThrow("registry or credential configuration");
      writeFileSync(join(pnpmDir, ".npmrc"), "@unsafe:registry=https://evil.example/ ; trailing comment\n");
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

  it("accepts an explicit official npm registry without credentials", () => {
    const dir = mkdtempSync(join(tmpdir(), "morpheus-security-npm-official-"));
    try {
      writeFileSync(join(dir, "package.json"), `${JSON.stringify({
        name: "official-npm-fixture", private: true, dependencies: { uuid: "9.0.1" },
      })}\n`);
      execFileSync("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], {
        cwd: dir,
        stdio: "ignore",
      });
      writeFileSync(join(dir, ".npmrc"), [
        "registry=https://registry.npmjs.org/",
        "@example:registry=https://registry.npmjs.org/ ; trusted public registry",
        "",
      ].join("\n"));
      expect(() => updateNpm({ ...osv, sourcePath: join(dir, "package-lock.json") })).not.toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

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

  it("normalizes REST checks and the newest legacy status without Actions access", () => {
    const rollup = restCheckRollup([
      { id: 1, name: "test", app: { id: 10 }, status: "completed", conclusion: "cancelled" },
      { id: 2, name: "test", app: { id: 10 }, status: "completed", conclusion: "success" },
      { id: 3, name: "build", app: { id: 10 }, status: "in_progress", conclusion: null },
    ], [
      { id: 4, context: "policy", state: "failure" },
      { id: 5, context: "policy", state: "success" },
    ]);
    expect(requiredChecksReady(rollup, ["test", "policy"]))
      .toEqual(expect.objectContaining({ ready: true }));
    expect(requiredChecksReady(rollup, ["build"]))
      .toEqual(expect.objectContaining({ ready: false }));
  });

  it("does not let a same-named check from another App or suite erase a failure", () => {
    const rollup = restCheckRollup([
      { id: 10, name: "test", app: { id: 1 }, check_suite: { id: 100 }, status: "completed", conclusion: "failure" },
      { id: 11, name: "test", app: { id: 1 }, check_suite: { id: 200 }, status: "completed", conclusion: "success" },
    ], []);
    expect(requiredChecksReady(rollup, ["test"]))
      .toEqual(expect.objectContaining({ ready: false }));
  });

  it("does not ignore a cancellation newer than the matching success", () => {
    const rollup = restCheckRollup([
      { id: 10, name: "test", app: { id: 1 }, check_suite: { id: 100 }, status: "completed", conclusion: "success" },
      { id: 11, name: "test", app: { id: 1 }, check_suite: { id: 200 }, status: "completed", conclusion: "cancelled" },
    ], []);
    expect(requiredChecksReady(rollup, ["test"]))
      .toEqual(expect.objectContaining({ ready: false }));
  });

  it("combines every paginated REST status page", () => {
    const readiness = restMergeReadiness(
      { mergeable: true, mergeable_state: "clean" },
      [{ check_runs: [] }],
      [
        [{ id: 1, context: "first", state: "success" }],
        [{ id: 2, context: "later", state: "success" }],
      ],
    );
    expect(readiness.mergeStateStatus).toBe("clean");
    expect(requiredChecksReady(readiness.statusCheckRollup, ["later"]))
      .toEqual(expect.objectContaining({ ready: true }));
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
    expect(staleCandidateAction("behind")).toBe("recreate");
    expect(staleCandidateAction(null)).toBe("wait");
  });

  it("does not require the Actions-only GraphQL check-rollup field", () => {
    const remediation = readFileSync("scripts/security-remediation.mjs", "utf8");
    expect(remediation).not.toContain("statusCheckRollup,mergeStateStatus");
    expect(remediation).not.toContain("mergeStateStatus,statusCheckRollup");
    expect(remediation).toContain("/check-runs?per_page=100");
    expect(remediation).toContain("/statuses?per_page=100");
  });

  it("binds the public target workflow to live policy and one repository token", () => {
    const workflow = readFileSync(".github/workflows/security-remediation.yml", "utf8");
    const reconcile = workflow.indexOf("name: Reconcile existing bot pull requests");
    const refresh = workflow.indexOf("name: Refresh and authenticate the live default branch");
    const revalidate = workflow.indexOf("name: Revalidate the live opt-in policy");
    const scan = workflow.indexOf("name: Scan trusted main with OSV");
    expect(workflow).toContain("workflow_call:");
    expect(workflow).not.toContain("workflow_dispatch:");
    expect(workflow).not.toContain("schedule:");
    expect(reconcile).toBeGreaterThan(-1);
    expect(refresh).toBeLessThan(reconcile);
    expect(revalidate).toBeGreaterThan(refresh);
    expect(revalidate).toBeLessThan(reconcile);
    expect(scan).toBeGreaterThan(reconcile);
    expect(workflow).toContain('test "$(git rev-parse HEAD)" = "$LIVE_SHA"');
    expect(workflow).toContain("TARGET_REPOSITORY: ${{ inputs.target-repository }}");
    expect(workflow).toContain("repositories: ${{ inputs.target-name }}");
    expect(workflow).toContain("permission-issues: write");
    expect(workflow).not.toContain("INCIDENT_GH_TOKEN");
    expect(workflow).not.toContain("incident-token");
    expect(workflow).toContain("ref: ${{ inputs.security-sha }}");
  });
});
