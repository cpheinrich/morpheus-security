import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { expect, it } from "vitest";

const engine = resolve("scripts/security-remediation.mjs");

function advisoryResult(directory: string, dependency: string, lockfile = "package-lock.json") {
  return {
    source: { type: "lockfile", path: `${directory}/${lockfile}` },
    packages: [{
      package: { name: dependency, ecosystem: "npm", version: "1.0.0" },
      vulnerabilities: [{ id: "GHSA-fixture", affected: [{ ranges: [{
        type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.0.1" }],
      }] }] }],
    }],
  };
}

it("replays an unresolved npm override and prepares the next independent candidate from a clean tree", () => {
  const dir = mkdtempSync(join(tmpdir(), "morpheus-security-prepare-"));
  try {
    const bin = join(dir, "bin");
    const source = join(dir, "source");
    mkdirSync(bin);
    mkdirSync(source);
    const git = (...args: string[]) => execFileSync("git", args, { cwd: source, encoding: "utf8" }).trim();
    function writeCandidate(name: string, direct: boolean) {
      const root = join(source, name);
      mkdirSync(root);
      const manifest = JSON.stringify({ name, ...(direct ? { dependencies: { [name]: "1.0.0" } } : {}) });
      const lock = JSON.stringify({ packages: { [`node_modules/${name}`]: { version: "1.0.0" } } });
      writeFileSync(join(root, "package.json"), manifest);
      writeFileSync(join(root, "package-lock.json"), lock);
      return { root, manifest, lock };
    }
    const blocked = writeCandidate("first", false);
    const viable = writeCandidate("second", true);
    writeFileSync(join(source, "policy.json"), JSON.stringify({ version: 1, holds: [], requiredChecks: ["ci"] }));
    writeFileSync(join(source, "scan.json"), JSON.stringify({
      results: [
        advisoryResult("first", "first"),
        advisoryResult("reports", "unsupported", "requirements.txt"),
        advisoryResult("second", "second"),
      ],
    }));
    git("init", "-q");
    git("add", ".");
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture");
    writeFileSync(join(bin, "gh"), '#!/bin/sh\nprintf "%s\\n" "[[]]"\n', { mode: 0o755 });
    writeFileSync(join(bin, "npm"), `#!/usr/bin/env node
const { writeFileSync } = require("node:fs");
const cwd = process.cwd();
if (cwd.endsWith("/first") && process.argv[2] === "update") {
  writeFileSync("package-lock.json", "partial update");
  console.error("Cannot read properties of null (reading 'edgesOut')");
  process.exitCode = 1;
}
if (cwd.endsWith("/second")) {
  writeFileSync("package-lock.json", JSON.stringify({ packages: {
    "node_modules/second": {
      version: "1.0.1", resolved: "https://registry.npmjs.org/second/-/second-1.0.1.tgz", integrity: "sha512-fixture",
    },
  }}));
}
`, { mode: 0o755 });
    const logs = execFileSync(process.execPath, [engine, "prepare"], {
      cwd: source, encoding: "utf8", env: {
        PATH: bin + delimiter + process.env.PATH, GH_TOKEN: "test-token", BOT_LOGIN: "test-security[bot]",
        TARGET_REPOSITORY: "unit/example", SECURITY_CONFIG: "policy.json",
        SCAN_FILE: "scan.json", PLAN_FILE: join(dir, "plan.json"), GITHUB_OUTPUT: join(dir, "outputs"),
      },
    });
    const plan = JSON.parse(readFileSync(join(dir, "plan.json"), "utf8"));
    expect(plan.finding.dependency).toBe("second");
    expect(plan.blocked).toEqual([{
      dependency: "first", advisory: "GHSA-fixture", sourcePath: "first/package-lock.json",
      reason: "npm kept first@1.0.0 after applying the scoped override",
    }, {
      dependency: "unsupported", advisory: "GHSA-fixture", sourcePath: "reports/requirements.txt",
      reason: "no remediation adapter for requirements.txt",
    }]);
    expect(plan.changedFiles).toEqual(["second/package-lock.json", "second/package.json"]);
    expect(readFileSync(join(blocked.root, "package.json"), "utf8")).toBe(blocked.manifest);
    expect(readFileSync(join(blocked.root, "package-lock.json"), "utf8")).toBe(blocked.lock);
    expect(JSON.parse(readFileSync(join(viable.root, "package.json"), "utf8")).dependencies.second).toBe("1.0.1");
    expect(logs).toContain("first/package-lock.json: first (GHSA-fixture) is blocked");
    expect(readFileSync(join(dir, "outputs"), "utf8")).toContain("changed=true\n");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
