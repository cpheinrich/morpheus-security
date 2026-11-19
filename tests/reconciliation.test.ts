import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const engine = resolve("scripts/security-remediation.mjs");
const repo = "unit/example";
const head = "a".repeat(40);
const base = "b".repeat(40);
const prUrl = "https://github.com/unit/example/pull/42";
const botLogin = "test-security[bot]";

const ghFixture = `#!/usr/bin/env node
const { appendFileSync } = require("node:fs");
const args = process.argv.slice(2);
const { pull, base, check, checks, failMerge, reportedHead } = JSON.parse(process.env.TEST_GH_FIXTURE);
const endpoint = args.find((arg) => arg.startsWith("repos/"));
if (endpoint?.endsWith("/commits/main")) console.log(base);
else if (endpoint?.includes("/pulls?")) console.log(JSON.stringify([[pull]]));
else if (endpoint?.endsWith("/pulls/42")) console.log(JSON.stringify({ ...pull, head: { ...pull.head, sha: reportedHead } }));
else if (endpoint?.includes("check_name=")) console.log(JSON.stringify({ check_runs: check ? [check] : [] }));
else if (endpoint?.includes("/check-runs?")) console.log(JSON.stringify([{ check_runs: checks }]));
else if (endpoint?.includes("/statuses?")) console.log("[[]]");
else if (args[0] === "pr") {
  appendFileSync(process.env.TEST_GH_WRITES, JSON.stringify(args) + "\\n");
  if (failMerge && args[1] === "merge") {
    console.error("GitHub still requires approval\\n::error::fixture");
    process.exitCode = 1;
  }
} else throw new Error("Unexpected GitHub CLI call: " + args.join(" "));
`;

function runReconciliation({
  draft = true, attested = true, hold = false, checks = true, failMerge = false,
  requiredChecks = ["ci"] as readonly string[], reportedRepo = repo,
  mergeState = "clean", reportedHead = head, liveBase = base,
} = {}) {
  const dir = mkdtempSync(join(tmpdir(), "morpheus-security-reconcile-"));
  try {
    const bin = join(dir, "bin");
    const writes = join(dir, "writes");
    const summary = join(dir, "summary");
    const outputs = join(dir, "outputs");
    mkdirSync(bin);
    writeFileSync(writes, "");
    writeFileSync(join(bin, "gh"), ghFixture, { mode: 0o755 });
    writeFileSync(join(bin, "git"), `#!/bin/sh\nprintf '%s\\n' '${base}'\n`, { mode: 0o755 });
    writeFileSync(join(dir, "policy.json"), JSON.stringify({
      version: 1,
      holds: hold ? [{ dependency: "sample", advisory: "GHSA-example", reason: "Runtime incompatibility" }] : [],
      requiredChecks,
    }));
    const pull = {
      number: 42, state: "open", draft, mergeable: true,
      mergeable_state: mergeState, html_url: prUrl,
      user: { login: botLogin },
      head: { sha: head, ref: "morpheus-security/npm-sample-abc", repo: { full_name: reportedRepo } },
      base: { ref: "main", repo: { full_name: repo } },
    };
    const check = attested ? {
      id: 10, name: "Morpheus Security / candidate", head_sha: head,
      app: { slug: "test-security" }, status: "completed", conclusion: "success",
      output: { summary: JSON.stringify({
        version: 1, repository: repo, headSha: head, dependency: "sample",
        advisory: "GHSA-example", aliases: [], sourcePath: "package-lock.json",
      }) },
    } : null;
    const logs = execFileSync(process.execPath, [engine, "reconcile"], {
      cwd: dir, encoding: "utf8",
      env: {
        PATH: bin + delimiter + process.env.PATH, GH_TOKEN: "test-token",
        TARGET_REPOSITORY: repo, DEFAULT_BRANCH: "main", BOT_LOGIN: botLogin,
        SECURITY_CONFIG: "policy.json", GITHUB_STEP_SUMMARY: summary, GITHUB_OUTPUT: outputs,
        TEST_GH_WRITES: writes,
        TEST_GH_FIXTURE: JSON.stringify({
          pull, base: liveBase, check, failMerge, reportedHead,
          checks: [{ id: 20, name: "ci", status: "completed", conclusion: checks ? "success" : "failure" }],
        }),
      },
    });
    return {
      logs,
      summary: readFileSync(summary, "utf8"),
      outputs: readFileSync(outputs, "utf8"),
      writes: readFileSync(writes, "utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line)),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("Security App pull request reconciliation", () => {
  it("marks a validated draft ready and waits for a subsequent run even when CI is green", () => {
    const result = runReconciliation();
    expect(result.writes).toEqual([["pr", "ready", "42", "--repo", repo]]);
    expect(result.outputs).toContain("merged=false\n");
    expect(result.logs).toContain(`${prUrl}: marked the attested candidate ready`);
    expect(result.summary).toContain("marked the attested candidate ready");

    const followingRun = runReconciliation({ draft: false });
    expect(followingRun.writes).toEqual([
      ["pr", "merge", "42", "--repo", repo, "--match-head-commit", head, "--squash", "--delete-branch"],
    ]);
    expect(followingRun.outputs).toContain("merged=true\n");
  });

  it.each([
    [{ hold: true }, "project hold: Runtime incompatibility"],
    [{ attested: false }, "no valid App-owned candidate attestation"],
    [{ requiredChecks: [] }, "automatic merge is disabled"],
    [{ reportedRepo: "unit/fork" }, "attested pull request or its target changed"],
    [{ reportedHead: "e".repeat(40) }, "attested pull request or its target changed"],
    [{ liveBase: "f".repeat(40) }, "Reconciliation stopped because main changed"],
    [{ draft: false, checks: false }, "required check has not passed: ci"],
  ] as const)("leaves a blocked PR alone for %j", (options, reason) => {
    const result = runReconciliation(options);
    expect(result.writes).toEqual([]);
    expect(result.outputs).toContain("merged=false\n");
    expect(result.logs).toContain(reason);
  });

  it("requests a fresh candidate if strict branch protection makes a green PR stale", () => {
    const result = runReconciliation({ draft: false, mergeState: "behind" });
    expect(result.writes).toEqual([["pr", "close", "42", "--repo", repo, "--delete-branch"]]);
    expect(result.outputs).toContain("merged=false\n");
    expect(result.logs).toContain("a replacement requires fresh validation");

    const unattestedReplacement = runReconciliation({ draft: false, attested: false });
    expect(unattestedReplacement.writes).toEqual([]);
    const validatedReplacement = runReconciliation({ draft: false, checks: true });
    expect(validatedReplacement.outputs).toContain("merged=true\n");
  });

  it("merges a ready PR only with a matching head guard", () => {
    const result = runReconciliation({ draft: false });
    expect(result.writes).toEqual([
      ["pr", "merge", "42", "--repo", repo, "--match-head-commit", head, "--squash", "--delete-branch"],
    ]);
    expect(result.outputs).toContain("merged=true\n");
  });

  it("records a GitHub refusal in private logs without executing workflow command text", () => {
    const result = runReconciliation({ draft: false, failMerge: true });
    expect(result.logs).toContain("GitHub still requires approval");
    expect(result.logs).toContain("\nMorpheus Security: ::error::fixture)");
    expect(result.outputs).toContain("merged=false\n");
  });
});
