#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parse, parseDocument } from "yaml";
import { validateSecurityConfig } from "./config.mjs";
import { compatibilityMappingFor, loadCompatibilityMappings } from "./compatibility-mappings.mjs";
import {
  findingKey,
  findingsFromOsvJson,
  isSecurityDependencyOnly,
  SECURITY_MARKER,
} from "../dist/policy.js";
import { isAllowedCompatibilitySource, replaceImportSpecifiers, validateGeneratedDistPaths, validateImportCompatibility } from "../dist/import-compatibility.js";

const INCIDENT_LABELS = [
  ["security-incident", "b60205", "Security incident record"],
  ["dependency-malware", "8b0000", "Malicious dependency advisory"],
  ["automated", "1f883d", "Created by automation"],
  ["needs-exposure-review", "d4c5f9", "Human exposure assessment required"],
];
const CANDIDATE_CHECK = "Morpheus Security / candidate";

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function targetRepository() {
  return required("TARGET_REPOSITORY");
}

function run(file, args, options = {}) {
  return execFileSync(file, args, {
    encoding: "utf8",
    maxBuffer: 30 * 1024 * 1024,
    stdio: options.stdio ?? ["ignore", "pipe", "pipe"],
    ...options,
  }).trim();
}

function generatedDistDigest() {
  return createHash("sha256").update(execFileSync("git", ["diff", "--binary", "--", "dist"])).digest("hex");
}

function packageManagerEnvironment() {
  const environment = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (!/(?:token|secret|password|credential|auth|private.?key)/i.test(name) &&
        !/^(?:npm_config|uv|pip)_.+(?:index|registry|cert|key|proxy)/i.test(name) &&
        !/^(?:https?_proxy|all_proxy|no_proxy|node_extra_ca_certs|ssl_cert_file|requests_ca_bundle)$/i.test(name)) {
      environment[name] = value;
    }
  }
  return {
    ...environment,
    NPM_CONFIG_REGISTRY: "https://registry.npmjs.org/",
    NPM_CONFIG_USERCONFIG: "/dev/null",
    UV_DEFAULT_INDEX: "https://pypi.org/simple",
  };
}

function packageRun(file, args, options = {}) {
  return run(file, args, { ...options, env: packageManagerEnvironment() });
}

function gh(args, token = process.env.GH_TOKEN) {
  const output = run("gh", args, { env: { ...process.env, GH_TOKEN: token } });
  return output ? JSON.parse(output) : null;
}

function output(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

function summary(markdown) {
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${markdown.trim()}\n`);
  else process.stdout.write(`${markdown.trim()}\n`);
}

function loadConfig() {
  const path = process.env.SECURITY_CONFIG ?? ".github/morpheus-security.json";
  if (!existsSync(path)) throw new Error(`Required opt-in policy is missing: ${path}`);
  const config = JSON.parse(readFileSync(path, "utf8"));
  return validateSecurityConfig(config);
}

function dependabotFindings(repo) {
  const pages = gh(["api", "--paginate", "--slurp", `repos/${repo}/dependabot/alerts?state=open&per_page=100`]);
  return (pages ?? []).flatMap((page) => page).filter((alert) => !alert.security_advisory?.withdrawn_at).map((alert) => ({
    ecosystem: alert.dependency.package.ecosystem,
    dependency: alert.dependency.package.name,
    version: "unknown",
    advisory: alert.security_advisory.ghsa_id,
    aliases: (alert.security_advisory.identifiers ?? []).map((identifier) => identifier.value).sort(),
    fixedVersion: alert.security_vulnerability.first_patched_version?.identifier ?? null,
    sourcePath: alert.dependency.manifest_path,
    malicious: String(alert.security_advisory.ghsa_id).startsWith("MAL-"),
    withdrawn: false,
  }));
}

export function combineFindings(osv, github) {
  const combined = [...osv];
  for (const candidate of github) {
    const match = combined.find((finding) =>
      finding.ecosystem.toLowerCase() === candidate.ecosystem.toLowerCase() &&
      finding.dependency === candidate.dependency &&
      finding.aliases.some((alias) => candidate.aliases.includes(alias)));
    if (match) {
      match.aliases = [...new Set([...match.aliases, ...candidate.aliases])].sort();
      match.fixedVersion ??= candidate.fixedVersion;
    } else {
      combined.push(candidate);
    }
  }
  return combined.sort((a, b) =>
    Number(b.malicious) - Number(a.malicious) ||
    a.sourcePath.localeCompare(b.sourcePath) || a.dependency.localeCompare(b.dependency));
}

function openSecurityPulls(repo) {
  const botLogin = required("BOT_LOGIN");
  const pages = gh(["api", "--paginate", "--slurp", `repos/${repo}/pulls?state=open&per_page=100`]);
  return (pages ?? []).flatMap((page) => page).filter((pr) =>
    pr.user?.login === botLogin && String(pr.head?.ref ?? "").startsWith("morpheus-security/"));
}

function held(finding, config) {
  return config.holds.find((hold) => hold.dependency === finding.dependency &&
    (!hold.advisory || finding.aliases.includes(hold.advisory)));
}

export function nextCompatibilityCandidate(findings, mappings, config, open) {
  if (config.importOnlyCompatibility !== true) return null;
  const openLockfiles = new Set(open.map((pr) => /Lockfile: `([^`]+)`/.exec(pr.body ?? "")?.[1]).filter(Boolean));
  for (const finding of findings) {
    const mapping = compatibilityMappingFor(finding, mappings);
    if (!mapping || held(finding, config) || openLockfiles.has(finding.sourcePath) ||
        open.some((pr) => String(pr.body ?? "").includes(`Dependency: \`${finding.dependency}\``))) continue;
    if (!["pnpm-lock.yaml", "package-lock.json"].includes(basename(finding.sourcePath))) continue;
    return { finding, mapping };
  }
  return null;
}

export function nextCandidate(findings, config, open) {
  const openLockfiles = new Set(open.map((pr) => /Lockfile: `([^`]+)`/.exec(pr.body ?? "")?.[1]).filter(Boolean));
  return findings.find((finding) => (finding.fixedVersion || finding.malicious) &&
    (finding.malicious || affectedVersionsForCandidate(findings, finding).every((affected) => affected.fixedVersion)) &&
    !held(finding, config) &&
    !open.some((pr) => String(pr.body ?? "").includes(`Dependency: \`${finding.dependency}\``)) &&
    !openLockfiles.has(finding.sourcePath)) ?? null;
}

function slug(value) {
  return value.toLowerCase().replace(/^@/, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 45);
}

function ensureLabel(repo, name, color, description, token = process.env.GH_TOKEN) {
  try {
    gh(["api", `repos/${repo}/labels/${encodeURIComponent(name)}`], token);
  } catch {
    gh(["api", "--method", "POST", `repos/${repo}/labels`, "-f", `name=${name}`, "-f", `color=${color}`, "-f", `description=${description}`], token);
  }
}

export function malwareIncidentBody(repo, finding, findings) {
  const related = findings.filter((candidate) => findingKey(candidate) === findingKey(finding));
  const affected = [...new Set(related.map((candidate) =>
    `- \`${candidate.sourcePath}\` (observed version: \`${candidate.version}\`)`))].sort();
  const marker = `<!-- morpheus-malware-incident:${findingKey(finding)} -->`;
  return `${marker}\n\nMorpheus Security detected malicious package advisory **${finding.advisory}** for ` +
    `\`${finding.dependency}\` in \`${repo}\`.\n\nAffected manifests:\n${affected.join("\n")}\n\n` +
    "Automated remediation is being attempted separately. Keep credentials, tokens, exposure " +
    "details, and other private investigation material out of this issue. Record only safe status " +
    "updates here.\n\n" +
    "- [ ] Private installation/execution exposure assessment completed\n" +
    "- [ ] Required credential rotation and containment completed\n" +
    "- [ ] Remediation merged and the default branch rescanned clean\n\n" +
    `Advisory: https://osv.dev/vulnerability/${finding.advisory}`;
}

function upsertMalwareIncident(repo, finding, findings) {
  for (const label of INCIDENT_LABELS) ensureLabel(repo, ...label);
  const marker = `<!-- morpheus-malware-incident:${findingKey(finding)} -->`;
  const pages = gh(["api", "--paginate", "--slurp", `repos/${repo}/issues?state=all&labels=dependency-malware&per_page=100`]);
  const existing = (pages ?? []).flatMap((page) => page).find((issue) => String(issue.body ?? "").includes(marker));
  const body = malwareIncidentBody(repo, finding, findings);
  if (existing) {
    gh(["api", "--method", "PATCH", `repos/${repo}/issues/${existing.number}`, "-f", `body=${body}`]);
    return existing.html_url;
  }
  const created = gh(["api", "--method", "POST", `repos/${repo}/issues`,
    "-f", `title=[Security incident] ${finding.advisory} in ${finding.dependency}`,
    "-f", `body=${body}`,
    ...INCIDENT_LABELS.flatMap(([name]) => ["-f", `labels[]=${name}`])]);
  return created.html_url;
}

function packageRoot(lockfile) {
  return dirname(resolve(lockfile));
}

function assertOfficialNpmConfiguration(root) {
  const npmrcFiles = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === ".git" || entry.name === "node_modules") continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (entry.isFile() && entry.name === ".npmrc") npmrcFiles.push(path);
    }
  };
  visit(root);
  for (const path of npmrcFiles) {
    const text = readFileSync(path, "utf8");
    if (/^\s*[^#;]*(?:_auth|authToken|password|certfile|keyfile)\s*=/im.test(text)) {
      throw new Error(`Refusing repository registry or credential configuration in ${relative(root, path)}`);
    }
    for (const line of text.split(/\r?\n/)) {
      if (/^\s*[#;]/.test(line) || !line.trim()) continue;
      const registry = /^\s*(?:@[^:\s]+:)?registry\s*=\s*(.*?)\s*$/i.exec(line);
      const value = registry?.[1].replace(/\s+[;#].*$/, "").trim();
      if (registry && !/^https:\/\/registry\.npmjs\.org\/?$/i.test(value)) {
        throw new Error(`Refusing repository registry or credential configuration in ${relative(root, path)}`);
      }
    }
  }
  const workspacePath = join(root, "pnpm-workspace.yaml");
  if (existsSync(workspacePath)) {
    const workspace = parse(readFileSync(workspacePath, "utf8"));
    if (workspace?.registries || workspace?.networkConfig) {
      throw new Error("Refusing custom pnpm registry configuration");
    }
  }
}

function registryArgs(dependency) {
  const scope = /^(@[^/]+)\//.exec(dependency)?.[1];
  return ["--registry=https://registry.npmjs.org/", ...(scope ? [`--${scope}:registry=https://registry.npmjs.org/`] : [])];
}

function installedNpmVersions(lockfile, dependency) {
  const lock = JSON.parse(readFileSync(lockfile, "utf8"));
  const suffix = `/node_modules/${dependency}`;
  const matches = Object.entries(lock.packages ?? {}).filter(([path]) =>
    path === `node_modules/${dependency}` || path.endsWith(suffix));
  return [...new Set(matches.map(([, entry]) => entry.version).filter(Boolean))];
}

function installedNpmVersion(lockfile, dependency) {
  const versions = installedNpmVersions(lockfile, dependency);
  return versions.length === 1 ? versions[0] : null;
}

export function updateNpm(finding) {
  const root = packageRoot(finding.sourcePath);
  assertOfficialNpmConfiguration(root);
  const manifestPath = join(root, "package.json");
  if (!existsSync(manifestPath)) throw new Error(`No package.json beside ${finding.sourcePath}`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const groups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  const direct = groups.find((group) => Object.hasOwn(manifest[group] ?? {}, finding.dependency));
  if (finding.malicious && !finding.fixedVersion) {
    if (!direct) throw new Error(`Malicious transitive ${finding.dependency} has no fixed version; incident opened but automatic removal is unsafe`);
    delete manifest[direct][finding.dependency];
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    packageRun("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", ...registryArgs(finding.dependency)], { cwd: root });
    return { strategy: "remove-malicious-direct", manifestPath: relative(process.cwd(), manifestPath) };
  }
  if (!finding.fixedVersion) throw new Error(`${finding.advisory} has no fixed version`);
  if (direct) {
    const current = manifest[direct][finding.dependency];
    if (typeof current !== "string" || !/^[~^]?\d/.test(current)) {
      throw new Error(`Refusing unsupported npm direct specifier for ${finding.dependency}: ${String(current)}`);
    }
    const prefix = /^[~^]/.test(current) ? current[0] : "";
    manifest[direct][finding.dependency] = `${prefix}${finding.fixedVersion}`;
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    packageRun("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", ...registryArgs(finding.dependency)], { cwd: root });
    return { strategy: "direct", manifestPath: relative(process.cwd(), manifestPath) };
  }

  packageRun("npm", ["update", finding.dependency, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", ...registryArgs(finding.dependency)], { cwd: root });
  const updated = installedNpmVersions(finding.sourcePath, finding.dependency);
  if (updated.length > 0 && !updated.includes(finding.version)) {
    return { strategy: "transitive-compatible", manifestPath: null };
  }

  // The parent range cannot reach the fix. An exact npm override is smaller
  // than an unrelated parent major bump. Scope it to the vulnerable installed
  // version so parallel, API-incompatible major lines remain untouched.
  const refreshed = JSON.parse(readFileSync(manifestPath, "utf8"));
  const selector = `${finding.dependency}@${finding.version}`;
  refreshed.overrides = { ...(refreshed.overrides ?? {}), [selector]: finding.fixedVersion };
  writeFileSync(manifestPath, `${JSON.stringify(refreshed, null, 2)}\n`);
  packageRun("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", ...registryArgs(finding.dependency)], { cwd: root });
  return { strategy: "transitive-override", manifestPath: relative(process.cwd(), manifestPath) };
}

function updateUv(finding) {
  if (!finding.fixedVersion) throw new Error(`${finding.advisory} has no fixed version`);
  const root = packageRoot(finding.sourcePath);
  const beforeLock = readFileSync(finding.sourcePath, "utf8");
  packageRun("uv", ["lock", "--no-build", "--default-index", "https://pypi.org/simple", "--upgrade-package", `${finding.dependency}>=${finding.fixedVersion}`], { cwd: root });
  return { strategy: "uv-lock", manifestPath: null, beforeLock };
}

function pnpmLock(lockfile) {
  return parse(readFileSync(lockfile, "utf8"));
}

function pnpmDirectManifests(lockfile, dependency) {
  const root = packageRoot(lockfile);
  const importers = pnpmLock(lockfile)?.importers ?? { ".": {} };
  const groups = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
  return Object.keys(importers).flatMap((importer) => {
    const manifestPath = join(root, importer === "." ? "package.json" : `${importer}/package.json`);
    if (!existsSync(manifestPath)) return [];
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    const group = groups.find((name) => Object.hasOwn(manifest[name] ?? {}, dependency));
    if (!group) return [];
    const resolution = importers[importer]?.[group]?.[dependency];
    const version = typeof resolution === "string" ? resolution : resolution?.version;
    if (typeof version !== "string" || !/^\d/.test(version)) {
      throw new Error(`Cannot identify the resolved pnpm direct version of ${dependency} in ${manifestPath}`);
    }
    return [{ manifestPath, manifest, group, version: version.split("(")[0] }];
  });
}

function installedPnpmVersions(lockfile, dependency) {
  const prefix = `${dependency}@`;
  return [...new Set(Object.keys(pnpmLock(lockfile)?.packages ?? {})
    .filter((key) => key.startsWith(prefix))
    .map((key) => key.slice(prefix.length).split("(")[0])
    .filter(Boolean))];
}

function overrideTargetsDependency(selector, dependency) {
  return selector === dependency || selector.startsWith(`${dependency}@`) ||
    selector.endsWith(`>${dependency}`) || selector.includes(`>${dependency}@`);
}

function writePnpmOverride(root, dependency, installedVersion, fixedVersion) {
  const selector = `${dependency}@${installedVersion}`;
  const workspacePath = join(root, "pnpm-workspace.yaml");
  if (existsSync(workspacePath)) {
    const document = parseDocument(readFileSync(workspacePath, "utf8"));
    // pnpm does not apply overrides transitively. An older selector may already
    // map a source release to this vulnerable installed version; update it too.
    for (const [key, value] of Object.entries(document.toJS().overrides ?? {})) {
      if (overrideTargetsDependency(key, dependency) && value === installedVersion) {
        document.setIn(["overrides", key], fixedVersion);
      }
    }
    document.setIn(["overrides", selector], fixedVersion);
    writeFileSync(workspacePath, String(document));
    return relative(process.cwd(), workspacePath);
  }
  const manifestPath = join(root, "package.json");
  if (!existsSync(manifestPath)) throw new Error(`No package.json beside ${join(root, "pnpm-lock.yaml")}`);
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const overrides = { ...(manifest.pnpm?.overrides ?? {}) };
  for (const [key, value] of Object.entries(overrides)) {
    if (overrideTargetsDependency(key, dependency) && value === installedVersion) overrides[key] = fixedVersion;
  }
  manifest.pnpm = { ...(manifest.pnpm ?? {}), overrides: { ...overrides, [selector]: fixedVersion } };
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return relative(process.cwd(), manifestPath);
}

export function updatePnpm(finding) {
  const root = packageRoot(finding.sourcePath);
  assertOfficialNpmConfiguration(root);
  const beforeLock = readFileSync(finding.sourcePath, "utf8");
  // A nested lockfile is its own project. Without this flag pnpm may discover
  // an ancestor workspace and mutate its lockfile instead of this one.
  const workspaceArgs = existsSync(join(root, "pnpm-workspace.yaml")) ? [] : ["--ignore-workspace"];
  const allDirect = pnpmDirectManifests(finding.sourcePath, finding.dependency);
  const direct = allDirect.filter((entry) => entry.version === finding.version);
  if (finding.malicious && !finding.fixedVersion) {
    if (direct.length === 0) throw new Error(`Malicious transitive ${finding.dependency} has no fixed version; incident opened but automatic removal is unsafe`);
    for (const entry of direct) {
      delete entry.manifest[entry.group][finding.dependency];
      writeFileSync(entry.manifestPath, `${JSON.stringify(entry.manifest, null, 2)}\n`);
    }
    packageRun("pnpm", ["install", "--lockfile-only", "--ignore-scripts", ...workspaceArgs, ...registryArgs(finding.dependency)], { cwd: root });
    return { strategy: "remove-malicious-direct", manifestPath: direct.map((entry) => relative(process.cwd(), entry.manifestPath)).join(","), beforeLock };
  }
  if (!finding.fixedVersion) throw new Error(`${finding.advisory} has no fixed version`);
  if (direct.length > 0) {
    for (const entry of direct) {
      const current = entry.manifest[entry.group][finding.dependency];
      if (typeof current !== "string" || !/^[~^]?\d/.test(current)) {
        throw new Error(`Refusing unsupported pnpm direct specifier for ${finding.dependency}: ${String(current)}`);
      }
      const prefix = /^[~^]/.test(current) ? current[0] : "";
      entry.manifest[entry.group][finding.dependency] = `${prefix}${finding.fixedVersion}`;
      writeFileSync(entry.manifestPath, `${JSON.stringify(entry.manifest, null, 2)}\n`);
    }
    packageRun("pnpm", ["install", "--lockfile-only", "--ignore-scripts", ...workspaceArgs, ...registryArgs(finding.dependency)], { cwd: root });
    return { strategy: "pnpm-direct", manifestPath: direct.map((entry) => relative(process.cwd(), entry.manifestPath)).join(","), beforeLock };
  }

  if (allDirect.length === 0) {
    packageRun("pnpm", ["update", `${finding.dependency}@${finding.fixedVersion}`, "--recursive", "--lockfile-only", "--ignore-scripts", ...workspaceArgs, ...registryArgs(finding.dependency)], { cwd: root });
    const updated = installedPnpmVersions(finding.sourcePath, finding.dependency);
    if (updated.length > 0 && !updated.includes(finding.version)) {
      return { strategy: "pnpm-transitive-compatible", manifestPath: null, beforeLock };
    }
  }

  const manifestPath = writePnpmOverride(root, finding.dependency, finding.version, finding.fixedVersion);
  packageRun("pnpm", ["install", "--lockfile-only", "--ignore-scripts", ...workspaceArgs, ...registryArgs(finding.dependency)], { cwd: root });
  return { strategy: "pnpm-transitive-override", manifestPath, beforeLock };
}

function replaceDirectDependency(manifestPath, dependency, replacement, version) {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  let replaced = false;
  for (const group of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    if (!Object.hasOwn(manifest[group] ?? {}, dependency)) continue;
    if (Object.hasOwn(manifest[group], replacement)) {
      throw new Error(`Replacement ${replacement} already exists in ${manifestPath}`);
    }
    delete manifest[group][dependency];
    manifest[group][replacement] = version;
    replaced = true;
  }
  if (replaced) writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return replaced;
}

/** A mapping can only replace a direct npm/pnpm dependency and its import literals. */
export function applyCompatibilityReplacement(finding, mapping, config = {}) {
  const root = packageRoot(finding.sourcePath);
  assertOfficialNpmConfiguration(root);
  const beforeLock = readFileSync(finding.sourcePath, "utf8");
  const lock = basename(finding.sourcePath);
  const workspaceArgs = existsSync(join(root, "pnpm-workspace.yaml")) ? [] : ["--ignore-workspace"];
  const manifests = lock === "pnpm-lock.yaml"
    ? pnpmDirectManifests(finding.sourcePath, finding.dependency).map((entry) => entry.manifestPath)
    : [join(root, "package.json")];
  let replaced = 0;
  for (const path of manifests) replaced += Number(replaceDirectDependency(path, finding.dependency, mapping.replacement, mapping.version));
  if (replaced === 0) {
    throw new Error(`No direct ${finding.dependency} dependency is eligible for import compatibility`);
  }
  const registry = registryArgs(mapping.replacement);
  if (lock === "pnpm-lock.yaml") {
    packageRun("pnpm", ["install", "--lockfile-only", "--ignore-scripts", ...workspaceArgs, ...registry], { cwd: root });
  } else if (lock === "package-lock.json") {
    packageRun("npm", ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", ...registry], { cwd: root });
  } else throw new Error(`Unsupported compatibility lockfile: ${lock}`);

  const changes = [];
  for (const path of run("git", ["ls-files", "-z", "--", "src", "tests"]).split("\0").filter(Boolean)) {
    if (!isAllowedCompatibilitySource(path)) continue;
    const before = readFileSync(path, "utf8");
    const after = replaceImportSpecifiers(path, before, finding.dependency, mapping.replacement);
    if (after === before) continue;
    changes.push({ path, before, after });
  }
  const importCount = validateImportCompatibility(changes, finding.dependency, mapping.replacement);
  for (const change of changes) writeFileSync(change.path, change.after);
  let generatedFiles = [];
  if (config.compatibilityGeneratedDist === true) {
    if (root !== process.cwd() || !existsSync("tsconfig.build.json") ||
        run("git", ["ls-files", "--", "dist"]).length === 0) {
      throw new Error("Committed generated dist requires a root TypeScript build and tracked dist files");
    }
    if (lock === "pnpm-lock.yaml") {
      packageRun("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts", ...registry], { cwd: root });
    } else {
      packageRun("npm", ["ci", "--ignore-scripts", "--no-audit", "--no-fund", ...registry], { cwd: root });
    }
    packageRun("pnpm", ["exec", "tsc", "-p", "tsconfig.build.json"], { cwd: root });
    if (run("git", ["ls-files", "--others", "--exclude-standard", "--", "dist"])) {
      throw new Error("TypeScript build created untracked dist files");
    }
    generatedFiles = run("git", ["diff", "--name-only", "--", "dist"]).split("\n").filter(Boolean);
    validateGeneratedDistPaths(changes.map((change) => change.path).filter((path) => path.startsWith("src/")), generatedFiles);
  }
  return { strategy: "import-only-compatibility", manifestPath: manifests.map((path) => relative(process.cwd(), path)).join(","),
    beforeLock, importFiles: changes.map((change) => change.path), importCount, generatedFiles,
    ...(config.compatibilityGeneratedDist === true ? { generatedDistDigest: generatedDistDigest() } : {}) };
}

function applyUpdate(finding) {
  const base = basename(finding.sourcePath);
  if (base === "package-lock.json") return updateNpm(finding);
  if (base === "pnpm-lock.yaml") return updatePnpm(finding);
  if (base === "uv.lock") return updateUv(finding);
  throw new Error(`No remediation adapter for ${base}; OSV detection still covers it`);
}

export function affectedVersionsForCandidate(findings, selected) {
  const seen = new Set();
  return [selected, ...findings].filter((finding) => {
    if (finding.sourcePath !== selected.sourcePath ||
        finding.ecosystem.toLowerCase() !== selected.ecosystem.toLowerCase() ||
        finding.dependency !== selected.dependency ||
        !finding.aliases.some((alias) => selected.aliases.includes(alias)) ||
        seen.has(finding.version)) return false;
    seen.add(finding.version);
    return true;
  });
}

function versionStillInstalled(finding) {
  if (basename(finding.sourcePath) === "package-lock.json") {
    return installedNpmVersions(finding.sourcePath, finding.dependency).includes(finding.version);
  }
  if (basename(finding.sourcePath) === "pnpm-lock.yaml") {
    return installedPnpmVersions(finding.sourcePath, finding.dependency).includes(finding.version);
  }
  return true;
}

export function applyAffectedUpdates(findings, selected) {
  const updates = [];
  let update;
  for (const affected of affectedVersionsForCandidate(findings, selected)) {
    if (updates.length > 0 && !versionStillInstalled(affected)) continue;
    const applied = applyUpdate(affected);
    update ??= applied;
    updates.push({ version: affected.version, fixedVersion: affected.fixedVersion, strategy: applied.strategy });
  }
  return { update, updates };
}

export function assertOfficialNpmArtifacts(lockfile, beforeText) {
  const lock = JSON.parse(readFileSync(lockfile, "utf8"));
  const before = JSON.parse(beforeText);
  for (const [path, entry] of Object.entries(lock.packages ?? {})) {
    if (!path.includes("node_modules/")) continue;
    const previous = before.packages?.[path];
    if (previous && previous.resolved === entry.resolved && previous.integrity === entry.integrity &&
        previous?.link === entry.link) continue;
    if (!entry.resolved) {
      throw new Error(`Refusing changed npm artifact without a registry URL: ${path}`);
    }
    if (!String(entry.resolved).startsWith("https://registry.npmjs.org/")) {
      throw new Error(`Refusing non-registry npm artifact at ${path}: ${entry.resolved}`);
    }
    if (!entry.integrity || !/^sha(?:256|384|512)-/.test(entry.integrity)) {
      throw new Error(`Refusing npm artifact without a recognized integrity hash: ${path}`);
    }
  }
}

function officialPnpmRelease(key) {
  const separator = key.lastIndexOf("@");
  const dependency = key.slice(0, separator);
  const version = key.slice(separator + 1).split("(")[0];
  if (separator <= 0 || !dependency || !version) throw new Error(`Cannot resolve pnpm package identity: ${key}`);
  const output = packageRun("npm", ["view", `${dependency}@${version}`, "dist.integrity", "dist.tarball", "--json", ...registryArgs(dependency)]);
  const metadata = JSON.parse(output);
  return {
    integrity: metadata.integrity ?? metadata["dist.integrity"],
    tarball: metadata.tarball ?? metadata["dist.tarball"],
  };
}

export function assertOfficialPnpmArtifacts(lockfile, beforeText, releaseLookup = officialPnpmRelease) {
  const before = parse(beforeText)?.packages ?? {};
  const after = pnpmLock(lockfile)?.packages ?? {};
  for (const [key, entry] of Object.entries(after)) {
    if (JSON.stringify(before[key]) === JSON.stringify(entry)) continue;
    const resolution = entry?.resolution;
    if (!resolution || typeof resolution !== "object") {
      throw new Error(`Refusing changed pnpm artifact without resolution metadata: ${key}`);
    }
    if (resolution.tarball) {
      const url = new URL(resolution.tarball);
      if (url.protocol !== "https:" || url.hostname !== "registry.npmjs.org") {
        throw new Error(`Refusing non-registry pnpm artifact at ${key}: ${resolution.tarball}`);
      }
    }
    if (typeof resolution.integrity !== "string" || !/^sha(?:256|384|512)-/.test(resolution.integrity)) {
      throw new Error(`Refusing pnpm artifact without a recognized integrity hash: ${key}`);
    }
    const official = releaseLookup(key);
    if (official?.integrity !== resolution.integrity) {
      throw new Error(`Refusing pnpm artifact whose integrity does not match registry.npmjs.org: ${key}`);
    }
    if (resolution.tarball && official?.tarball !== resolution.tarball) {
      throw new Error(`Refusing pnpm artifact whose tarball does not match registry.npmjs.org: ${key}`);
    }
  }
}

function uvPackages(lockText) {
  return lockText.split(/^\[\[package\]\]\s*$/m).slice(1).map((block) => {
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"$/m.exec(block)?.[1] ?? "";
    const source = /^source = (.+)$/m.exec(block)?.[1] ?? "workspace";
    if (!name) throw new Error("uv.lock package is missing a name");
    return { name, version, source, block };
  });
}

export function assertOfficialUvArtifacts(lockfile, beforeText) {
  const before = uvPackages(beforeText);
  const after = uvPackages(readFileSync(lockfile, "utf8"));
  for (const entry of after) {
    const previous = before.find((candidate) => candidate.name === entry.name &&
      candidate.version === entry.version && candidate.source === entry.source);
    if (previous?.block === entry.block) continue;
    if (entry.source !== '{ registry = "https://pypi.org/simple" }') {
      if (previous) continue; // Existing workspace/path identity; only dependency edges changed.
      throw new Error(`Refusing changed uv artifact from a non-PyPI source: ${entry.name}`);
    }
    const artifacts = [...entry.block.matchAll(/\{\s*url = "([^"]+)"([^}]*)\}/g)];
    const urlFields = [...entry.block.matchAll(/url = "[^"]+"/g)];
    if (artifacts.length === 0 || artifacts.length !== urlFields.length) {
      throw new Error(`Refusing changed PyPI package without complete artifact metadata: ${entry.name}`);
    }
    for (const artifact of artifacts) {
      const url = new URL(artifact[1]);
      if (url.protocol !== "https:" || !["files.pythonhosted.org", "pypi.org"].includes(url.hostname)) {
        throw new Error(`Refusing changed uv artifact from a non-PyPI host: ${entry.name}`);
      }
      if (!/hash = "sha256:[a-f0-9]{64}"/.test(artifact[2])) {
        throw new Error(`Refusing changed PyPI artifact without a sha256 hash: ${entry.name}`);
      }
    }
  }
}

function prepare() {
  const repo = targetRepository();
  const scanFile = required("SCAN_FILE");
  const planFile = required("PLAN_FILE");
  const config = loadConfig();
  const osv = findingsFromOsvJson(JSON.parse(readFileSync(scanFile, "utf8")));
  const findings = combineFindings(osv, dependabotFindings(repo));
  for (const finding of findings) {
    if (finding.version === "unknown" && basename(finding.sourcePath) === "package-lock.json") {
      finding.version = installedNpmVersion(finding.sourcePath, finding.dependency) ?? "unknown";
    }
  }
  const open = openSecurityPulls(repo);

  for (const finding of findings.filter((candidate) => candidate.malicious)) {
    finding.incidentUrl = upsertMalwareIncident(repo, finding, findings);
  }

  const ordinary = nextCandidate(findings, config, open);
  const compatibility = ordinary ? null : nextCompatibilityCandidate(findings, loadCompatibilityMappings(), config, open);
  const finding = ordinary ?? compatibility?.finding;
  if (!finding) {
    const unpatched = findings.filter((candidate) => !candidate.fixedVersion && !candidate.malicious);
    writeFileSync(planFile, JSON.stringify({ status: findings.length ? "waiting" : "clean", findings, unpatched, open: open.map((pr) => pr.html_url) }, null, 2));
    output("changed", "false");
    summary(findings.length ? `## Security remediation\n\nNo new PR: ${open.length} bot PR(s) already cover available lockfiles, project holds apply, or no fixed version is published for ${unpatched.length} finding(s). These findings remain open.` : "## Security remediation\n\nOSV and GitHub advisory inputs are clean.");
    return;
  }

  const beforeLock = ["package-lock.json", "pnpm-lock.yaml"].includes(basename(finding.sourcePath))
    ? readFileSync(finding.sourcePath, "utf8") : null;
  const { update, updates } = compatibility
    ? { update: applyCompatibilityReplacement(finding, compatibility.mapping, config), updates: [] }
    : applyAffectedUpdates(findings, finding);
  const changedFiles = run("git", ["diff", "--name-only"]).split("\n").filter(Boolean);
  const importFiles = compatibility ? update.importFiles : [];
  const generatedFiles = compatibility ? update.generatedFiles : [];
  if (!isSecurityDependencyOnly(changedFiles.filter((path) => !importFiles.includes(path) && !generatedFiles.includes(path))) ||
      (compatibility && (![...importFiles, ...generatedFiles].every((path) => changedFiles.includes(path)) ||
        (generatedFiles.length > 0 && !config.compatibilityGeneratedDist)))) {
    throw new Error(`Updater changed a disallowed path: ${changedFiles.join(", ")}`);
  }
  if (!changedFiles.includes(finding.sourcePath)) throw new Error(`Updater did not change ${finding.sourcePath}`);
  if (beforeLock && basename(finding.sourcePath) === "package-lock.json") {
    assertOfficialNpmArtifacts(finding.sourcePath, beforeLock);
  }
  if (beforeLock && basename(finding.sourcePath) === "pnpm-lock.yaml") {
    assertOfficialPnpmArtifacts(finding.sourcePath, beforeLock);
  }
  if (update.beforeLock) {
    assertOfficialUvArtifacts(finding.sourcePath, update.beforeLock);
    delete update.beforeLock;
  }
  const plan = { status: "prepared", finding, update, updates, changedFiles,
    ...(compatibility ? { compatibility: compatibility.mapping } : {}), beforeSha: run("git", ["rev-parse", "HEAD"]) };
  mkdirSync(dirname(planFile), { recursive: true });
  writeFileSync(planFile, `${JSON.stringify(plan, null, 2)}\n`);
  output("changed", "true");
  output("dependency", slug(finding.dependency));
  output("advisory", slug(finding.advisory));
}

function ensureSecurityLabels(repo) {
  for (const label of [
    ["security", "b60205", "Security remediation"],
    ["dependencies", "0366d6", "Dependency changes"],
    ["automated-security", "1f883d", "Created by Morpheus Security"],
  ]) ensureLabel(repo, ...label);
}

export function requiredChecksReady(rollup, requiredChecks) {
  if (!Array.isArray(requiredChecks) || requiredChecks.length === 0) {
    return { ready: false, reason: "no explicit requiredChecks policy" };
  }
  for (const requiredCheck of requiredChecks) {
    const matches = (rollup ?? []).filter((check) => (check.name ?? check.context) === requiredCheck);
    if (matches.length === 0) return { ready: false, reason: `required check is missing: ${requiredCheck}` };
    const successfulCheckIds = matches.filter((check) =>
      check.status === "COMPLETED" && check.conclusion === "SUCCESS" && Number.isFinite(Number(check.id)))
      .map((check) => Number(check.id));
    const latestSuccessfulCheckId = successfulCheckIds.length ? Math.max(...successfulCheckIds) : null;
    const accepted = matches.every((check) => {
      if (check.status !== "COMPLETED") return check.state === "SUCCESS";
      if (check.conclusion === "SUCCESS") return true;
      return ["CANCELLED", "SKIPPED", "NEUTRAL"].includes(check.conclusion) &&
        latestSuccessfulCheckId != null && Number(check.id) < latestSuccessfulCheckId;
    });
    const hasSuccess = matches.some((check) =>
      check.status === "COMPLETED" ? check.conclusion === "SUCCESS" : check.state === "SUCCESS");
    if (!accepted || !hasSuccess) return { ready: false, reason: `required check has not passed: ${requiredCheck}` };
  }
  return { ready: true, reason: "all explicit required checks passed" };
}

export function staleCandidateAction(mergeStateStatus) {
  const state = String(mergeStateStatus ?? "unknown").toUpperCase();
  if (state === "BEHIND" || state === "DIRTY") return "recreate";
  if (state === "UNKNOWN") return "wait";
  return "continue";
}

export function restCheckRollup(checkRuns, commitStatuses) {
  const latestStatuses = new Map();
  for (const status of commitStatuses ?? []) {
    const current = latestStatuses.get(status.context);
    if (!current || Number(status.id ?? 0) > Number(current.id ?? 0)) latestStatuses.set(status.context, status);
  }
  return [
    ...(checkRuns ?? []).map((check) => ({
      id: check.id,
      name: check.name,
      status: String(check.status ?? "").toUpperCase(),
      conclusion: check.conclusion == null ? null : String(check.conclusion).toUpperCase(),
    })),
    ...[...latestStatuses.values()].map((status) => ({
      context: status.context,
      state: String(status.state ?? "").toUpperCase(),
    })),
  ];
}

export function restMergeReadiness(pull, checkPages, statusPages) {
  return {
    mergeStateStatus: pull?.mergeable == null ? "unknown" : pull.mergeable_state,
    statusCheckRollup: restCheckRollup(
      (checkPages ?? []).flatMap((page) => page.check_runs ?? []),
      (statusPages ?? []).flatMap((page) => page),
    ),
  };
}

function mergeReadiness(repo, prNumber, headSha) {
  const pull = gh(["api", `repos/${repo}/pulls/${prNumber}`]);
  const checkPages = gh(["api", "--paginate", "--slurp",
    `repos/${repo}/commits/${headSha}/check-runs?per_page=100`]);
  const statusPages = gh(["api", "--paginate", "--slurp",
    `repos/${repo}/commits/${headSha}/statuses?per_page=100`]);
  return restMergeReadiness(pull, checkPages, statusPages);
}

export function verifiedCandidateAttestation(checkRuns, botSlug, headSha, repo) {
  const candidates = (checkRuns ?? []).filter((check) =>
    check.name === CANDIDATE_CHECK && check.head_sha === headSha && check.app?.slug === botSlug &&
    check.status === "completed" && check.conclusion === "success");
  for (const check of candidates.sort((left, right) => Number(right.id ?? 0) - Number(left.id ?? 0))) {
    try {
      const receipt = JSON.parse(check.output?.summary ?? "");
      if ([1, 2].includes(receipt.version) && receipt.repository === repo && receipt.headSha === headSha &&
          typeof receipt.dependency === "string" && receipt.dependency.length > 0 &&
          typeof receipt.advisory === "string" && Array.isArray(receipt.aliases) &&
          receipt.aliases.every((alias) => typeof alias === "string") &&
          typeof receipt.sourcePath === "string" && receipt.sourcePath.length > 0 &&
          (receipt.version === 1 || (receipt.mode === "import-only-compatibility" &&
            typeof receipt.replacement === "string" && Array.isArray(receipt.importFiles) &&
            receipt.importFiles.length >= 1 && receipt.importFiles.length <= 8 &&
            Array.isArray(receipt.generatedFiles) && receipt.generatedFiles.length <= 32 &&
            Number.isInteger(receipt.importCount) && receipt.importCount >= 1 && receipt.importCount <= 20))) {
        return receipt;
      }
    } catch {
      // Ignore malformed or unrelated check output and fail closed below.
    }
  }
  return null;
}

export function verifiedIndependentReview(comments, repo, prNumber, headSha) {
  for (const comment of [...(comments ?? [])].reverse()) {
    if (comment.user?.login !== "morpheus-gh-manager[bot]" ||
        comment.performed_via_github_app?.slug !== "morpheus-gh-manager") continue;
    const marker = /^<!-- morpheus-security-review (\{[^\n]*\}) -->$/m.exec(comment.body ?? "");
    if (!marker) continue;
    try {
      const record = JSON.parse(marker[1]);
      if (record.version === 1 && record.repository === repo && record.pr === prNumber &&
          record.headSha === headSha && record.verdict === "clear") return record;
    } catch { /* Malformed comments do not clear a candidate. */ }
  }
  return null;
}

function createCandidateAttestation(repo, finding, headSha, plan) {
  const receipt = JSON.stringify({
    version: plan.compatibility ? 2 : 1,
    repository: repo,
    headSha,
    dependency: finding.dependency,
    advisory: finding.advisory,
    aliases: finding.aliases,
    sourcePath: finding.sourcePath,
    ...(plan.compatibility ? { mode: "import-only-compatibility", replacement: plan.compatibility.replacement,
      importFiles: plan.update.importFiles, importCount: plan.update.importCount,
      generatedFiles: plan.update.generatedFiles } : {}),
  });
  gh(["api", "--method", "POST", `repos/${repo}/check-runs`,
    "-f", `name=${CANDIDATE_CHECK}`,
    "-f", `head_sha=${headSha}`,
    "-f", "status=completed",
    "-f", "conclusion=success",
    "-f", "output[title]=Validated security dependency candidate",
    "-f", `output[summary]=${receipt}`]);
}

function deliver() {
  const repo = targetRepository();
  const botLogin = required("BOT_LOGIN");
  const defaultBranch = required("DEFAULT_BRANCH");
  const plan = JSON.parse(readFileSync(required("PLAN_FILE"), "utf8"));
  const after = findingsFromOsvJson(JSON.parse(readFileSync(required("AFTER_SCAN_FILE"), "utf8")));
  const finding = plan.finding;
  const remains = after.some((candidate) => candidate.sourcePath === finding.sourcePath &&
    candidate.dependency === finding.dependency &&
    candidate.aliases.some((alias) => finding.aliases.includes(alias)));
  if (remains) throw new Error(`${finding.advisory} remains after the candidate update`);

  const changedFiles = run("git", ["diff", "--name-only"]).split("\n").filter(Boolean);
  const importFiles = plan.compatibility ? plan.update.importFiles : [];
  const generatedFiles = plan.compatibility ? plan.update.generatedFiles : [];
  if (JSON.stringify(changedFiles.sort()) !== JSON.stringify([...plan.changedFiles].sort()) ||
      !isSecurityDependencyOnly(changedFiles.filter((path) => !importFiles.includes(path) && !generatedFiles.includes(path))) ||
      (plan.compatibility && (!loadConfig().importOnlyCompatibility ||
        ![...importFiles, ...generatedFiles].every((path) => changedFiles.includes(path))))) {
    throw new Error("Candidate diff changed between preparation and delivery");
  }
  if (plan.compatibility) {
    if (generatedFiles.length > 0) {
      if (!loadConfig().compatibilityGeneratedDist) throw new Error("Generated dist opt-in was removed");
      validateGeneratedDistPaths(importFiles.filter((path) => path.startsWith("src/")), generatedFiles);
      if (generatedDistDigest() !== plan.update.generatedDistDigest) throw new Error("Generated dist changed after preparation");
    }
    const changes = importFiles.map((path) => ({
      path,
      before: execFileSync("git", ["show", `${plan.beforeSha}:${path}`], { encoding: "utf8" }),
      after: readFileSync(path, "utf8"),
    }));
    if (validateImportCompatibility(changes, finding.dependency, plan.compatibility.replacement) !== plan.update.importCount) {
      throw new Error("Import compatibility proof changed after preparation");
    }
  }
  if (process.env.DRY_RUN === "true") {
    summary(`## Security remediation dry run\n\nValidated ${finding.dependency}: scoped diff, official artifacts, and clean candidate rescan.`);
    return;
  }
  const branch = `morpheus-security/${slug(finding.ecosystem)}-${slug(finding.dependency)}-${slug(finding.advisory)}-${plan.beforeSha.slice(0, 8)}`;
  run("git", ["config", "user.name", botLogin]);
  run("git", ["config", "user.email", `${botLogin.replace(/\[bot\]$/, "")}[bot]@users.noreply.github.com`]);
  run("git", ["switch", "-c", branch]);
  run("git", ["add", "--", ...changedFiles]);
  run("git", ["commit", "-m", `fix(deps): remediate ${finding.dependency} ${finding.advisory}`,
    "-m", "Co-authored-by: Codex <codex@cpheinrich.com>"]);
  const candidateHead = run("git", ["rev-parse", "HEAD"]);
  run("gh", ["auth", "setup-git"]);
  run("git", ["push", "--set-upstream", "origin", branch]);
  createCandidateAttestation(repo, finding, candidateHead, plan);
  ensureSecurityLabels(repo);
  const incident = finding.incidentUrl ? `\nRelated incident: ${finding.incidentUrl}` : "";
  const updateLines = (plan.updates ?? [{ version: finding.version, fixedVersion: finding.fixedVersion, strategy: plan.update.strategy }])
    .map((entry) => `- Update \`${entry.version}\` to the smallest available fixed line, \`${entry.fixedVersion ?? "removed"}\`, using \`${entry.strategy}\`.`)
    .join("\n");
  const body = `${SECURITY_MARKER}\n\n## Summary\n\n` +
    `Dependency: \`${finding.dependency}\`\n\nLockfile: \`${finding.sourcePath}\`\n\n` +
    `Advisories: ${finding.aliases.map((alias) => `\`${alias}\``).join(", ")}\n\n` +
    `- Remediate ${finding.advisory} (${finding.aliases.join(", ")}).\n` +
    `${plan.compatibility ? `- Replace direct \`${finding.dependency}\` with exact registry release \`${plan.compatibility.replacement}@${plan.compatibility.version}\`; only ${plan.update.importCount} import literals in ${plan.update.importFiles.length} source files changed.\n` : `${updateLines}\n`}` +
    `- OSV rescanned the candidate and no longer reports this package/advisory pair.\n` +
    `- Registry URLs and lockfile integrity hashes passed the deterministic supply-chain gate.\n` +
    `- Candidate head: \`${candidateHead}\`.${incident}\n\n` +
    `## Test plan\n\nThe configured required checks must pass before a later reconciliation run merges this PR.\n\n` +
    `## Open questions\n\nNone.\n`;
  const url = run("gh", ["pr", "create", "--repo", repo, "--base", defaultBranch, "--head", branch,
    "--title", `fix(deps): remediate ${finding.dependency} security advisory`, "--body", body,
    "--label", "security", "--label", "dependencies", "--label", "automated-security"]);
  output("pull_request", url);
  summary(`## Security remediation\n\nOpened ${url} for ${finding.dependency}. A later run will merge it only after the explicit required checks pass.`);
}

function reconcile() {
  const repo = targetRepository();
  const defaultBranch = required("DEFAULT_BRANCH");
  const config = loadConfig();
  const checkedOutSha = run("git", ["rev-parse", "HEAD"]);
  const initialLiveSha = run("gh", ["api", `repos/${repo}/commits/${defaultBranch}`, "--jq", ".sha"]);
  if (checkedOutSha !== initialLiveSha) {
    summary(`- Reconciliation stopped because ${defaultBranch} changed after checkout.`);
    output("open_prs", "0");
    output("merged", "false");
    return;
  }
  const open = openSecurityPulls(repo);
  let merged = false;
  for (const pr of open) {
    const headSha = pr.head?.sha;
    if (!/^[0-9a-f]{40}$/.test(headSha ?? "")) {
      summary(`- ${pr.html_url}: not merged because its head is invalid.`);
      continue;
    }
    const checkRuns = gh(["api", `repos/${repo}/commits/${headSha}/check-runs?check_name=${encodeURIComponent(CANDIDATE_CHECK)}`]);
    const botSlug = required("BOT_LOGIN").replace(/\[bot\]$/, "");
    const attestation = verifiedCandidateAttestation(checkRuns?.check_runs, botSlug, headSha, repo);
    if (!attestation) {
      summary(`- ${pr.html_url}: not merged because no valid App-owned candidate attestation covers its head.`);
      continue;
    }
    if (attestation.mode === "import-only-compatibility") {
      const mapping = loadCompatibilityMappings().find((entry) =>
        entry.dependency === attestation.dependency && entry.replacement === attestation.replacement &&
        [attestation.advisory, ...attestation.aliases].includes(entry.advisory));
      if (!config.importOnlyCompatibility || !mapping) {
        summary(`- ${pr.html_url}: not merged because the import-only opt-in or reviewed mapping is absent.`);
        continue;
      }
      const pages = gh(["api", "--paginate", "--slurp", `repos/${repo}/issues/${pr.number}/comments?per_page=100`]);
      if (!verifiedIndependentReview((pages ?? []).flatMap((page) => page), repo, pr.number, headSha)) {
        summary(`- ${pr.html_url}: waiting for a separate Manager App review of this exact head.`);
        continue;
      }
    }
    if (held({ dependency: attestation.dependency, aliases: attestation.aliases }, config)) {
      summary(`- ${pr.html_url}: not merged because of the current project hold.`);
      continue;
    }
    const detail = mergeReadiness(repo, pr.number, headSha);
    const staleAction = staleCandidateAction(detail?.mergeStateStatus);
    if (staleAction === "recreate") {
      run("gh", ["pr", "close", String(pr.number), "--repo", repo, "--delete-branch"]);
      summary(`- ${pr.html_url}: closed because its base is stale or conflicted; this run will recreate the candidate from current main and require fresh validation.`);
      continue;
    }
    if (staleAction === "wait") {
      summary(`- ${pr.html_url}: waiting because GitHub has not resolved its merge state.`);
      continue;
    }
    const readiness = requiredChecksReady(detail?.statusCheckRollup, config.requiredChecks);
    if (!readiness.ready) {
      summary(`- ${pr.html_url}: waiting; ${readiness.reason}.`);
      continue;
    }
    const liveSha = run("gh", ["api", `repos/${repo}/commits/${defaultBranch}`, "--jq", ".sha"]);
    if (liveSha !== checkedOutSha) {
      summary(`- ${pr.html_url}: not merged because ${defaultBranch} changed during reconciliation.`);
      break;
    }
    try {
      run("gh", ["pr", "merge", String(pr.number), "--repo", repo, "--match-head-commit", headSha,
        "--squash", "--delete-branch"]);
      merged = true;
      summary(`- ${pr.html_url}: merged after every explicit required check passed.`);
      break;
    } catch (error) {
      summary(`- ${pr.html_url}: merge rejected by GitHub (${String(error.stderr ?? error.message).trim()})`);
    }
  }
  output("open_prs", String(open.length));
  output("merged", String(merged));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const command = process.argv[2];
  if (command === "prepare") prepare();
  else if (command === "deliver") deliver();
  else if (command === "reconcile") reconcile();
  else throw new Error("Usage: security-remediation.mjs prepare|deliver|reconcile");
}
