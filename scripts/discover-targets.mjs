#!/usr/bin/env node
import { createSign } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const API = "https://api.github.com";
const CONFIG_PATH = ".github/morpheus-security.json";
const APPROVED_PATH = "config/approved-repositories.json";

function base64url(value) {
  return Buffer.from(value).toString("base64url");
}

export function appJwt(appId, privateKey, now = Math.floor(Date.now() / 1000)) {
  if (!/^\d+$/.test(String(appId))) throw new Error("MORPHEUS_SECURITY_APP_ID must be numeric");
  if (!String(privateKey).includes("PRIVATE KEY")) throw new Error("MORPHEUS_SECURITY_PRIVATE_KEY must be a PEM private key");
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = base64url(JSON.stringify({ iat: now - 60, exp: now + 540, iss: String(appId) }));
  const unsigned = `${header}.${payload}`;
  const signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  signer.end();
  return `${unsigned}.${signer.sign(privateKey, "base64url")}`;
}

async function request(fetchImpl, path, token, options = {}) {
  const response = await fetchImpl(`${API}${path}`, {
    ...options,
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.headers ?? {}),
    },
  });
  if (options.allowNotFound && response.status === 404) return null;
  if (!response.ok) throw new Error(`GitHub API ${options.method ?? "GET"} ${path} failed with ${response.status}`);
  if (response.status === 204) return null;
  return response.json();
}

async function paginated(fetchImpl, path, token, field = null) {
  const values = [];
  for (let page = 1; ; page += 1) {
    const separator = path.includes("?") ? "&" : "?";
    const body = await request(fetchImpl, `${path}${separator}per_page=100&page=${page}`, token);
    const entries = field ? body[field] : body;
    if (!Array.isArray(entries)) throw new Error(`Unexpected paginated response for ${path}`);
    values.push(...entries);
    if (entries.length < 100) return values;
  }
}

function validateConfig(config, repository) {
  if (config?.version !== 1 || !Array.isArray(config.holds) ||
      !Array.isArray(config.requiredChecks) ||
      !config.requiredChecks.every((name) => typeof name === "string" && name.trim() === name && name.length > 0) ||
      !(config.incidentRepository === null || typeof config.incidentRepository === "string")) {
    throw new Error(`${repository} has an invalid ${CONFIG_PATH}`);
  }
}

export function approvedRepositories(path = APPROVED_PATH) {
  const repositories = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(repositories) ||
      !repositories.every((repository) => /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/.test(repository)) ||
      new Set(repositories).size !== repositories.length) {
    throw new Error(`${path} must contain unique owner/name repository strings`);
  }
  return repositories;
}

export async function discoverTargets({
  appId,
  privateKey,
  approved = [],
  fetchImpl = fetch,
  now,
  warn = () => {},
} = {}) {
  const jwt = appJwt(appId, privateKey, now);
  const approvedSet = new Set(approved);
  const installations = await paginated(fetchImpl, "/app/installations", jwt);
  const targets = [];
  for (const installation of installations) {
    if (installation.suspended_at) continue;
    const tokenBody = await request(fetchImpl, `/app/installations/${installation.id}/access_tokens`, jwt, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ permissions: { contents: "read" } }),
    });
    const token = tokenBody.token;
    try {
      const repositories = await paginated(fetchImpl, "/installation/repositories", token, "repositories");
      for (const repository of repositories) {
        if (!approvedSet.has(repository.full_name)) continue;
        const configBody = await request(fetchImpl,
          `/repos/${repository.full_name}/contents/${CONFIG_PATH}?ref=${encodeURIComponent(repository.default_branch)}`,
          token, { allowNotFound: true });
        if (!configBody) continue;
        if (configBody.type !== "file" || configBody.encoding !== "base64") {
          throw new Error(`${repository.full_name} returned an invalid ${CONFIG_PATH}`);
        }
        try {
          const config = JSON.parse(Buffer.from(configBody.content, "base64").toString("utf8"));
          validateConfig(config, repository.full_name);
        } catch {
          warn(`${repository.full_name} was skipped because ${CONFIG_PATH} is invalid`);
          continue;
        }
        targets.push({
          repository: repository.full_name,
          owner: repository.owner.login,
          name: repository.name,
          defaultBranch: repository.default_branch,
        });
      }
    } finally {
      await request(fetchImpl, "/installation/token", token, { method: "DELETE" });
    }
  }
  return targets.sort((left, right) => left.repository.localeCompare(right.repository));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const targets = await discoverTargets({
    appId: process.env.MORPHEUS_SECURITY_APP_ID,
    privateKey: process.env.MORPHEUS_SECURITY_PRIVATE_KEY,
    approved: approvedRepositories(),
    warn: (message) => process.stderr.write(`::warning title=Morpheus Security discovery::${message}\n`),
  });
  if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required");
  appendFileSync(process.env.GITHUB_OUTPUT, `targets=${JSON.stringify(targets)}\n`);
  process.stdout.write(`Discovered ${targets.length} opted-in repositories.\n`);
}
