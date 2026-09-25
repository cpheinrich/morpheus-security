#!/usr/bin/env node
import { createSign } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const API = "https://api.github.com";
const CONFIG_PATH = ".github/morpheus-security.json";
const APPROVED_PATH = "config/approved-repositories.json";
const REPOSITORY = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;

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

function validateConfig(config, approved) {
  if (config?.version !== 1 || !Array.isArray(config.holds) ||
      !Array.isArray(config.requiredChecks) ||
      !config.requiredChecks.every((name) => typeof name === "string" && name.trim() === name && name.length > 0) ||
      config.incidentRepository != null) {
    throw new Error(`${approved.repository} has an invalid or unapproved ${CONFIG_PATH}`);
  }
}

export function approvedRepositories(path = APPROVED_PATH) {
  const entries = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(entries) || entries.length === 0 || entries.some((entry) =>
    !entry || !REPOSITORY.test(entry.repository ?? "") || Object.keys(entry).some((key) => key !== "repository")) ||
    new Set(entries.map((entry) => entry.repository)).size !== entries.length) {
    throw new Error(`${path} must contain unique repository entries`);
  }
  return entries;
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
  const targets = [];
  for (const entry of approved) {
    let token = null;
    try {
      const installation = await request(fetchImpl, `/repos/${entry.repository}/installation`, jwt, {
        allowNotFound: true,
      });
      if (!installation || installation.suspended_at) {
        warn(`${entry.repository} was skipped because the App installation is unavailable`);
        continue;
      }
      const [, name] = entry.repository.split("/");
      const tokenBody = await request(fetchImpl, `/app/installations/${installation.id}/access_tokens`, jwt, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repositories: [name], permissions: { contents: "read" } }),
      });
      token = tokenBody.token;
      const repository = await request(fetchImpl, `/repos/${entry.repository}`, token);
      const configBody = await request(fetchImpl,
        `/repos/${entry.repository}/contents/${CONFIG_PATH}?ref=${encodeURIComponent(repository.default_branch)}`,
        token, { allowNotFound: true });
      if (!configBody) continue;
      if (configBody.type !== "file" || configBody.encoding !== "base64") {
        throw new Error(`${entry.repository} returned an invalid ${CONFIG_PATH}`);
      }
      const config = JSON.parse(Buffer.from(configBody.content, "base64").toString("utf8"));
      validateConfig(config, entry);
      const [owner, repositoryName] = entry.repository.split("/");
      targets.push({
        repository: entry.repository,
        owner,
        name: repositoryName,
        defaultBranch: repository.default_branch,
      });
    } catch (error) {
      warn(`${entry.repository} was skipped: ${String(error.message ?? error)}`);
    } finally {
      if (token) {
        try {
          await request(fetchImpl, "/installation/token", token, { method: "DELETE" });
        } catch {
          warn(`${entry.repository} discovery token could not be revoked and will expire automatically`);
        }
      }
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
