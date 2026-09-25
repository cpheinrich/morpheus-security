#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const NAME = /^(?!\.{1,2}$)[A-Za-z0-9._-]{1,100}$/;

function parseRepository(value, label) {
  const [owner, name, extra] = String(value ?? "").split("/");
  if (!OWNER.test(owner ?? "") || !NAME.test(name ?? "") || extra) {
    throw new Error(`${label} must be a safe GitHub owner/name`);
  }
  return { owner, name, repository: `${owner}/${name}` };
}

export function validateTargetScope(config, targetRepository, targetOwner, targetName) {
  const target = parseRepository(targetRepository, "TARGET_REPOSITORY");
  if (target.owner !== targetOwner || target.name !== targetName) {
    throw new Error("Target owner/name inputs do not match TARGET_REPOSITORY");
  }
  if (config?.version !== 1 || !Array.isArray(config.holds) || !Array.isArray(config.requiredChecks) ||
      !config.requiredChecks.every((name) => typeof name === "string" && name.trim() === name && name.length > 0)) {
    throw new Error("Security config must explicitly define version 1 and valid holds/requiredChecks arrays");
  }
  if (config.incidentRepository != null) {
    throw new Error("incidentRepository routing is unsupported; incidents are filed in the target repository");
  }
  return { target: target.repository };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const path = process.env.CONFIG_FILE ?? ".github/morpheus-security.json";
  if (!existsSync(path)) throw new Error(`Required opt-in policy is missing: ${path}`);
  const config = JSON.parse(readFileSync(path, "utf8"));
  validateTargetScope(
    config,
    process.env.TARGET_REPOSITORY,
    process.env.TARGET_OWNER,
    process.env.TARGET_NAME,
  );
}
