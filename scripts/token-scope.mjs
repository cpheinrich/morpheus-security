#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export function tokenRepositories(config, targetRepository) {
  const [owner, repository, extra] = targetRepository.split("/");
  if (!owner || !repository || extra) throw new Error("TARGET_REPOSITORY must be owner/name");
  if (config?.version !== 1 || !Array.isArray(config.holds ?? [])) {
    throw new Error("Security config must have version 1 and an optional holds array");
  }
  const repositories = [repository];
  if (config.incidentRepository) {
    const [incidentOwner, incidentRepository, incidentExtra] = config.incidentRepository.split("/");
    if (!incidentOwner || !incidentRepository || incidentExtra || incidentOwner !== owner) {
      throw new Error("incidentRepository must be owner/name under the target repository owner");
    }
    repositories.push(incidentRepository);
  }
  return [...new Set(repositories)];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const path = process.env.CONFIG_FILE ?? ".github/morpheus-security.json";
  const config = existsSync(path)
    ? JSON.parse(readFileSync(path, "utf8"))
    : { version: 1, holds: [], incidentRepository: null };
  const repositories = tokenRepositories(config, process.env.TARGET_REPOSITORY ?? "");
  if (!process.env.GITHUB_OUTPUT) throw new Error("GITHUB_OUTPUT is required");
  appendFileSync(process.env.GITHUB_OUTPUT, `repositories<<EOF\n${repositories.join("\n")}\nEOF\n`);
}
