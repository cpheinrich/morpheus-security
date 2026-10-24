/** All callers read the same fail-closed, committed repository opt-in. */
export function validateSecurityConfig(config) {
  if (config?.version !== 1 || !Array.isArray(config.holds) ||
      !Array.isArray(config.requiredChecks) ||
      !config.requiredChecks.every((name) => typeof name === "string" && name.trim() === name && name.length > 0) ||
      config.incidentRepository != null ||
      (config.importOnlyCompatibility !== undefined && typeof config.importOnlyCompatibility !== "boolean")) {
    throw new Error("Security config must explicitly define version 1 and valid holds/requiredChecks arrays; importOnlyCompatibility must be boolean when present");
  }
  return { ...config, importOnlyCompatibility: config.importOnlyCompatibility === true };
}
