/** All callers read the same fail-closed, committed repository opt-in. */
export function validateSecurityConfig(config) {
  if (config?.version !== 1 || !Array.isArray(config.holds) ||
      !Array.isArray(config.requiredChecks) ||
      !config.requiredChecks.every((name) => typeof name === "string" && name.trim() === name && name.length > 0) ||
      config.incidentRepository != null ||
      (config.importOnlyCompatibility !== undefined && typeof config.importOnlyCompatibility !== "boolean") ||
      (config.compatibilityGeneratedDist !== undefined && typeof config.compatibilityGeneratedDist !== "boolean") ||
      (config.compatibilityGeneratedDist === true && config.importOnlyCompatibility !== true)) {
    throw new Error("Security config must explicitly define version 1 and valid holds/requiredChecks arrays; compatibility options must be valid booleans");
  }
  return { ...config, importOnlyCompatibility: config.importOnlyCompatibility === true,
    compatibilityGeneratedDist: config.compatibilityGeneratedDist === true };
}
