import { readFileSync } from "node:fs";

const PACKAGE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const ADVISORY = /^[A-Z][A-Z0-9]{1,31}-[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;

/** Engine-owned mappings are reviewed code, not a target PR's untrusted proposal. */
export function validateCompatibilityMappings(value) {
  if (!Array.isArray(value)) throw new Error("Compatibility mappings must be an array");
  const seen = new Set();
  for (const mapping of value) {
    if (!mapping || Object.keys(mapping).sort().join(",") !== "advisory,dependency,replacement,version" ||
        !ADVISORY.test(mapping.advisory) || !PACKAGE.test(mapping.dependency) ||
        !PACKAGE.test(mapping.replacement) || mapping.dependency === mapping.replacement ||
        !VERSION.test(mapping.version)) {
      throw new Error("Compatibility mapping needs one advisory, distinct registry packages and an exact version");
    }
    const key = `${mapping.advisory}:${mapping.dependency}`;
    if (seen.has(key)) throw new Error(`Duplicate compatibility mapping: ${key}`);
    seen.add(key);
  }
  return value;
}

export function loadCompatibilityMappings() {
  return validateCompatibilityMappings(JSON.parse(readFileSync(new URL("../config/compatibility-replacements.json", import.meta.url), "utf8")));
}

export function compatibilityMappingFor(finding, mappings) {
  if (finding.malicious || finding.fixedVersion || finding.ecosystem.toLowerCase() !== "npm") return null;
  return mappings.find((mapping) => mapping.dependency === finding.dependency &&
    finding.aliases.includes(mapping.advisory)) ?? null;
}
