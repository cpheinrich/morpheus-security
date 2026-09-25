import { existsSync } from "node:fs";
import { isAbsolute, relative } from "node:path";

export const MORPHEUS_SECURITY_LOGIN = "morpheus-security[bot]";
export const SECURITY_MARKER = "<!-- morpheus-security-update -->";

export interface SecurityFinding {
  ecosystem: string;
  dependency: string;
  version: string;
  advisory: string;
  aliases: string[];
  fixedVersion: string | null;
  sourcePath: string;
  malicious: boolean;
  withdrawn: boolean;
}

interface OsvEvent { introduced?: string; fixed?: string; last_affected?: string }
interface OsvAffected { ranges?: Array<{ type?: string; events?: OsvEvent[] }> }
interface OsvVulnerability {
  id?: string;
  aliases?: string[];
  withdrawn?: string;
  affected?: OsvAffected[];
}

function numericVersion(value: string): number[] | null {
  const match = /^v?(\d+(?:\.\d+)*)(?:[-+].*)?$/.exec(value);
  return match ? match[1]!.split(".").map(Number) : null;
}

export function compareVersions(left: string, right: string): number {
  const a = numericVersion(left);
  const b = numericVersion(right);
  if (!a || !b) return left.localeCompare(right, undefined, { numeric: true });
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

export function smallestFixedVersion(vulnerability: OsvVulnerability, installed: string): string | null {
  const candidates = (vulnerability.affected ?? [])
    .flatMap((affected) => affected.ranges ?? [])
    .filter((range) => range.type === "SEMVER" || range.type === "ECOSYSTEM")
    .flatMap((range) => range.events ?? [])
    .map((event) => event.fixed)
    .filter((version): version is string => Boolean(version))
    .filter((version) => compareVersions(version, installed) > 0)
    .sort(compareVersions);
  return candidates[0] ?? null;
}

export function findingsFromOsvJson(value: unknown): SecurityFinding[] {
  const input = value as {
    results?: Array<{
      source?: { path?: string; type?: string };
      packages?: Array<{
        package?: { ecosystem?: string; name?: string; version?: string };
        vulnerabilities?: OsvVulnerability[];
      }>;
    }>;
  };
  if (!Array.isArray(input?.results)) throw new Error("OSV JSON must contain a results array");

  const findings: SecurityFinding[] = [];
  for (const result of input.results) {
    if (result.source?.type !== "lockfile" || !result.source.path || !Array.isArray(result.packages)) {
      throw new Error("OSV result is missing an exact lockfile source");
    }
    for (const entry of result.packages) {
      const pkg = entry.package;
      if (!pkg?.ecosystem || !pkg.name || !pkg.version || !Array.isArray(entry.vulnerabilities)) {
        throw new Error("OSV package result is incomplete");
      }
      for (const vulnerability of entry.vulnerabilities) {
        if (!vulnerability.id || !/^(?:GHSA|CVE|MAL|OSV)-/.test(vulnerability.id)) {
          throw new Error("OSV vulnerability has an unrecognized advisory id");
        }
        findings.push({
          ecosystem: pkg.ecosystem,
          dependency: pkg.name,
          version: pkg.version,
          advisory: vulnerability.id,
          aliases: [...new Set([vulnerability.id, ...(vulnerability.aliases ?? [])])].sort(),
          fixedVersion: smallestFixedVersion(vulnerability, pkg.version),
          sourcePath: normalizeSourcePath(result.source.path),
          malicious: vulnerability.id.startsWith("MAL-"),
          withdrawn: Boolean(vulnerability.withdrawn),
        });
      }
    }
  }
  return findings.filter((finding) => !finding.withdrawn).sort((a, b) =>
    Number(b.malicious) - Number(a.malicious) ||
    a.sourcePath.localeCompare(b.sourcePath) ||
    a.dependency.localeCompare(b.dependency) ||
    a.advisory.localeCompare(b.advisory));
}

function normalizeSourcePath(path: string): string {
  const normalized = path.replaceAll("\\", "/").replace(/^\.\//, "");
  if (!isAbsolute(normalized)) return normalized;
  const direct = relative(process.cwd(), normalized);
  if (!direct.startsWith("..") && existsSync(direct)) return direct;
  const parts = normalized.split("/").filter(Boolean);
  for (let index = 0; index < parts.length; index += 1) {
    const candidate = parts.slice(index).join("/");
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(`OSV lockfile source is outside the checked-out repository: ${path}`);
}

export function findingKey(finding: Pick<SecurityFinding, "ecosystem" | "dependency" | "advisory">): string {
  return `${finding.ecosystem.toLowerCase()}:${finding.dependency}:${finding.advisory}`;
}

export function isSecurityDependencyOnly(paths: string[]): boolean {
  return paths.length > 0 && paths.every((path) => {
    const base = path.split("/").at(-1) ?? "";
    return [
      "Cargo.lock", "Cargo.toml", "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
      "go.mod", "go.sum", "package-lock.json", "package.json", "pnpm-lock.yaml", "pyproject.toml",
      "pnpm-workspace.yaml", "uv.lock", "yarn.lock",
    ].includes(base) || /^requirements(?:[-_.].+)?\.txt$/.test(base);
  });
}

export function hasSecurityMarker(body: string): boolean {
  return body.includes(SECURITY_MARKER);
}
