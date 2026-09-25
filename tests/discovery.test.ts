import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { appJwt, discoverTargets } from "../scripts/discover-targets.mjs";

const privateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
  type: "pkcs1",
  format: "pem",
}).toString();

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("central installation discovery", () => {
  it("signs a short-lived App JWT", () => {
    const token = appJwt("5075643", privateKey, 1_700_000_000);
    const [header, payload, signature] = token.split(".");
    expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toEqual({
      iat: 1_699_999_940,
      exp: 1_700_000_540,
      iss: "5075643",
    });
    expect(signature.length).toBeGreaterThan(100);
  });

  it("selects only installed repositories with a valid opt-in policy", async () => {
    const calls: Array<{ url: string; method: string; authorization: string | null }> = [];
    const config = Buffer.from(JSON.stringify({
      version: 1,
      holds: [],
      requiredChecks: ["test"],
      incidentRepository: null,
    })).toString("base64");
    const fetchImpl = async (input: string | URL | Request, options: RequestInit = {}) => {
      const url = String(input);
      const method = options.method ?? "GET";
      const headers = new Headers(options.headers);
      calls.push({ url, method, authorization: headers.get("authorization") });
      if (url.includes("/app/installations?")) {
        return json([{ id: 42, suspended_at: null }, { id: 99, suspended_at: "2026-01-01" }]);
      }
      if (url.endsWith("/app/installations/42/access_tokens")) return json({ token: "installation-token" });
      if (url.includes("/installation/repositories?")) {
        return json({ repositories: [
          { full_name: "cpheinrich/lakinacapital", name: "lakinacapital", owner: { login: "cpheinrich" }, default_branch: "main" },
          { full_name: "cpheinrich/incidents", name: "incidents", owner: { login: "cpheinrich" }, default_branch: "main" },
        ] });
      }
      if (url.includes("repos/cpheinrich/lakinacapital/contents/.github/morpheus-security.json")) {
        return json({ type: "file", encoding: "base64", content: config });
      }
      if (url.includes("repos/cpheinrich/incidents/contents/.github/morpheus-security.json")) return json({}, 404);
      if (url.endsWith("/installation/token") && method === "DELETE") return new Response(null, { status: 204 });
      throw new Error(`Unexpected request: ${method} ${url}`);
    };

    await expect(discoverTargets({
      appId: "5075643",
      privateKey,
      approved: ["cpheinrich/lakinacapital"],
      fetchImpl,
      now: 1_700_000_000,
    }))
      .resolves.toEqual([{
        repository: "cpheinrich/lakinacapital",
        owner: "cpheinrich",
        name: "lakinacapital",
        defaultBranch: "main",
      }]);
    expect(calls.some((call) => call.method === "DELETE" && call.authorization === "Bearer installation-token"))
      .toBe(true);
    expect(calls.some((call) => call.url.includes("/app/installations/99/access_tokens"))).toBe(false);
  });

  it("isolates a malformed opt-in policy without blocking other installations", async () => {
    const invalid = Buffer.from(JSON.stringify({ version: 1, requiredChecks: [""] })).toString("base64");
    const fetchImpl = async (input: string | URL | Request, options: RequestInit = {}) => {
      const url = String(input);
      if (url.includes("/app/installations?")) return json([{ id: 42, suspended_at: null }]);
      if (url.endsWith("/app/installations/42/access_tokens")) return json({ token: "installation-token" });
      if (url.includes("/installation/repositories?")) return json({ repositories: [{
        full_name: "cpheinrich/unsafe",
        name: "unsafe",
        owner: { login: "cpheinrich" },
        default_branch: "main",
      }] });
      if (url.includes("/contents/.github/morpheus-security.json")) {
        return json({ type: "file", encoding: "base64", content: invalid });
      }
      if (url.endsWith("/installation/token") && options.method === "DELETE") return new Response(null, { status: 204 });
      throw new Error(`Unexpected request: ${options.method ?? "GET"} ${url}`);
    };
    const warnings: string[] = [];
    await expect(discoverTargets({
      appId: "5075643",
      privateKey,
      approved: ["cpheinrich/unsafe"],
      fetchImpl,
      now: 1_700_000_000,
      warn: (message: string) => warnings.push(message),
    })).resolves.toEqual([]);
    expect(warnings).toEqual([expect.stringContaining("cpheinrich/unsafe was skipped")]);
  });
});
