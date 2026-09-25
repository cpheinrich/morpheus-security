import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
// @ts-expect-error operational JavaScript intentionally ships outside the TypeScript build
import { appJwt, discoverTargets } from "../scripts/discover-targets.mjs";

const privateKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
  type: "pkcs1",
  format: "pem",
}).toString();

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("central installation discovery", () => {
  it("signs a short-lived App JWT", () => {
    const token = appJwt("5075643", privateKey, 1_700_000_000);
    const [header, payload, signature] = token.split(".");
    expect(JSON.parse(Buffer.from(header, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    expect(JSON.parse(Buffer.from(payload, "base64url").toString())).toEqual({
      iat: 1_699_999_940, exp: 1_700_000_540, iss: "5075643",
    });
    expect(signature.length).toBeGreaterThan(100);
  });

  it("queries only allowlisted repositories and requires matching live policy", async () => {
    const calls: Array<{ url: string; method: string; authorization: string | null; body?: string }> = [];
    const config = Buffer.from(JSON.stringify({
      version: 1, holds: [], requiredChecks: ["test"],
    })).toString("base64");
    const fetchImpl = async (input: string | URL | Request, options: RequestInit = {}) => {
      const url = String(input);
      const method = options.method ?? "GET";
      const headers = new Headers(options.headers);
      calls.push({ url, method, authorization: headers.get("authorization"), body: String(options.body ?? "") });
      if (url.endsWith("/repos/cpheinrich/lakinacapital/installation")) return json({ id: 42, suspended_at: null });
      if (url.endsWith("/app/installations/42/access_tokens")) return json({ token: "installation-token" });
      if (url.endsWith("/repos/cpheinrich/lakinacapital")) return json({ default_branch: "main" });
      if (url.includes("repos/cpheinrich/lakinacapital/contents/.github/morpheus-security.json")) {
        return json({ type: "file", encoding: "base64", content: config });
      }
      if (url.endsWith("/installation/token") && method === "DELETE") return new Response(null, { status: 204 });
      throw new Error(`Unexpected request: ${method} ${url}`);
    };

    await expect(discoverTargets({
      appId: "5075643",
      privateKey,
      approved: [{ repository: "cpheinrich/lakinacapital" }],
      fetchImpl,
      now: 1_700_000_000,
    })).resolves.toEqual([{
      repository: "cpheinrich/lakinacapital",
      owner: "cpheinrich",
      name: "lakinacapital",
      defaultBranch: "main",
    }]);
    expect(calls.some((call) => call.url.includes("/app/installations?"))).toBe(false);
    expect(calls.find((call) => call.url.endsWith("/access_tokens"))?.body)
      .toContain('\"repositories\":[\"lakinacapital\"]');
    expect(calls.some((call) => call.method === "DELETE" && call.authorization === "Bearer installation-token"))
      .toBe(true);
  });

  it("isolates unavailable or malformed allowlisted targets", async () => {
    const invalid = Buffer.from(JSON.stringify({ version: 1, holds: [], requiredChecks: [""] })).toString("base64");
    const fetchImpl = async (input: string | URL | Request, options: RequestInit = {}) => {
      const url = String(input);
      if (url.endsWith("/repos/cpheinrich/missing/installation")) return json({}, 404);
      if (url.endsWith("/repos/cpheinrich/unsafe/installation")) return json({ id: 42, suspended_at: null });
      if (url.endsWith("/app/installations/42/access_tokens")) return json({ token: "installation-token" });
      if (url.endsWith("/repos/cpheinrich/unsafe")) return json({ default_branch: "main" });
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
      approved: [
        { repository: "cpheinrich/missing" },
        { repository: "cpheinrich/unsafe" },
      ],
      fetchImpl,
      now: 1_700_000_000,
      warn: (message: string) => warnings.push(message),
    })).resolves.toEqual([]);
    expect(warnings).toHaveLength(2);
    expect(warnings.join("\n")).toContain("cpheinrich/missing");
    expect(warnings.join("\n")).toContain("cpheinrich/unsafe");
  });
});
