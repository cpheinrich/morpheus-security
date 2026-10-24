import { describe, expect, it } from "vitest";
import { hasPackageReference, validateGeneratedDistPaths, validateImportCompatibility } from "../src/import-compatibility.js";

const oldPackage = "gray-matter";
const newPackage = "@11ty/gray-matter";

function change(before: string, after: string, path = "src/review/local.ts") {
  return [{ path, before, after }];
}

describe("import-only security compatibility", () => {
  it("accepts exact static import, export, and require specifier substitutions", () => {
    const before = "import matter from 'gray-matter';\nexport { x } from \"gray-matter\";\nconst m = require('gray-matter');\n";
    const after = "import matter from '@11ty/gray-matter';\nexport { x } from \"@11ty/gray-matter\";\nconst m = require('@11ty/gray-matter');\n";
    expect(validateImportCompatibility(change(before, after), oldPackage, newPackage)).toBe(3);
  });

  it("rejects an import change with a behavioral or policy edit", () => {
    const before = "import matter from 'gray-matter';\nreturn check();\n";
    expect(() => validateImportCompatibility(change(before,
      "import matter from '@11ty/gray-matter';\nreturn true;\n"), oldPackage, newPackage)).toThrow("beyond mapped imports");
    expect(() => validateImportCompatibility(change(before,
      "import matter from '@11ty/gray-matter';\nreturn check();\n", "src/security/policy.ts"), oldPackage, newPackage))
      .toThrow("path is not allowed");
  });

  it("does not accept a comment, arbitrary string, or dynamic import as proof", () => {
    for (const before of [
      "// import x from 'gray-matter';\n",
      "const text = 'gray-matter';\n",
      "const x = import('gray-matter');\n",
    ]) {
      expect(() => validateImportCompatibility(change(before, before.replace(oldPackage, newPackage)), oldPackage, newPackage))
        .toThrow("beyond mapped imports");
    }
  });

  it("detects old-package references left in dynamic imports or excluded source", () => {
    expect(hasPackageReference("src/parser.ts", "const x = import('gray-matter');", oldPackage)).toBe(true);
    expect(hasPackageReference("src/auth.ts", "const x = require('gray-matter');", oldPackage)).toBe(true);
    expect(hasPackageReference("dist/parser.js", "import x from 'gray-matter/subpath';", oldPackage)).toBe(true);
    expect(hasPackageReference("src/parser.ts", "// gray-matter\nimport x from '@11ty/gray-matter';", oldPackage)).toBe(false);
  });

  it("enforces eight source files and twenty imports at the boundary", () => {
    const one = change("import x from 'gray-matter';\n", "import x from '@11ty/gray-matter';\n")[0]!;
    const eight = Array.from({ length: 8 }, (_, index) => ({ ...one, path: `src/parser${index}.ts` }));
    expect(validateImportCompatibility(eight, oldPackage, newPackage)).toBe(8);
    expect(() => validateImportCompatibility([...eight, { ...one, path: "src/parser8.ts" }], oldPackage, newPackage))
      .toThrow("1 to 8");
    const twenty = change(one.before.repeat(20), one.after.repeat(20));
    expect(validateImportCompatibility(twenty, oldPackage, newPackage)).toBe(20);
    expect(() => validateImportCompatibility(change(one.before.repeat(21), one.after.repeat(21)), oldPackage, newPackage))
      .toThrow("20 import changes");
  });

  it("rejects duplicate paths, unrelated trees, and unsafe package names", () => {
    const one = change("import x from 'gray-matter';\n", "import x from '@11ty/gray-matter';\n")[0]!;
    expect(() => validateImportCompatibility([one, one], oldPackage, newPackage)).toThrow("distinct");
    expect(() => validateImportCompatibility([{ ...one, path: ".github/workflows/ci.yml" }], oldPackage, newPackage))
      .toThrow("path is not allowed");
    for (const path of ["src/trading/foo.ts", "src/auth.ts", "src/authorization.ts", "src/credentials.ts",
      "src/trades.ts", "src/orders.ts", "src/portfolio.ts", "src/market-data.ts", "tests/trade.test.ts"]) {
      expect(() => validateImportCompatibility([{ ...one, path }], oldPackage, newPackage)).toThrow("path is not allowed");
    }
    expect(() => validateImportCompatibility([one], oldPackage, "../../unsafe"))
      .toThrow("registry package names");
  });

  it("bounds committed dist output to the exact changed TypeScript sources", () => {
    expect(() => validateGeneratedDistPaths(["src/review/local.ts"], ["dist/review/local.js", "dist/review/local.js.map"]))
      .not.toThrow();
    expect(() => validateGeneratedDistPaths(["src/review/local.ts"], ["dist/check/pr.js"]))
      .toThrow("unrelated");
    expect(() => validateGeneratedDistPaths(["src/review/local.ts"], []))
      .toThrow("missing emitted JavaScript");
    expect(() => validateGeneratedDistPaths(["src/review/local.tsx"], []))
      .toThrow("TypeScript source");
  });
});
