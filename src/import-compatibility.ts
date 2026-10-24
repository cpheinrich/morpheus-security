import ts from "typescript";

export const MAX_COMPATIBILITY_SOURCE_FILES = 8;
export const MAX_COMPATIBILITY_IMPORTS = 20;

export interface SourceChange {
  path: string;
  before: string;
  after: string;
}

const PACKAGE = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/;
const SOURCE = /^(?:src|tests)\/(?!.*(?:^|\/)(?:policy|auth|credential|secret|trade|trading|order|execution)(?:[./]|$))[A-Za-z0-9._/-]+\.(?:[cm]?[jt]s|jsx|tsx)$/;

export function isAllowedCompatibilitySource(path: string): boolean {
  return SOURCE.test(path) && !path.includes("..") && !path.includes("//");
}

/** Morpheus's committed TypeScript output is a deterministic derivative, never authored text. */
export function validateGeneratedDistPaths(sourcePaths: string[], generatedPaths: string[]): void {
  if (sourcePaths.length < 1 || sourcePaths.length > MAX_COMPATIBILITY_SOURCE_FILES ||
      sourcePaths.some((path) => !/^src\/[A-Za-z0-9._/-]+\.ts$/.test(path) || !isAllowedCompatibilitySource(path))) {
    throw new Error("Generated dist requires allowed TypeScript source files");
  }
  const allowed = new Set(sourcePaths.flatMap((path) => {
    const base = `dist/${path.slice(4, -3)}`;
    return [".js", ".js.map", ".d.ts", ".d.ts.map"].map((extension) => base + extension);
  }));
  if (generatedPaths.some((path) => !allowed.has(path))) {
    throw new Error("Generated dist changed a file unrelated to mapped imports");
  }
}

function importLiteralPositions(path: string, source: string, dependency: string): Array<{ start: number; end: number }> {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
  const positions: Array<{ start: number; end: number }> = [];
  const add = (literal: ts.Node | undefined): void => {
    if (!literal || !ts.isStringLiteral(literal) || literal.text !== dependency) return;
    const start = literal.getStart(file);
    const end = literal.getEnd();
    const raw = source.slice(start, end);
    // Escaped spellings are deliberately outside this small mechanical lane.
    if (raw !== `'${dependency}'` && raw !== `"${dependency}"`) return;
    positions.push({ start, end });
  };
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) add(node.moduleSpecifier);
    if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      add(node.moduleReference.expression);
    }
    if (ts.isCallExpression(node) && node.arguments.length === 1 &&
        ts.isIdentifier(node.expression) && node.expression.text === "require") add(node.arguments[0]);
    ts.forEachChild(node, visit);
  };
  visit(file);
  return positions;
}

/** Construct a candidate; validation below independently compares it with the original bytes. */
export function replaceImportSpecifiers(path: string, source: string, dependency: string, replacement: string): string {
  if (!PACKAGE.test(dependency) || !PACKAGE.test(replacement) || dependency === replacement) {
    throw new Error("Compatibility package names must be distinct registry package names");
  }
  let result = source;
  for (const { start, end } of importLiteralPositions(path, source, dependency).reverse()) {
    const quote = source[start];
    result = result.slice(0, start) + quote + replacement + quote + result.slice(end);
  }
  return result;
}

/** Proves byte-for-byte that only approved module specifiers changed. */
export function validateImportCompatibility(changes: SourceChange[], dependency: string, replacement: string): number {
  if (!PACKAGE.test(dependency) || !PACKAGE.test(replacement) || dependency === replacement) {
    throw new Error("Compatibility package names must be distinct registry package names");
  }
  if (changes.length < 1 || changes.length > MAX_COMPATIBILITY_SOURCE_FILES ||
      new Set(changes.map((change) => change.path)).size !== changes.length) {
    throw new Error("Compatibility candidate must change 1 to 8 distinct source files");
  }
  let imports = 0;
  for (const change of changes) {
    if (!isAllowedCompatibilitySource(change.path)) {
      throw new Error(`Compatibility source path is not allowed: ${change.path}`);
    }
    const positions = importLiteralPositions(change.path, change.before, dependency);
    const expected = replaceImportSpecifiers(change.path, change.before, dependency, replacement);
    if (positions.length === 0 || change.after !== expected) {
      throw new Error(`Compatibility source contains a change beyond mapped imports: ${change.path}`);
    }
    imports += positions.length;
  }
  if (imports > MAX_COMPATIBILITY_IMPORTS) throw new Error("Compatibility candidate exceeds 20 import changes");
  return imports;
}
