import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import yauzl from "yauzl";
import ts from "typescript-parser";

export const LIMITS = { archiveBytes: 100 * 1024 * 1024, extractedBytes: 250 * 1024 * 1024, files: 20_000, fileBytes: 10 * 1024 * 1024, depth: 32 };
export type IntakeSource = { type: "local_path"; path: string } | { type: "zip"; path: string };
export type Technology = { name: string; category: string; confidence: number; evidence: string[]; reason: string };
export type DiscoveredRoute = { method: string; path: string; file: string; line: number | null; confidence: number };
export type Finding = { severity: "warning" | "error"; code: string; message: string };
export type IntakeResult = { sourceType: string; canonicalLocation: string; identityType: "git_commit" | "content_sha256"; identity: string; fileCount: number; totalBytes: number; scanRoot: string; temporaryRoot: string | null; technologies: Technology[]; routes: DiscoveredRoute[]; findings: Finding[] };

const excludedDirectoryNames = new Set(["node_modules", ".next", "dist", "build", "vendor", "coverage", "out", ".turbo", ".cache", "target", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".gradle"]);

function inside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === "" || (!rel.startsWith(`..${sep}`) && rel !== ".." && !isAbsolute(rel));
}

function workspaceRoots(): string[] {
  return (process.env.WORKSPACE_ROOTS ?? "/workspace").split(process.platform === "win32" ? ";" : ":").map((v) => v.trim()).filter(Boolean);
}

export async function validateLocalPath(input: string): Promise<string> {
  if (!isAbsolute(input)) throw new Error("Repository path must be absolute and inside a configured workspace root");
  const target = await realpath(input);
  const info = await stat(target);
  if (!info.isDirectory()) throw new Error("Repository path must be a directory");
  const roots = await Promise.all(workspaceRoots().map((root) => realpath(root).catch(() => "")));
  if (!roots.some((root) => root && inside(root, target))) throw new Error("Repository path is outside configured workspace roots");
  return target;
}

async function inventory(root: string): Promise<{ files: string[]; size: number; hash: string; commit: string | null; skipped: Map<string, number> }> {
  const files: string[] = [];
  const skipped = new Map<string, number>();
  let size = 0;
  const hash = createHash("sha256");
  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > LIMITS.depth) throw new Error("Repository exceeds the maximum directory depth");
    const entries = await readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    for (const entry of entries) {
      if (dir === root && entry.name === ".git") continue;
      if (entry.isDirectory() && excludedDirectoryNames.has(entry.name)) {
        skipped.set(entry.name, (skipped.get(entry.name) ?? 0) + 1);
        continue;
      }
      const full = join(dir, entry.name);
      const info = await lstat(full);
      if (info.isSymbolicLink()) throw new Error(`Symbolic links are not accepted: ${relative(root, full)}`);
      if (info.isDirectory()) { await walk(full, depth + 1); continue; }
      if (!info.isFile()) throw new Error(`Special files are not accepted: ${relative(root, full)}`);
      if (info.size > LIMITS.fileBytes) throw new Error(`File exceeds the ${LIMITS.fileBytes} byte per-file limit: ${relative(root, full)}`);
      size += info.size;
      if (size > LIMITS.extractedBytes) throw new Error("Repository exceeds the total source size limit");
      files.push(relative(root, full).split(sep).join("/"));
      if (files.length > LIMITS.files) throw new Error("Repository exceeds the maximum file count");
    }
  }
  await walk(root, 0);
  for (const path of files) {
    const bytes = await readFile(join(root, ...path.split("/")));
    hash.update(path).update("\0").update(String(bytes.length)).update("\0").update(bytes).update("\0");
  }
  return { files, size, hash: hash.digest("hex"), commit: await gitHead(root), skipped };
}

async function gitHead(root: string): Promise<string | null> {
  const git = join(root, ".git");
  try {
    if (!(await lstat(git)).isDirectory()) return null;
    const head = (await readFile(join(git, "HEAD"), "utf8")).trim();
    const direct = /^[0-9a-f]{40,64}$/i.test(head) ? head.toLowerCase() : null;
    if (direct) return direct;
    const match = /^ref: (refs\/[\w./-]+)$/.exec(head);
    if (!match) return null;
    const refPath = resolve(git, match[1]);
    if (!inside(git, refPath)) return null;
    const value = (await readFile(refPath, "utf8").catch(() => "")).trim();
    if (/^[0-9a-f]{40,64}$/i.test(value)) return value.toLowerCase();
    const packed = await readFile(join(git, "packed-refs"), "utf8").catch(() => "");
    const packedMatch = packed.split(/\r?\n/).find((line) => line.endsWith(` ${match[1]}`));
    const packedHash = packedMatch?.split(" ")[0];
    return packedHash && /^[0-9a-f]{40,64}$/i.test(packedHash) ? packedHash.toLowerCase() : null;
  } catch { return null; }
}

function zipOpen(path: string): Promise<yauzl.ZipFile> {
  return new Promise((resolveZip, reject) => yauzl.open(path, { lazyEntries: true, autoClose: false, decodeStrings: true, validateEntrySizes: true }, (error, zip) => error || !zip ? reject(error ?? new Error("Invalid ZIP archive")) : resolveZip(zip)));
}

async function extractZip(archive: string, dest: string): Promise<void> {
  const archiveInfo = await stat(archive);
  if (archiveInfo.size > LIMITS.archiveBytes) throw new Error("ZIP exceeds the 100 MB upload limit");
  const zip = await zipOpen(archive);
  let files = 0;
  let total = 0;
  await new Promise<void>((resolveExtract, reject) => {
    const fail = (error: Error) => { zip.close(); reject(error); };
    zip.on("error", fail);
    zip.on("entry", (entry) => {
      const raw = entry.fileName;
      const normalized = raw.replace(/\\/g, "/");
      const mode = (entry.externalFileAttributes >>> 16) & 0xffff;
      const fileType = mode & 0o170000;
      const parts = normalized.split("/").filter((part: string) => part && part !== ".");
      if (!normalized || normalized.startsWith("/") || /^[a-z]:/i.test(normalized) || parts.includes("..") || parts.length > LIMITS.depth || fileType === 0o120000 || (fileType !== 0 && fileType !== 0o100000 && fileType !== 0o040000)) return fail(new Error(`Unsafe ZIP entry rejected: ${raw.slice(0, 160)}`));
      const isDirectory = normalized.endsWith("/") || fileType === 0o040000;
      const out = resolve(dest, ...parts);
      if (!inside(dest, out)) return fail(new Error("ZIP entry escapes extraction directory"));
      if (isDirectory) { mkdir(out, { recursive: true }).then(() => zip.readEntry(), fail); return; }
      files += 1; total += entry.uncompressedSize;
      if (files > LIMITS.files || entry.uncompressedSize > LIMITS.fileBytes || total > LIMITS.extractedBytes) return fail(new Error("ZIP exceeds file count, per-file, or expanded size limit"));
      mkdir(dirname(out), { recursive: true }).then(() => {
        zip.openReadStream(entry, (error, stream) => {
          if (error || !stream) return fail(error ?? new Error("Could not read ZIP entry"));
          const chunks: Buffer[] = []; let seen = 0;
          stream.on("data", (chunk: Buffer) => { seen += chunk.length; if (seen > LIMITS.fileBytes || seen > entry.uncompressedSize) stream.destroy(new Error("ZIP entry exceeded declared size")); else chunks.push(chunk); });
          stream.on("error", fail);
          stream.on("end", () => { if (seen !== entry.uncompressedSize) return fail(new Error("ZIP entry size mismatch")); writeFile(out, Buffer.concat(chunks), { flag: "wx", mode: 0o444 }).then(() => zip.readEntry(), fail); });
        });
      }, fail);
    });
    zip.on("end", () => { zip.close(); resolveExtract(); });
    zip.readEntry();
  });
}

const extLanguage: Record<string, string> = { ".ts": "TypeScript", ".tsx": "TypeScript", ".js": "JavaScript", ".jsx": "JavaScript", ".py": "Python", ".go": "Go", ".rs": "Rust", ".java": "Java", ".php": "PHP", ".rb": "Ruby", ".cs": "C#", ".vue": "Vue", ".svelte": "Svelte" };

type StaticImport = { specifier: string; exportName: string };
type StaticRoute = { receiver: string; method: string; path: string; file: string; line: number };
type StaticMount = { receiver: string; prefix: string | null; refs: string[]; inlineRouter: boolean; file: string; line: number };
type StaticModule = {
  file: string;
  routerVars: Set<string>;
  appVars: Set<string>;
  imports: Map<string, StaticImport>;
  aliases: Map<string, string>;
  exportedLocals: Map<string, string>;
  reexports: Map<string, StaticImport>;
  routes: StaticRoute[];
  mounts: StaticMount[];
};

const routeMethods = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);
const maxRouteParserFiles = 5_000;
const maxRouteParserBytes = 64 * 1024 * 1024;

function staticString(node: ts.Expression | undefined): string | null {
  return node && (ts.isStringLiteralLike(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : null;
}

function staticReference(node: ts.Expression | undefined): string | null {
  if (!node) return null;
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) {
    const parent = staticReference(node.expression);
    return parent ? `${parent}.${node.name.text}` : null;
  }
  return null;
}

function calledName(node: ts.Expression): string | null {
  if (ts.isIdentifier(node)) return node.text;
  return ts.isPropertyAccessExpression(node) ? node.name.text : null;
}

function isRouterFactoryCall(node: ts.Expression | undefined, factories: Map<string, string>): boolean {
  if (!node || !ts.isCallExpression(node)) return false;
  const name = calledName(node.expression);
  if (name !== "Router") return false;
  if (ts.isIdentifier(node.expression)) return factories.get(name) === "express_router";
  if (ts.isPropertyAccessExpression(node.expression)) {
    const receiver = staticReference(node.expression.expression);
    return Boolean(receiver && factories.get(receiver) === "express");
  }
  return false;
}

function moduleSource(node: ts.Expression | undefined): string | null {
  return staticString(node);
}

function sourceLine(source: ts.SourceFile, node: ts.Node): number {
  return source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1;
}

function routeParserFinding(findings: Finding[], code: string, file: string, line: number, detail: string): void {
  findings.push({ severity: "warning", code, message: `${detail} (${file}:${line}); some routes may be missing` });
}

function resolveRelativeModule(root: string, importer: string, specifier: string, files: Set<string>): string | null {
  if (!specifier.startsWith(".")) return null;
  const base = resolve(root, dirname(join(root, ...importer.split("/"))), specifier);
  if (!inside(root, base)) return null;
  const candidates = [base];
  const extension = extname(base).toLowerCase();
  if (extension) {
    if (extension === ".js") candidates.push(base.slice(0, -3) + ".ts", base.slice(0, -3) + ".tsx", base.slice(0, -3) + ".jsx");
    if (extension === ".mjs") candidates.push(base.slice(0, -4) + ".mts");
    if (extension === ".cjs") candidates.push(base.slice(0, -4) + ".cts");
  } else {
    for (const ext of [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]) candidates.push(`${base}${ext}`);
    for (const ext of [".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]) candidates.push(join(base, `index${ext}`));
  }
  for (const candidate of candidates) {
    const relativePath = relative(root, candidate).split(sep).join("/");
    if (inside(root, candidate) && files.has(relativePath)) return relativePath;
  }
  return null;
}

async function extractExpressRoutes(root: string, files: string[], findings: Finding[]): Promise<DiscoveredRoute[]> {
  const scriptFiles = files.filter((file) => /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(file));
  const fileSet = new Set(files);
  const modules = new Map<string, StaticModule>();
  let parsedFileCount = 0;
  let parsedBytes = 0;
  let limitReported = false;

  for (const file of scriptFiles) {
    if (parsedFileCount >= maxRouteParserFiles || parsedBytes >= maxRouteParserBytes) {
      if (!limitReported) findings.push({ severity: "warning", code: "route_parser_limit", message: "Static route parsing reached its file or source-size limit; additional routes may be missing" });
      limitReported = true;
      break;
    }
    const bytes = await readFile(join(root, ...file.split("/"))).catch(() => null);
    if (!bytes) continue;
    parsedFileCount += 1;
    parsedBytes += bytes.byteLength;
    if (parsedBytes > maxRouteParserBytes) {
      if (!limitReported) findings.push({ severity: "warning", code: "route_parser_limit", message: "Static route parsing reached its file or source-size limit; additional routes may be missing" });
      limitReported = true;
      continue;
    }
    const extension = extname(file).toLowerCase();
    const scriptKind = extension === ".tsx" ? ts.ScriptKind.TSX : [".jsx"].includes(extension) ? ts.ScriptKind.JSX : [".ts", ".mts", ".cts"].includes(extension) ? ts.ScriptKind.TS : ts.ScriptKind.JS;
    const source = ts.createSourceFile(file, bytes.toString("utf8"), ts.ScriptTarget.Latest, true, scriptKind);
    const parseDiagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics;
    if (parseDiagnostics?.length) routeParserFinding(findings, "route_source_parse_warning", file, 1, "Could not fully parse JavaScript/TypeScript syntax");
    const info: StaticModule = { file, routerVars: new Set(), appVars: new Set(), imports: new Map(), aliases: new Map(), exportedLocals: new Map(), reexports: new Map(), routes: [], mounts: [] };
    const factories = new Map<string, string>();
    const explicitExports = new Set<string>();

    for (const statement of source.statements) {
      if (ts.isImportDeclaration(statement)) {
        const specifier = moduleSource(statement.moduleSpecifier);
        const clause = statement.importClause;
        if (!specifier || !clause) continue;
        if (clause.name) {
          info.imports.set(clause.name.text, { specifier, exportName: "default" });
          if (specifier === "express") factories.set(clause.name.text, "express");
          if (specifier === "fastify") factories.set(clause.name.text, "fastify");
        }
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const element of clause.namedBindings.elements) {
            const importedName = element.propertyName?.text ?? element.name.text;
            info.imports.set(element.name.text, { specifier, exportName: importedName });
            if (specifier === "express" && importedName === "Router") factories.set(element.name.text, "express_router");
          }
        }
        if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
          info.imports.set(clause.namedBindings.name.text, { specifier, exportName: "*" });
          if (specifier === "express") factories.set(clause.namedBindings.name.text, "express");
          if (specifier === "fastify") factories.set(clause.namedBindings.name.text, "fastify");
        }
      }
    }

    const requireSource = (node: ts.Expression | undefined): string | null => {
      if (!node || !ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== "require") return null;
      return staticString(node.arguments[0]);
    };
    for (const statement of source.statements) {
      if (!ts.isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        const specifier = requireSource(declaration.initializer);
        if (specifier && ts.isIdentifier(declaration.name)) {
          info.imports.set(declaration.name.text, { specifier, exportName: "default" });
          if (specifier === "express") factories.set(declaration.name.text, "express");
          if (specifier === "fastify") factories.set(declaration.name.text, "fastify");
        } else if (specifier && ts.isObjectBindingPattern(declaration.name)) {
          for (const element of declaration.name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            const importedName = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
            info.imports.set(element.name.text, { specifier, exportName: importedName });
            if (specifier === "express" && importedName === "Router") factories.set(element.name.text, "express_router");
          }
        }
      }
    }

    for (const statement of source.statements) {
      if (ts.isVariableStatement(statement)) {
        const isExported = ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ?? false;
        for (const declaration of statement.declarationList.declarations) {
          if (!ts.isIdentifier(declaration.name)) continue;
          const name = declaration.name.text;
          const initializer = declaration.initializer;
          if (isRouterFactoryCall(initializer, factories)) {
            info.routerVars.add(name);
            if (isExported) info.exportedLocals.set(name, name);
            continue;
          }
          if (initializer && ts.isIdentifier(initializer)) info.aliases.set(name, initializer.text);
          if (initializer && ts.isCallExpression(initializer)) {
            const callee = calledName(initializer.expression);
            const packageName = callee ? factories.get(callee) : undefined;
            if (packageName === "express" || callee === "express") info.appVars.add(name);
            if (packageName === "fastify" || callee === "fastify" || callee === "Fastify") info.appVars.add(name);
          }
        }
      } else if (ts.isExportDeclaration(statement)) {
        if (!statement.exportClause || !ts.isNamedExports(statement.exportClause)) continue;
        const specifier = moduleSource(statement.moduleSpecifier);
        for (const element of statement.exportClause.elements) {
          const exportedName = element.name.text;
          const localName = (element.propertyName ?? element.name).text;
          if (specifier) info.reexports.set(exportedName, { specifier, exportName: localName });
          else info.exportedLocals.set(exportedName, localName);
        }
      } else if (ts.isExportAssignment(statement)) {
        if (ts.isIdentifier(statement.expression)) info.exportedLocals.set("default", statement.expression.text);
        else if (isRouterFactoryCall(statement.expression, factories)) {
          info.routerVars.add("$default");
          info.exportedLocals.set("default", "$default");
        }
      } else if (ts.isExpressionStatement(statement) && ts.isBinaryExpression(statement.expression) && statement.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        const { left, right } = statement.expression;
        if (ts.isPropertyAccessExpression(left) && (left.expression.getText(source) === "exports" || left.expression.getText(source) === "module.exports") && ts.isIdentifier(right)) info.exportedLocals.set(left.name.text, right.text);
        else if (left.getText(source) === "module.exports" && ts.isIdentifier(right)) info.exportedLocals.set("default", right.text);
      }
    }

    // Follow ordinary identifier aliases so an app or router keeps its structural identity.
    let aliasChanged = true;
    while (aliasChanged) {
      aliasChanged = false;
      for (const [alias, target] of info.aliases) {
        if (info.appVars.has(target) && !info.appVars.has(alias)) {
          info.appVars.add(alias);
          aliasChanged = true;
        }
      }
    }

    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const receiver = staticReference(node.expression.expression);
        const method = node.expression.name.text.toLowerCase();
        if (receiver && routeMethods.has(method) && node.arguments.length) {
          const path = staticString(node.arguments[0]);
          if (path !== null && path.startsWith("/")) {
            const route: StaticRoute = { receiver, method: method === "all" ? "ALL" : method.toUpperCase(), path, file, line: sourceLine(source, node) };
            info.routes.push(route);
          }
        }
        if (receiver && method === "use" && node.arguments.length >= 1) {
          const hasExplicitMountPath = node.arguments.length >= 2;
          const prefix = hasExplicitMountPath ? staticString(node.arguments[0]) : "/";
          const refs = (hasExplicitMountPath ? node.arguments.slice(1) : node.arguments).map((argument) => staticReference(argument) ?? "");
          const inlineRouter = (hasExplicitMountPath ? node.arguments.slice(1) : node.arguments).some((argument) => isRouterFactoryCall(argument, factories));
          info.mounts.push({ receiver: receiver.split(".")[0], prefix, refs, inlineRouter, file, line: sourceLine(source, node) });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
    modules.set(file, info);
  }

  const keyOf = (file: string, name: string) => `${file}#${name}`;
  function resolveExport(file: string, exportName: string, seen: Set<string>): string | null {
    const token = `${file}:${exportName}`;
    if (seen.has(token)) return null;
    seen.add(token);
    const moduleInfo = modules.get(file);
    if (!moduleInfo) return null;
    const local = moduleInfo.exportedLocals.get(exportName);
    if (local) return resolveLocal(file, local, seen);
    const reexport = moduleInfo.reexports.get(exportName);
    if (reexport) {
      const target = resolveRelativeModule(root, file, reexport.specifier, fileSet);
      return target ? resolveExport(target, reexport.exportName, seen) : null;
    }
    return null;
  }
  function resolveLocal(file: string, reference: string, seen: Set<string>): string | null {
    const moduleInfo = modules.get(file);
    if (!moduleInfo) return null;
    const [localName, property] = reference.split(".", 2);
    if (moduleInfo.routerVars.has(localName)) return keyOf(file, localName);
    if (property && moduleInfo.imports.get(localName)?.exportName === "*") {
      const binding = moduleInfo.imports.get(localName)!;
      const target = resolveRelativeModule(root, file, binding.specifier, fileSet);
      return target ? resolveExport(target, property, seen) : null;
    }
    const alias = moduleInfo.aliases.get(localName);
    if (alias) return resolveLocal(file, alias, seen);
    const binding = moduleInfo.imports.get(localName);
    if (binding) {
      const target = resolveRelativeModule(root, file, binding.specifier, fileSet);
      return target ? resolveExport(target, binding.exportName, seen) : null;
    }
    return null;
  }
  function couldBeUnresolvedRouter(file: string, reference: string): boolean {
    const moduleInfo = modules.get(file);
    if (!moduleInfo) return false;
    const localName = reference.split(".")[0];
    const binding = moduleInfo.imports.get(localName);
    if (!binding || !binding.specifier.startsWith(".")) return false;
    const target = resolveRelativeModule(root, file, binding.specifier, fileSet);
    if (!target) return true;
    const targetInfo = modules.get(target);
    return Boolean(targetInfo && (targetInfo.routerVars.size > 0 || targetInfo.reexports.size > 0));
  }

  type MountEdge = { parent: string | null; child: string; prefix: string; file: string; line: number };
  const edges: MountEdge[] = [];
  for (const info of modules.values()) {
    for (const mount of info.mounts) {
      const parent = resolveLocal(info.file, mount.receiver, new Set()) ?? (info.appVars.has(mount.receiver) || ["app", "server"].includes(mount.receiver) ? null : undefined);
      if (parent === undefined) continue;
      let resolvedChild = false;
      for (const ref of mount.refs) {
        if (!ref) continue;
        const child = resolveLocal(info.file, ref, new Set());
        if (child) {
          resolvedChild = true;
          if (mount.prefix === null || !mount.prefix.startsWith("/")) {
            routeParserFinding(findings, "route_mount_dynamic", mount.file, mount.line, "Express router mount path is not a literal absolute path");
          } else edges.push({ parent, child, prefix: mount.prefix, file: mount.file, line: mount.line });
        } else if (couldBeUnresolvedRouter(info.file, ref)) {
          routeParserFinding(findings, "route_mount_unresolved", mount.file, mount.line, "Could not resolve an imported Express router mount");
          resolvedChild = true;
        }
      }
      if (mount.inlineRouter) routeParserFinding(findings, "route_mount_dynamic", mount.file, mount.line, "Inline Express Router() mounts cannot be linked to route declarations");
      if (!resolvedChild && mount.prefix === null && mount.refs.some((ref) => ref && couldBeUnresolvedRouter(info.file, ref))) routeParserFinding(findings, "route_mount_dynamic", mount.file, mount.line, "Express router mount path is not a literal string");
    }
  }

  const routes: DiscoveredRoute[] = [];
  const visited = new Set<string>();
  const emitted = new Set<string>();
  const combine = (prefix: string, path: string) => {
    const left = prefix === "/" ? "" : prefix.replace(/\/+$/, "");
    const right = path === "/" ? "" : `/${path.replace(/^\/+/, "")}`;
    const joined = `${left}${right}`.replace(/\/{2,}/g, "/");
    return joined || "/";
  };
  function expand(routerKey: string, prefix: string, depth: number): void {
    if (depth > 16 || visited.has(`${routerKey}|${prefix}`)) return;
    visited.add(`${routerKey}|${prefix}`);
    const split = routerKey.lastIndexOf("#");
    const file = routerKey.slice(0, split);
    const name = routerKey.slice(split + 1);
    const info = modules.get(file);
    if (!info) return;
    for (const route of info.routes) {
      if (resolveLocal(file, route.receiver, new Set()) !== routerKey) continue;
      const output = { method: route.method, path: combine(prefix, route.path), file: route.file, line: route.line, confidence: 0.9 };
      const dedupe = `${output.method}:${output.path}:${output.file}:${output.line}`;
      if (!emitted.has(dedupe)) { emitted.add(dedupe); routes.push(output); }
    }
    for (const edge of edges) if (edge.parent === routerKey) expand(edge.child, combine(prefix, edge.prefix), depth + 1);
  }
  // Routes declared directly on an Express/Fastify app are already absolute.
  for (const info of modules.values()) {
    const rootedRouters = new Set<string>();
    const markReachable = (key: string, stack: Set<string>) => {
      if (stack.has(key)) return;
      rootedRouters.add(key);
      const nextStack = new Set(stack); nextStack.add(key);
      for (const edge of edges) if (edge.parent === key) markReachable(edge.child, nextStack);
    };
    for (const edge of edges) if (edge.parent === null) markReachable(edge.child, new Set());
    for (const route of info.routes) {
      const routeRouter = resolveLocal(info.file, route.receiver, new Set());
      if (routeRouter) continue;
      const receiver = route.receiver.split(".")[0];
      if (info.appVars.has(receiver) || ["app", "server", "router"].includes(route.receiver)) routes.push({ method: route.method, path: route.path, file: route.file, line: route.line, confidence: 0.85 });
    }
    for (const edge of edges) if (edge.parent === null) expand(edge.child, edge.prefix, 0);
    for (const [exportName, localName] of info.exportedLocals) {
      if (!info.routerVars.has(localName)) continue;
      const key = keyOf(info.file, localName);
      if (!rootedRouters.has(key) && info.routes.some((route) => resolveLocal(info.file, route.receiver, new Set()) === key)) routeParserFinding(findings, "route_mount_unresolved", info.file, info.routes.find((route) => resolveLocal(info.file, route.receiver, new Set()) === key)!.line, `Exported Express router '${exportName}' has no statically resolved app.use mount`);
    }
  }
  return [...new Map(routes.map((route) => [`${route.method}:${route.path}:${route.file}:${route.line}`, route])).values()];
}

async function detect(root: string, files: string[], skipped: Map<string, number>): Promise<{ technologies: Technology[]; routes: DiscoveredRoute[]; findings: Finding[] }> {
  const findings: Finding[] = [];
  const evidence = new Map<string, Set<string>>();
  const add = (name: string, category: string, path: string, reason: string, confidence = 0.95) => {
    const key = `${category}:${name}`; const set = evidence.get(key) ?? new Set<string>(); set.add(path); evidence.set(key, set);
    technologyMeta.set(key, { name, category, reason, confidence });
  };
  const technologyMeta = new Map<string, Omit<Technology, "evidence">>();
  let packageJson: Record<string, unknown> = {};
  if (files.includes("package.json")) {
    try { packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as Record<string, unknown>; }
    catch { findings.push({ severity: "warning", code: "manifest_invalid", message: "package.json could not be parsed" }); }
    add("Node.js", "runtime", "package.json", "Node package manifest present");
    const lock = files.find((file) => ["pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock", "package-lock.json"].includes(basename(file)));
    const lockName = lock ? basename(lock) : "";
    const packageManager = lockName.startsWith("pnpm-lock") ? "pnpm" : lockName === "yarn.lock" ? "Yarn" : lockName.startsWith("bun.lock") ? "Bun" : "npm";
    add(packageManager, "package_manager", lock ?? "package.json", lock ? `${basename(lock)} lockfile present` : "Node package manifest present", lock ? 0.95 : 0.7);
    const deps = { ...((packageJson.dependencies ?? {}) as Record<string, unknown>), ...((packageJson.devDependencies ?? {}) as Record<string, unknown>) };
    for (const [dep, name, category] of [["next", "Next.js", "framework"], ["express", "Express", "framework"], ["react", "React", "ui"], ["fastify", "Fastify", "framework"], ["@nestjs/core", "NestJS", "framework"]]) if (dep in deps) add(name, category, "package.json", `Dependency ${dep} declared`);
  }
  for (const file of files) {
    const lang = extLanguage[extname(file).toLowerCase()]; if (lang) add(lang, "language", file, `Source file extension ${extname(file)}`, 0.75);
    if (basename(file) === "Dockerfile" || file.endsWith("/Dockerfile")) add("Docker", "container", file, "Dockerfile present");
    if (/\.ya?ml$/i.test(file) && /openapi|swagger/i.test(file)) add("OpenAPI", "api_spec", file, "API specification filename");
    if (["go.mod", "Cargo.toml", "requirements.txt", "pyproject.toml", "composer.json", "Gemfile"].includes(basename(file))) add(({ "go.mod": "Go modules", "Cargo.toml": "Cargo", "requirements.txt": "pip", "pyproject.toml": "Python packaging", "composer.json": "Composer", Gemfile: "Bundler" } as Record<string, string>)[basename(file)], "package_manager", file, "Ecosystem manifest present", 0.9);
  }
  const technologies = [...evidence.entries()].map(([key, paths]) => ({ ...technologyMeta.get(key)!, evidence: [...paths].sort() }));
  const routes: DiscoveredRoute[] = [];
  const next = technologies.some((t) => t.name === "Next.js");
  const appRoute = /(?:^|\/)app\/(.+)\/(?:route|page)\.(?:js|jsx|ts|tsx)$/;
  const appRootRoute = /(?:^|\/)app\/(?:route|page)\.(?:js|jsx|ts|tsx)$/;
  const pagesRoute = /(?:^|\/)pages\/(.+)\.(?:js|jsx|ts|tsx)$/;
  for (const file of files) {
    const appMatch = next ? appRoute.exec(file) : null;
    const rootMatch = next ? appRootRoute.test(file) : false;
    const pageMatch = next ? pagesRoute.exec(file) : null;
    if (appMatch || rootMatch || (pageMatch && !/(?:^|\/)_[^/]+$/.test(pageMatch[1]))) {
      let routePath = rootMatch ? "/" : appMatch ? `/${appMatch[1]}` : `/${pageMatch?.[1] ?? ""}`;
      routePath = routePath.replace(/\.(?:js|jsx|ts|tsx)$/, "").replace(/\/page$/, "").replace(/\/route$/, "").replace(/\/index$/, "");
      if (routePath === "") routePath = "/";
      routePath = routePath.replace(/\[\[\.\.\.([^\]]+)\]\]/g, "* $1").replace(/\[\.\.\.([^\]]+)\]/g, "* $1").replace(/\[([^\]]+)\]/g, ":$1").replace(/\/\* \w+$/, "/*").replace(/\/\([^/]+\)/g, "");
      if (/^\/[^.]*$/.test(routePath)) {
        if (appMatch || rootMatch) {
          const source = await readFile(join(root, ...file.split("/")), "utf8").catch(() => "");
          const lines = source.split(/\r?\n/);
          let foundMethod = false;
          lines.forEach((line, i) => { for (const method of line.matchAll(/\bexport\s+(?:async\s+)?(?:function\s+|const\s+)(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/g)) { routes.push({ method: method[1], path: routePath, file, line: i + 1, confidence: 0.95 }); foundMethod = true; } });
          if (!foundMethod) routes.push({ method: "FILE", path: routePath, file, line: null, confidence: 0.75 });
        } else routes.push({ method: "FILE", path: routePath, file, line: null, confidence: 0.8 });
      }
    }
  }
  const hasScriptSource = files.some((file) => /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i.test(file));
  if (hasScriptSource) routes.push(...await extractExpressRoutes(root, files, findings));
  const unique = [...new Map(routes.map((route) => [`${route.method}:${route.path}:${route.file}:${route.line}`, route])).values()];
  if (!technologies.length) findings.push({ severity: "warning", code: "stack_unknown", message: "No supported technology manifests or source extensions were detected" });
  if (!unique.length) findings.push({ severity: "warning", code: "routes_none", message: "No supported routes were found by the conservative source parser" });
  if (skipped.size) {
    const summary = [...skipped.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([name, count]) => `${name} (${count})`).join(", ");
    findings.push({ severity: "warning", code: "generated_content_skipped", message: `Skipped known generated/dependency directories; stack and route parsing is incomplete there: ${summary}` });
  }
  findings.push({ severity: "warning", code: "untrusted_source", message: "Repository files were inspected as untrusted data; no package scripts or repository code were executed" });
  return { technologies, routes: unique, findings };
}

export async function inspectSource(source: IntakeSource, jobId: string): Promise<IntakeResult> {
  const intakeDir = process.env.INTAKE_DIR ?? "/intake";
  let root: string; let temporaryRoot: string | null = null;
  if (source.type === "local_path") root = await validateLocalPath(source.path);
  else {
    const archive = resolve(intakeDir, source.path);
    if (!inside(await realpath(intakeDir), await realpath(archive))) throw new Error("ZIP path is outside the intake directory");
    temporaryRoot = await mkdtemp(join(intakeDir, `work-${jobId}-`));
    root = temporaryRoot;
  }
  try {
    if (temporaryRoot) {
      await extractZip(resolve(intakeDir, source.path), root);
      const entries = await readdir(root, { withFileTypes: true });
      if (entries.length === 1 && entries[0].isDirectory()) root = join(root, entries[0].name);
    }
    const { files, size, hash, commit, skipped } = await inventory(root);
    const detected = await detect(root, files, skipped);
    return { sourceType: source.type, canonicalLocation: source.type === "local_path" ? root : basename(source.path), identityType: commit ? "git_commit" : "content_sha256", identity: commit ?? hash, fileCount: files.length, totalBytes: size, scanRoot: root, temporaryRoot, ...detected };
  } catch (error) {
    if (temporaryRoot) await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
}

export async function stageUpload(stream: NodeJS.ReadableStream, jobId: string): Promise<string> {
  const intakeDir = process.env.INTAKE_DIR ?? "/intake";
  await mkdir(intakeDir, { recursive: true });
  const dest = join(intakeDir, `${jobId}.zip`);
  let size = 0; const chunks: Buffer[] = [];
  for await (const chunk of stream) { const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk); size += buffer.length; if (size > LIMITS.archiveBytes) throw new Error("ZIP exceeds the 100 MB upload limit"); chunks.push(buffer); }
  if (!size) throw new Error("ZIP upload is empty");
  await writeFile(dest, Buffer.concat(chunks), { flag: "wx", mode: 0o400 });
  return dest;
}
