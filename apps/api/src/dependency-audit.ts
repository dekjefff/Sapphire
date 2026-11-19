import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { isDeepStrictEqual, promisify } from "node:util";
import { z } from "zod";

const run = promisify(execFile);
const registry = "https://registry.npmjs.org/";
const dependencyMap = z.record(z.string(), z.string()).default({});
const manifestSchema = z.object({
  dependencies: dependencyMap,
  devDependencies: dependencyMap,
  optionalDependencies: dependencyMap,
  peerDependencies: dependencyMap,
  workspaces: z.never().optional(),
});
const lockedPackageSchema = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$/),
  resolved: z.string().startsWith(registry),
  link: z.literal(false).optional(),
});
const lockSchema = z.object({
  lockfileVersion: z.union([z.literal(2), z.literal(3)]),
  packages: z.record(z.string(), z.unknown()),
});
const severity = z.enum(["info", "low", "moderate", "high", "critical"]);
const advisorySchema = z.object({
  source: z.number().int().positive(),
  title: z.string(),
  url: z.url(),
  severity,
  range: z.string(),
});
const npmReportSchema = z.object({
  auditReportVersion: z.literal(2),
  vulnerabilities: z.record(z.string(), z.object({
    severity,
    isDirect: z.boolean(),
    nodes: z.array(z.string()).min(1),
    via: z.array(z.union([z.string(), advisorySchema])).min(1),
    fixAvailable: z.union([
      z.boolean(),
      z.object({ name: z.string(), version: z.string(), isSemVerMajor: z.boolean() }),
    ]),
  })),
  metadata: z.object({
    vulnerabilities: z.object({ total: z.number().int().nonnegative() }),
  }),
});

const provenance = { schema_version: 1, ecosystem: "npm", source: "npm-audit", registry } as const;

export function incompleteDependencyAudit(reason: string, lockfileSha256: string | null = null) {
  return {
    ...provenance,
    status: "incomplete" as const,
    reason,
    lockfile_sha256: lockfileSha256,
    findings: [],
  };
}

function readLockedPackages(manifest: string, lockfile: string) {
  const project = manifestSchema.parse(JSON.parse(manifest));
  const { packages } = lockSchema.parse(JSON.parse(lockfile));
  const root = manifestSchema.parse(packages[""]);
  if (!isDeepStrictEqual(project, root)) throw new Error("Manifest and lockfile differ");

  const versions = new Map<string, string>();
  for (const [path, entry] of Object.entries(packages)) {
    if (path === "") continue;
    if (!path.startsWith("node_modules/")) throw new Error("Unsupported lockfile entry");
    versions.set(path, lockedPackageSchema.parse(entry).version);
  }
  const required = { ...project.dependencies, ...project.devDependencies };
  for (const name of Object.keys(required)) {
    if (!Object.hasOwn(project.optionalDependencies, name) && !versions.has(`node_modules/${name}`)) {
      throw new Error("Required package missing from lockfile");
    }
  }
  return versions;
}

function normalizeReport(stdout: string, versions: ReadonlyMap<string, string>, digest: string, exitCode: number) {
  const report = npmReportSchema.parse(JSON.parse(stdout));
  const findings = Object.entries(report.vulnerabilities).sort(([left], [right]) => left.localeCompare(right, "en"))
    .map(([name, entry]) => ({
      package: name,
      severity: entry.severity,
      direct: entry.isDirect,
      instances: [...new Set(entry.nodes)].sort().map(path => {
        const version = versions.get(path);
        if (!version) throw new Error("Audit result references an unlocked package");
        return { path, version };
      }),
      advisories: entry.via.filter(via => typeof via !== "string").map(advisory => ({
        id: `npm:${advisory.source}`,
        title: advisory.title,
        url: advisory.url,
        severity: advisory.severity,
        affected_range: advisory.range,
      })),
      via_packages: [...new Set(entry.via.filter(via => typeof via === "string"))].sort(),
      fix_available: entry.fixAvailable !== false,
      suggested_update: typeof entry.fixAvailable === "object" ? {
        package: entry.fixAvailable.name,
        version: entry.fixAvailable.version,
        major_upgrade: entry.fixAvailable.isSemVerMajor,
      } : null,
    }));
  if (findings.length !== report.metadata.vulnerabilities.total || (exitCode === 1 && findings.length === 0)) {
    throw new Error("Inconsistent npm audit report");
  }
  return {
    ...provenance,
    status: findings.length ? "findings" as const : "clean" as const,
    lockfile_sha256: digest,
    locked_package_instances: versions.size,
    findings,
  };
}

type AuditRunner = (cwd: string) => Promise<{ stdout: string; exitCode: number }>;

function npmRunner(npmCli: string): AuditRunner {
  return async cwd => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
      /^(path|systemroot|temp|tmp|tmpdir|home|userprofile|localappdata|appdata|https?_proxy|no_proxy|node_extra_ca_certs)$/i.test(key)
    ));
    try {
      const { stdout } = await run(process.execPath, [
        npmCli, "audit", "--json", "--package-lock-only", "--ignore-scripts",
        `--registry=${registry}`, "--fetch-retries=0", "--audit-level=info",
        `--userconfig=${join(cwd, "user.npmrc")}`, `--globalconfig=${join(cwd, "global.npmrc")}`,
      ], { cwd, env, timeout: 60_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
      return { stdout, exitCode: 0 };
    } catch (error) {
      // npm also uses exit status 1 when it successfully reports findings.
      const result = error as { code?: unknown; stdout?: unknown };
      if (result.code === 1 && typeof result.stdout === "string") return { stdout: result.stdout, exitCode: 1 };
      throw error;
    }
  };
}

/** Audits the manifest and lockfile of one npm package selected by the operator. */
export async function auditDependencies(directory: string, npmCli: string, runner = npmRunner(npmCli)) {
  let manifest: string;
  let lockfile: string;
  let digest: string | null = null;
  let versions: Map<string, string>;
  try {
    const [manifestText, lockfileBytes] = await Promise.all([
      readFile(join(directory, "package.json"), "utf8"),
      readFile(join(directory, "package-lock.json")),
    ]);
    manifest = manifestText;
    lockfile = lockfileBytes.toString("utf8");
    digest = createHash("sha256").update(lockfileBytes).digest("hex");
    versions = readLockedPackages(manifest, lockfile);
  } catch {
    return incompleteDependencyAudit("missing_unreadable_or_unsupported_input", digest);
  }

  let snapshot: string | undefined;
  try {
    snapshot = await mkdtemp(join(tmpdir(), "sapphire-audit-"));
    await writeFile(join(snapshot, "package.json"), manifest);
    await writeFile(join(snapshot, "package-lock.json"), lockfile);
    const { stdout, exitCode } = await runner(snapshot);
    if (exitCode !== 0 && exitCode !== 1) return incompleteDependencyAudit("npm_audit_failed", digest);
    try {
      return normalizeReport(stdout, versions, digest, exitCode);
    } catch {
      return incompleteDependencyAudit("invalid_npm_audit_report", digest);
    }
  } catch {
    return incompleteDependencyAudit("npm_audit_failed", digest);
  } finally {
    if (snapshot) await rm(snapshot, { recursive: true, force: true, maxRetries: 2 });
  }
}
