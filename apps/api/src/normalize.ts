import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";

export type NormalizedFinding = {
  rawPointer: string; findingType: "sast" | "vulnerability" | "secret" | "misconfiguration" | "license" | "unknown";
  ruleId: string | null; cveId: string | null; title: string; message: string;
  severity: "critical" | "high" | "medium" | "low" | "info" | "unknown"; confidence: number | null;
  sourceFile: string | null; startLine: number | null; startColumn: number | null; endLine: number | null; endColumn: number | null;
  fingerprint: string; evidence: Record<string, unknown>;
};

type RecordValue = Record<string, any>;
function record(value: unknown): RecordValue { return value && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {}; }
function text(value: unknown, max = 4000): string | null { return typeof value === "string" && value.trim() ? value.trim().slice(0, max) : null; }
function line(value: unknown): number | null { return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : null; }
function severity(value: unknown): NormalizedFinding["severity"] {
  const raw = String(value ?? "").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(raw)) return raw as NormalizedFinding["severity"];
  if (raw === "error") return "high";
  if (raw === "warning") return "medium";
  return "unknown";
}
function relativeSource(root: string, value: unknown): string | null {
  const raw = text(value, 2048); if (!raw) return null;
  const rel = relative(root, resolve(root, raw));
  if (isAbsolute(rel) || rel === ".." || rel.startsWith(`..${sep}`)) return null;
  return rel.split(sep).join("/") || null;
}
function confidence(value: unknown): number | null {
  const raw = String(value ?? "").toLowerCase();
  if (raw === "high") return 0.9;
  if (raw === "medium") return 0.7;
  if (raw === "low") return 0.4;
  const number = Number(value); return Number.isFinite(number) && number >= 0 && number <= 1 ? number : null;
}
function createFinding(input: Omit<NormalizedFinding, "fingerprint">): NormalizedFinding {
  const key = [input.cveId ?? input.ruleId ?? input.title.toLowerCase().replace(/\s+/g, " "), input.sourceFile ?? "", input.startLine ?? "", input.findingType].join("\0");
  return { ...input, fingerprint: createHash("sha256").update(key).digest("hex") };
}

export function parseSemgrepJson(raw: unknown, sourceRoot: string): NormalizedFinding[] {
  const root = record(raw);
  if (!Array.isArray(root.results)) throw new Error("semgrep_json_invalid");
  if (Array.isArray(root.errors) && root.errors.length > 0) throw new Error("semgrep_report_errors");
  if (root.results.length > 20_000) throw new Error("finding_limit_exceeded");
  return root.results.map((value: unknown, index: number) => {
    const result = record(value); const extra = record(result.extra); const metadata = record(extra.metadata);
    const start = record(result.start); const end = record(result.end); const ruleId = text(result.check_id, 512);
    const title = ruleId ?? "Semgrep finding";
    return createFinding({ rawPointer: `/results/${index}`, findingType: "sast", ruleId, cveId: null, title, message: text(extra.message, 4000) ?? title, severity: severity(extra.severity), confidence: confidence(metadata.confidence), sourceFile: relativeSource(sourceRoot, result.path), startLine: line(start.line), startColumn: line(start.col), endLine: line(end.line), endColumn: line(end.col), evidence: { cwe: metadata.cwe ?? null, references: Array.isArray(metadata.references) ? metadata.references.slice(0, 20) : [], category: metadata.category ?? null, fingerprint: text(extra.fingerprint, 256) } });
  });
}

export function parseTrivyJson(raw: unknown, sourceRoot: string): NormalizedFinding[] {
  const root = record(raw);
  if (root.Results !== null && root.Results !== undefined && !Array.isArray(root.Results)) throw new Error("trivy_json_invalid");
  const findings: NormalizedFinding[] = [];
  for (const [resultIndex, value] of (Array.isArray(root.Results) ? root.Results : []).entries()) {
    const result = record(value); const file = relativeSource(sourceRoot, result.Target);
    for (const [index, rawVulnerability] of (Array.isArray(result.Vulnerabilities) ? result.Vulnerabilities : []).entries()) {
      const vuln = record(rawVulnerability); const cve = text(vuln.VulnerabilityID, 128); const title = text(vuln.Title, 1000) ?? cve ?? "Trivy vulnerability";
      findings.push(createFinding({ rawPointer: `/Results/${resultIndex}/Vulnerabilities/${index}`, findingType: "vulnerability", ruleId: cve, cveId: cve?.startsWith("CVE-") ? cve : null, title, message: text(vuln.Description, 4000) ?? title, severity: severity(vuln.Severity), confidence: null, sourceFile: file, startLine: line(vuln.StartLine), startColumn: null, endLine: line(vuln.EndLine), endColumn: null, evidence: { target: text(result.Target, 2048), package: text(vuln.PkgName, 256), installed_version: text(vuln.InstalledVersion, 256), fixed_version: text(vuln.FixedVersion, 256), primary_url: text(vuln.PrimaryURL, 2048), result_class: text(result.Class, 128) } }));
    }
    for (const [index, rawSecret] of (Array.isArray(result.Secrets) ? result.Secrets : []).entries()) {
      const secret = record(rawSecret); const title = text(secret.Title, 1000) ?? text(secret.RuleID, 512) ?? "Trivy secret finding";
      findings.push(createFinding({ rawPointer: `/Results/${resultIndex}/Secrets/${index}`, findingType: "secret", ruleId: text(secret.RuleID, 512), cveId: null, title, message: title, severity: severity(secret.Severity), confidence: null, sourceFile: file, startLine: line(secret.StartLine), startColumn: null, endLine: line(secret.EndLine), endColumn: null, evidence: { target: text(result.Target, 2048), category: text(secret.Category, 256), redacted: true } }));
    }
  }
  if (findings.length > 20_000) throw new Error("finding_limit_exceeded");
  return findings;
}
