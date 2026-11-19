const MAX_SITES = 1_000;
const MAX_ALERTS = 20_000;
const MAX_INSTANCES = 50_000;
const MAX_DIAGNOSTICS = 20_000;

const HTTP_METHODS = new Set<string>(["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);
const SEVERITIES = ["info", "low", "medium", "high"] as const;

type ZapFinding = {
  ruleId: string;
  severity: (typeof SEVERITIES)[number];
  rawPointer: string;
  instances: { rawPointer: string; method: string | null; statusCode: number | null }[];
};

type NormalizedZapReport = {
  tool: "zap";
  zapVersion: string;
  coverage: "unknown" | "incomplete";
  coverageReasons: ("zap_plan_errors" | "zap_plan_warnings")[];
  findings: ZapFinding[];
};

function requireObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("zap_report_invalid");
  return value as Record<string, unknown>;
}

function requireArray(value: unknown, limit: number): unknown[] {
  if (!Array.isArray(value)) throw new Error("zap_report_invalid");
  if (value.length > limit) throw new Error("zap_report_limit_exceeded");
  return value;
}

function parseVersion(value: unknown): string {
  if (typeof value !== "string") throw new Error("zap_report_invalid");
  if (value === "Dev Build" || /^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value) || /^D-\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$/.test(value)) return value;
  throw new Error("zap_report_invalid");
}

function parseRuleId(value: unknown): string {
  const id = typeof value === "number" ? String(value) : value;
  if (typeof id !== "string" || !/^(?:0|[1-9]\d{0,9})$/.test(id) || Number(id) > 2_147_483_647) throw new Error("zap_report_invalid");
  return id;
}

function parseSeverity(value: unknown): ZapFinding["severity"] {
  const code = typeof value === "number" ? String(value) : value;
  if (typeof code !== "string" || !/^[0-3]$/.test(code)) throw new Error("zap_report_invalid");
  return SEVERITIES[Number(code)];
}

function parseStatusCode(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const statusLine = /^HTTP\/(?:1\.[01]|[23](?:\.0)?) ([1-5]\d{2})(?=[ \r\n]|$)/.exec(value);
  return statusLine ? Number(statusLine[1]) : null;
}

function hasDiagnostics(report: Record<string, unknown>, key: "afPlanErrors" | "afPlanWarns"): boolean {
  if (!Object.hasOwn(report, key)) return false;
  const diagnostics = requireArray(report[key], MAX_DIAGNOSTICS);
  for (const entry of diagnostics) {
    if (typeof entry !== "string") throw new Error("zap_report_invalid");
  }
  return diagnostics.length > 0;
}

/** Normalize Traditional JSON reports into a fixed set of finding and HTTP metadata fields. */
export function normalizeZapReport(raw: unknown): NormalizedZapReport {
  const report = requireObject(raw);
  const zapVersion = parseVersion(report["@version"]);
  const coverageReasons: NormalizedZapReport["coverageReasons"] = [];
  if (hasDiagnostics(report, "afPlanErrors")) coverageReasons.push("zap_plan_errors");
  if (hasDiagnostics(report, "afPlanWarns")) coverageReasons.push("zap_plan_warnings");
  const findings: ZapFinding[] = [];
  let instanceCount = 0;

  for (const [siteIndex, rawSite] of requireArray(report.site, MAX_SITES).entries()) {
    const site = requireObject(rawSite);
    const alerts = requireArray(site.alerts, MAX_ALERTS - findings.length);

    for (const [alertIndex, rawAlert] of alerts.entries()) {
      const alert = requireObject(rawAlert);
      const rawPointer = `/site/${siteIndex}/alerts/${alertIndex}`;
      const ruleId = parseRuleId(alert.pluginid);
      const severity = parseSeverity(alert.riskcode);
      const rawInstances = requireArray(alert.instances, MAX_INSTANCES - instanceCount);
      const instances: ZapFinding["instances"] = [];
      instanceCount += rawInstances.length;

      for (const [instanceIndex, rawInstance] of rawInstances.entries()) {
        const instance = requireObject(rawInstance);
        instances.push({
          rawPointer: `${rawPointer}/instances/${instanceIndex}`,
          method: typeof instance.method === "string" && HTTP_METHODS.has(instance.method) ? instance.method : null,
          statusCode: parseStatusCode(instance["response-header"]),
        });
      }

      findings.push({ ruleId, severity, rawPointer, instances });
    }
  }

  return { tool: "zap", zapVersion, coverage: coverageReasons.length ? "incomplete" : "unknown", coverageReasons, findings };
}
