const severities = ['info', 'low', 'moderate', 'high', 'critical'] as const;
const dependencyStatuses = ['clean', 'findings', 'incomplete'] as const;

type Finding = {
  file: string;
  line: number;
  severity: (typeof severities)[number];
  title: string;
  evidence: string;
  remediation: string;
};

type DependencyAudit = {
  status: (typeof dependencyStatuses)[number];
  lockfile_verified: boolean;
  finding_count: number;
  reason?: string;
};

export type CodeReviewReport =
  | { status: 'incomplete'; dependency_audit: DependencyAudit | null; reason: string }
  | {
      status: 'reviewed';
      dependency_audit: DependencyAudit;
      model: string;
      reviewed_files: string[];
      findings: Finding[];
      coverage_gaps: string[];
    };

export const maxCodeReviewReportBytes = 128 * 1024;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isText(value: unknown, limit: number): value is string {
  return typeof value === 'string' && value.length <= limit && value.trim().length > 0;
}

function isInteger(value: unknown, minimum: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum;
}

function isOneOf<T extends string>(value: unknown, choices: readonly T[]): value is T {
  return choices.some((choice) => value === choice);
}

function isList<T>(
  value: unknown,
  limit: number,
  accepts: (item: unknown) => item is T,
): value is T[] {
  return Array.isArray(value) && value.length <= limit && value.every(accepts);
}

function isDependencyAudit(value: unknown): value is DependencyAudit {
  return (
    isObject(value) &&
    isOneOf(value.status, dependencyStatuses) &&
    typeof value.lockfile_verified === 'boolean' &&
    isInteger(value.finding_count, 0) &&
    (value.reason === undefined || isText(value.reason, 120))
  );
}

function isFinding(value: unknown): value is Finding {
  return (
    isObject(value) &&
    isText(value.file, 512) &&
    isInteger(value.line, 1) &&
    isOneOf(value.severity, severities) &&
    isText(value.title, 180) &&
    isText(value.evidence, 500) &&
    isText(value.remediation, 600)
  );
}

export function parseCodeReviewReport(bytes: Uint8Array): CodeReviewReport {
  if (bytes.byteLength > maxCodeReviewReportBytes) {
    throw new Error('Choose a report smaller than 128 KiB.');
  }

  // Windows PowerShell 5 saves redirected CLI output as UTF-16LE with a BOM.
  const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le' : 'utf-8';
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder(encoding, { fatal: true }).decode(bytes));
  } catch {
    throw new Error('The selected file is not valid JSON.');
  }

  if (isObject(data) && data.schema_version === 1) {
    if (
      data.status === 'incomplete' &&
      isText(data.reason, 120) &&
      (data.dependency_audit === null || isDependencyAudit(data.dependency_audit)) &&
      Array.isArray(data.reviewed_files) &&
      data.reviewed_files.length === 0 &&
      Array.isArray(data.findings) &&
      data.findings.length === 0
    ) {
      return { status: data.status, reason: data.reason, dependency_audit: data.dependency_audit };
    }
    if (
      data.status === 'reviewed' &&
      isText(data.model, 200) &&
      isDependencyAudit(data.dependency_audit) &&
      isList(data.reviewed_files, 8, (file): file is string => isText(file, 512)) &&
      data.reviewed_files.length > 0 &&
      isList(data.findings, 12, isFinding) &&
      isList(data.coverage_gaps, 8, (gap): gap is string => isText(gap, 240))
    ) {
      const reviewed = new Set(data.reviewed_files);
      if (data.findings.every((finding) => reviewed.has(finding.file))) {
        return {
          status: data.status,
          model: data.model,
          dependency_audit: data.dependency_audit,
          reviewed_files: data.reviewed_files,
          findings: data.findings,
          coverage_gaps: data.coverage_gaps,
        };
      }
    }
  }
  throw new Error('Choose a version 1 code-review.json report from Sapphire.');
}
