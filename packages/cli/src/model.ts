export const REPORT_SCHEMA_VERSION = 1 as const;

export type Severity = "error" | "warning" | "info";

export type FindingLocation = {
  document?: string;
  section?: string;
  line?: number;
  jsonPath?: string;
};

export type Finding = {
  ruleId: string;
  severity: Severity;
  message: string;
  location?: FindingLocation;
  help?: string;
  specReference?: string;
  sourceRuleIds?: string[];
};

export type ReportSummary = {
  errorCount: number;
  warningCount: number;
  infoCount: number;
};

export type ProbeHop = {
  url: string;
  status: number;
  durationMs: number;
  contentType?: string;
  redirectTo?: string;
};

export type ConformanceReport = {
  schemaVersion: typeof REPORT_SCHEMA_VERSION;
  subject: string;
  startedAt: string;
  durationMs: number;
  findings: Finding[];
  summary: ReportSummary;
  probe?: ProbeHop[];
};

export const severityRank: Record<Severity, number> = {
  error: 0,
  warning: 1,
  info: 2,
};

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const severity = severityRank[left.severity] - severityRank[right.severity];
    if (severity !== 0) {
      return severity;
    }

    return firstDifference([
      [left.ruleId, right.ruleId],
      [findingLocationKey(left), findingLocationKey(right)],
      [left.message, right.message],
      [optionalTextKey(left.help), optionalTextKey(right.help)],
      [optionalTextKey(left.specReference), optionalTextKey(right.specReference)],
      [findingSourceRuleIdsKey(left), findingSourceRuleIdsKey(right)],
    ]);
  });
}

export function deduplicateFindings(findings: readonly Finding[]): Finding[] {
  const merged = new Map<string, Finding>();

  for (const finding of sortFindings(findings)) {
    const key = [
      finding.severity,
      finding.message,
      findingLocationKey(finding),
      finding.help ?? "",
      finding.specReference ?? "",
    ].join("\u0000");
    const current = merged.get(key);

    if (current === undefined) {
      merged.set(key, {
        ...finding,
        sourceRuleIds: [...new Set([finding.ruleId, ...(finding.sourceRuleIds ?? [])])].sort(
          compareText,
        ),
      });
      continue;
    }

    const sourceRuleIds = [
      ...new Set([
        ...(current.sourceRuleIds ?? [current.ruleId]),
        finding.ruleId,
        ...(finding.sourceRuleIds ?? []),
      ]),
    ].sort(compareText);

    merged.set(key, {
      ...current,
      ruleId: sourceRuleIds[0] ?? current.ruleId,
      sourceRuleIds,
    });
  }

  return sortFindings([...merged.values()]);
}

export function summarizeFindings(findings: readonly Finding[]): ReportSummary {
  return findings.reduce<ReportSummary>(
    (summary, finding) => {
      if (finding.severity === "error") {
        summary.errorCount += 1;
      } else if (finding.severity === "warning") {
        summary.warningCount += 1;
      } else {
        summary.infoCount += 1;
      }
      return summary;
    },
    { errorCount: 0, warningCount: 0, infoCount: 0 },
  );
}

function findingLocationKey(finding: Finding): string {
  const location = finding.location;
  if (location === undefined) {
    return "\u0000";
  }

  return [
    "\u0001",
    optionalTextKey(location.document),
    optionalTextKey(location.section),
    optionalNumberKey(location.line),
    optionalTextKey(location.jsonPath),
  ].join("\u0000");
}

function findingSourceRuleIdsKey(finding: Finding): string {
  if (finding.sourceRuleIds === undefined) {
    return "\u0000";
  }
  return `\u0001${[...new Set(finding.sourceRuleIds)].sort(compareText).join("\u0000")}`;
}

function optionalTextKey(value: string | undefined): string {
  return value === undefined ? "\u0000" : `\u0001${value}`;
}

function optionalNumberKey(value: number | undefined): string {
  return value === undefined ? "\u0000" : `\u0001${value}`;
}

function firstDifference(pairs: ReadonlyArray<readonly [string, string]>): number {
  for (const [left, right] of pairs) {
    const difference = compareText(left, right);
    if (difference !== 0) {
      return difference;
    }
  }
  return 0;
}

function compareText(left: string, right: string): number {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}
