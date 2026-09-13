import {
  type ConformanceReport,
  type Finding,
  type ProbeHop,
  type Severity,
  sortFindings,
} from "./model.js";

export interface Reporter {
  render(report: ConformanceReport): string;
}

/**
 * The canonical artifact is deliberately distinct from the full in-memory
 * report. It keeps CI diffs reproducible while callers of runConformanceCheck
 * retain the actual run and probe timing observations.
 */
export type CanonicalConformanceReport = Omit<
  ConformanceReport,
  "startedAt" | "durationMs" | "probe"
> & {
  probe?: Array<Omit<ProbeHop, "durationMs">>;
};

export type HumanReporterOptions = {
  color: boolean;
  verbose: boolean;
  quiet: boolean;
};

export class JsonReporter implements Reporter {
  public render(report: ConformanceReport): string {
    return `${JSON.stringify(canonicalizeReport(report), null, 2)}\n`;
  }
}

export class HumanReporter implements Reporter {
  public constructor(private readonly options: HumanReporterOptions) {}

  public render(report: ConformanceReport): string {
    if (this.options.quiet) {
      return "";
    }

    const lines = [`authmd check: ${report.subject}`, summaryLine(report, this.options.color)];
    const groups: Array<[Severity, string]> = [
      ["error", "Errors"],
      ["warning", "Warnings"],
      ["info", "Info"],
    ];

    for (const [severity, title] of groups) {
      const findings = report.findings.filter((finding) => finding.severity === severity);
      if (findings.length === 0) {
        continue;
      }

      lines.push("");
      lines.push(colorize(`${title} (${findings.length})`, severity, this.options.color));
      for (const finding of findings) {
        lines.push(formatFinding(finding, this.options));
      }
    }

    if (report.probe !== undefined) {
      lines.push("");
      lines.push("Read-only probe trace");
      for (const hop of report.probe) {
        const contentType = hop.contentType === undefined ? "" : ` ${hop.contentType}`;
        const redirect = hop.redirectTo === undefined ? "" : ` -> ${hop.redirectTo}`;
        lines.push(`  ${hop.status} ${hop.durationMs}ms ${hop.url}${contentType}${redirect}`);
      }
    }

    return `${lines.join("\n")}\n`;
  }
}

export function createReporter(json: boolean, options: HumanReporterOptions): Reporter {
  return json ? new JsonReporter() : new HumanReporter(options);
}

export function canonicalizeReport(report: ConformanceReport): CanonicalConformanceReport {
  return {
    schemaVersion: report.schemaVersion,
    subject: report.subject,
    findings: sortFindings(report.findings).map(orderedFinding),
    summary: {
      errorCount: report.summary.errorCount,
      warningCount: report.summary.warningCount,
      infoCount: report.summary.infoCount,
    },
    ...(report.probe === undefined
      ? {}
      : {
          probe: report.probe.map((hop) => ({
            url: hop.url,
            status: hop.status,
            ...(hop.contentType === undefined ? {} : { contentType: hop.contentType }),
            ...(hop.redirectTo === undefined ? {} : { redirectTo: hop.redirectTo }),
          })),
        }),
  };
}

function orderedFinding(finding: Finding): Finding {
  return {
    ruleId: finding.ruleId,
    severity: finding.severity,
    message: finding.message,
    ...(finding.location === undefined
      ? {}
      : {
          location: {
            ...(finding.location.document === undefined
              ? {}
              : { document: finding.location.document }),
            ...(finding.location.section === undefined
              ? {}
              : { section: finding.location.section }),
            ...(finding.location.line === undefined ? {} : { line: finding.location.line }),
            ...(finding.location.jsonPath === undefined
              ? {}
              : { jsonPath: finding.location.jsonPath }),
          },
        }),
    ...(finding.help === undefined ? {} : { help: finding.help }),
    ...(finding.specReference === undefined ? {} : { specReference: finding.specReference }),
    ...(finding.sourceRuleIds === undefined
      ? {}
      : { sourceRuleIds: [...new Set(finding.sourceRuleIds)].sort() }),
  };
}

function summaryLine(report: ConformanceReport, color: boolean): string {
  const summary =
    report.summary.errorCount +
    " errors, " +
    report.summary.warningCount +
    " warnings, " +
    report.summary.infoCount +
    " info";
  const severity: Severity =
    report.summary.errorCount > 0 ? "error" : report.summary.warningCount > 0 ? "warning" : "info";
  return colorize(summary, severity, color);
}

function formatFinding(finding: Finding, options: HumanReporterOptions): string {
  const prefix = colorize(`  [${finding.ruleId}]`, finding.severity, options.color);
  const location = formatLocation(finding);
  const detail = options.verbose ? formatDetail(finding) : "";
  return `${prefix} ${finding.message}${location}${detail}`;
}

function formatLocation(finding: Finding): string {
  if (finding.location === undefined) {
    return "";
  }

  const parts = [
    finding.location.document,
    finding.location.section,
    finding.location.line === undefined ? undefined : `line ${finding.location.line}`,
    finding.location.jsonPath,
  ].filter((part): part is string => part !== undefined);

  return parts.length === 0 ? "" : ` (${parts.join(", ")})`;
}

function formatDetail(finding: Finding): string {
  const details = [finding.help, finding.specReference].filter(
    (detail): detail is string => detail !== undefined,
  );
  return details.length === 0 ? "" : `\n      ${details.join(" · ")}`;
}

function colorize(value: string, severity: Severity, color: boolean): string {
  if (!color) {
    return value;
  }

  const code = severity === "error" ? "31" : severity === "warning" ? "33" : "36";
  return `\u001B[${code}m${value}\u001B[0m`;
}
