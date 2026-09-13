import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { appendOutput, readActionState, writeActionState } from "./runtime.mjs";

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function nonNegativeInteger(value) {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : undefined;
}

function tableCell(value) {
  return String(value ?? "")
    .replaceAll("\\", "\\\\")
    .replaceAll("|", "\\|")
    .replaceAll("\r\n", "<br>")
    .replaceAll("\n", "<br>")
    .replaceAll("\r", "<br>");
}

function inlineCode(value) {
  return String(value ?? "")
    .replaceAll("`", "\\`")
    .replaceAll("\r", " ")
    .replaceAll("\n", " ");
}

function commandMessage(value) {
  return String(value ?? "")
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
}

function commandProperty(value) {
  return commandMessage(value).replaceAll(":", "%3A").replaceAll(",", "%2C");
}

function reportValidationError(report) {
  if (!isRecord(report)) {
    return "Report is not a JSON object";
  }

  if (report.schemaVersion !== 1) {
    return "Report schemaVersion must be 1";
  }

  if (typeof report.subject !== "string" || !report.subject) {
    return "Report subject must be a non-empty string";
  }

  if (!Array.isArray(report.findings)) {
    return "Report must include a findings array";
  }

  if (!isRecord(report.summary)) {
    return "Report must include a summary object";
  }

  for (const field of ["errorCount", "warningCount", "infoCount"]) {
    if (nonNegativeInteger(report.summary[field]) === undefined) {
      return `Report summary.${field} must be a non-negative integer`;
    }
  }

  for (const finding of report.findings) {
    if (!isRecord(finding)) {
      return "Every report finding must be an object";
    }

    if (typeof finding.ruleId !== "string" || !finding.ruleId) {
      return "Every report finding must have a non-empty ruleId";
    }

    if (!["error", "warning", "info"].includes(finding.severity)) {
      return "Every report finding must have severity error, warning, or info";
    }

    if (typeof finding.message !== "string" || !finding.message) {
      return "Every report finding must have a non-empty message";
    }
  }

  return undefined;
}

export function readReport(reportPath) {
  if (!existsSync(reportPath)) {
    return { error: `Report was not written: ${reportPath}`, report: undefined };
  }

  try {
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    const validationError = reportValidationError(report);

    if (validationError) {
      return {
        error: `Report is not a valid Warden JSON report: ${validationError}`,
        report: undefined,
      };
    }

    return { error: undefined, report };
  } catch (error) {
    return { error: `Report could not be read: ${errorMessage(error)}`, report: undefined };
  }
}

function findingsFrom(report) {
  if (!report || !Array.isArray(report.findings)) {
    return [];
  }

  return report.findings.filter(isRecord);
}

function severityOf(finding) {
  return typeof finding.severity === "string" ? finding.severity.toLowerCase() : "unknown";
}

function locationText(location) {
  if (typeof location === "string" && location) {
    return ` (${location})`;
  }

  if (!isRecord(location)) {
    return "";
  }

  const parts = [
    typeof location.document === "string" ? location.document : undefined,
    typeof location.section === "string" ? location.section : undefined,
    typeof location.line === "number" ? `line ${location.line}` : undefined,
    typeof location.jsonPath === "string" ? location.jsonPath : undefined,
  ].filter((part) => part !== undefined);

  return parts.length === 0 ? "" : ` (${parts.join(", ")})`;
}

function count(report, field, findings, severity) {
  const reported = isRecord(report?.summary)
    ? nonNegativeInteger(report.summary[field])
    : undefined;
  return reported ?? findings.filter((finding) => severityOf(finding) === severity).length;
}

export function annotationForFinding(finding) {
  const severity = severityOf(finding);
  const level = severity === "error" ? "error" : "warning";
  const ruleId =
    typeof finding.ruleId === "string" && finding.ruleId ? finding.ruleId : "unknown-rule";
  const message =
    typeof finding.message === "string" && finding.message
      ? finding.message
      : "No message supplied";
  const location = locationText(finding.location);

  return `::${level} title=${commandProperty(`warden: ${ruleId}`)}::${commandMessage(`[${ruleId}] ${message}${location}`)}`;
}

export function buildPresentation({ report, reportError, state }) {
  const findings = findingsFrom(report);
  const actionableFindings = findings.filter((finding) => {
    const severity = severityOf(finding);
    return severity === "error" || severity === "warning";
  });
  const errorCount = count(report, "errorCount", findings, "error");
  const warningCount = count(report, "warningCount", findings, "warning");
  const cliExitCode = state.check?.exitCode;
  const result = report && cliExitCode === 0 ? "success" : "failure";
  const subject =
    typeof report?.subject === "string" && report.subject ? report.subject : state.inputs.url;
  const lines = [
    "## Warden conformance check",
    "",
    "| Result | Errors | Warnings |",
    "| --- | ---: | ---: |",
    `| ${result} | ${errorCount} | ${warningCount} |`,
    "",
    `Target: \`${inlineCode(subject)}\``,
    "",
  ];

  if (reportError) {
    lines.push("### Report unavailable", "", tableCell(reportError), "");
  }

  if (typeof cliExitCode === "number") {
    lines.push(`CLI exit code: ${cliExitCode}`, "");
  }

  lines.push("### Error and warning findings", "");

  if (actionableFindings.length === 0) {
    lines.push("No error or warning findings.", "");
  } else {
    lines.push("| Severity | Rule | Message |", "| --- | --- | --- |");
    for (const finding of actionableFindings) {
      const ruleId =
        typeof finding.ruleId === "string" && finding.ruleId ? finding.ruleId : "unknown-rule";
      const message =
        typeof finding.message === "string" && finding.message
          ? finding.message
          : "No message supplied";
      lines.push(
        `| ${tableCell(severityOf(finding))} | ${tableCell(ruleId)} | ${tableCell(message)} |`,
      );
    }
    lines.push("");
  }

  return {
    annotations: actionableFindings.map(annotationForFinding),
    errorCount,
    markdown: lines.join("\n"),
    result,
    warningCount,
  };
}

export function renderReport(env = process.env) {
  const { path: statePath, state } = readActionState(env);
  const { error: reportError, report } = readReport(state.reportPath);
  const presentation = buildPresentation({ report, reportError, state });

  if (env.GITHUB_STEP_SUMMARY) {
    appendFileSync(env.GITHUB_STEP_SUMMARY, `${presentation.markdown}\n`, "utf8");
  } else {
    process.stdout.write(`${presentation.markdown}\n`);
  }

  for (const annotation of presentation.annotations) {
    process.stdout.write(`${annotation}\n`);
  }

  appendOutput(env, "result", presentation.result);
  appendOutput(env, "error-count", String(presentation.errorCount));
  appendOutput(env, "warning-count", String(presentation.warningCount));
  appendOutput(env, "report-path", state.reportPath);

  state.presentation = {
    errorCount: presentation.errorCount,
    result: presentation.result,
    warningCount: presentation.warningCount,
  };
  writeActionState(statePath, state);

  return presentation;
}
