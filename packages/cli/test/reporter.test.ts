import { describe, expect, it } from "vitest";

import {
  deduplicateFindings,
  REPORT_SCHEMA_VERSION,
  sortFindings,
  summarizeFindings,
} from "../src/model.js";
import { canonicalizeReport, HumanReporter, JsonReporter } from "../src/reporter.js";

describe("findings and reporters", () => {
  it("uses locale-independent code-unit ordering for canonical findings", () => {
    const findings = sortFindings([
      { ruleId: "RULE", severity: "error", message: "ä" },
      { ruleId: "RULE", severity: "error", message: "z" },
    ]);

    expect(findings.map((finding) => finding.message)).toEqual(["z", "ä"]);
  });

  it("fully tie-breaks canonical findings and canonicalizes source ids", () => {
    const findings = [
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Same message",
        location: { jsonPath: "$.same" },
        help: "Help B",
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Same message",
        location: { jsonPath: "$.same" },
        help: "Help A",
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Same message",
        location: { jsonPath: "$.same" },
        help: "Help A",
        specReference: "Spec B",
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Same message",
        location: { jsonPath: "$.same" },
        help: "Help A",
        specReference: "Spec A",
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Same message",
        location: { jsonPath: "$.same" },
        help: "Help A",
        specReference: "Spec A",
        sourceRuleIds: ["SOURCE_B", "SOURCE_A"],
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Same message",
        location: { jsonPath: "$.same" },
        help: "Help A",
        specReference: "Spec A",
        sourceRuleIds: ["SOURCE_C"],
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Optional fields",
      },
      {
        ruleId: "RULE",
        severity: "error" as const,
        message: "Optional fields",
        location: {},
        help: "",
        specReference: "",
        sourceRuleIds: [],
      },
    ];
    const report = {
      schemaVersion: REPORT_SCHEMA_VERSION,
      subject: "https://service.test/",
      startedAt: "2026-09-13T00:00:00.000Z",
      durationMs: 0,
      findings,
      summary: summarizeFindings(findings),
    };
    const reporter = new JsonReporter();

    expect(sortFindings(findings)).toEqual(sortFindings([...findings].reverse()));
    expect(reporter.render(report)).toBe(
      reporter.render({ ...report, findings: [...findings].reverse() }),
    );
    expect(JSON.parse(reporter.render(report)).findings).toContainEqual(
      expect.objectContaining({ sourceRuleIds: ["SOURCE_A", "SOURCE_B"] }),
    );
  });

  it("merges duplicate findings while preserving source rule ids", () => {
    const findings = deduplicateFindings([
      {
        ruleId: "SECOND_SOURCE",
        severity: "error",
        message: "Issuer is inconsistent.",
        location: { jsonPath: "$.issuer" },
      },
      {
        ruleId: "FIRST_SOURCE",
        severity: "error",
        message: "Issuer is inconsistent.",
        location: { jsonPath: "$.issuer" },
      },
    ]);

    expect(findings).toEqual([
      expect.objectContaining({
        ruleId: "FIRST_SOURCE",
        sourceRuleIds: ["FIRST_SOURCE", "SECOND_SOURCE"],
      }),
    ]);
  });

  it("renders versioned JSON byte-stably despite volatile observations", () => {
    const report = reportFixture();
    const reporter = new JsonReporter();
    const laterReport = { ...report, startedAt: "2026-09-13T01:23:45.000Z", durationMs: 9876 };

    expect(reporter.render(report)).toBe(reporter.render(laterReport));
    expect(JSON.parse(reporter.render(report))).toMatchObject({
      schemaVersion: REPORT_SCHEMA_VERSION,
      subject: "https://service.test/",
      findings: [
        {
          ruleId: "TEST_WARNING",
          severity: "warning",
          location: { jsonPath: "$.agent_auth" },
        },
      ],
    });
    expect(report).toMatchObject({
      startedAt: "2026-09-13T00:00:00.000Z",
      durationMs: 0,
    });
  });

  it("makes the full timing-bearing report and canonical artifact explicit", () => {
    const report = reportFixture();
    const canonical = canonicalizeReport(report);

    expect(report).toMatchObject({
      startedAt: "2026-09-13T00:00:00.000Z",
      durationMs: 0,
    });
    expect(canonical).not.toHaveProperty("startedAt");
    expect(canonical).not.toHaveProperty("durationMs");
  });

  it("omits volatile probe durations from the stable JSON artifact", () => {
    const reporter = new JsonReporter();
    const report = {
      ...reportFixture(),
      probe: [{ url: "https://service.test/auth.md", status: 200, durationMs: 4 }],
    };
    const slowerReport = {
      ...report,
      probe: [{ ...report.probe[0], durationMs: 4000 }],
    };

    expect(reporter.render(report)).toBe(reporter.render(slowerReport));
    expect(JSON.parse(reporter.render(report))).toMatchObject({
      probe: [{ status: 200, url: "https://service.test/auth.md" }],
    });
    expect(reporter.render(report)).not.toContain("durationMs");
  });

  it("groups human output without ANSI color when stdout is not a TTY", () => {
    const output = new HumanReporter({ color: false, verbose: true, quiet: false }).render(
      reportFixture(),
    );

    expect(output).toContain("Warnings (1)");
    expect(output).toContain("[TEST_WARNING] Test warning");
    expect(output).toContain("Fix it · Test specification");
    expect(output).not.toContain("\u001B[");
  });
});

function reportFixture() {
  const findings = [
    {
      ruleId: "TEST_WARNING",
      severity: "warning" as const,
      message: "Test warning",
      location: { jsonPath: "$.agent_auth" },
      help: "Fix it",
      specReference: "Test specification",
      sourceRuleIds: ["TEST_WARNING"],
    },
  ];

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    subject: "https://service.test/",
    startedAt: "2026-09-13T00:00:00.000Z",
    durationMs: 0,
    findings,
    summary: summarizeFindings(findings),
  };
}
