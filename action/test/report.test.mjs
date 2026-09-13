import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  annotationForFinding,
  buildPresentation,
  readReport,
  renderReport,
} from "../lib/report.mjs";
import {
  buildCliArguments,
  finishAction,
  prepareAction,
  readInputs,
  runCheck,
  writeActionState,
} from "../lib/runtime.mjs";

const inputs = {
  cliVersion: "0.1.0",
  failOn: "error",
  jsonOutputPath: ".warden/conformance.json",
  probe: false,
  url: "https://service.example",
  workingDirectory: ".",
};

describe("Warden conformance action", () => {
  it("defaults to an exact pinned CLI version and rejects npm tags or ranges", () => {
    const base = {
      WARDEN_INPUT_URL: "https://service.example",
    };

    expect(readInputs(base).cliVersion).toBe("0.1.0");
    expect(() => readInputs({ ...base, WARDEN_INPUT_CLI_VERSION: "latest" })).toThrow(
      "cli-version must be an exact npm version",
    );
    expect(() => readInputs({ ...base, WARDEN_INPUT_CLI_VERSION: "^0.1.0" })).toThrow(
      "cli-version must be an exact npm version",
    );
  });

  it("resolves the report under working-directory and shares state with later steps", () => {
    const directory = mkdtempSync(join(tmpdir(), "warden-action-test-"));
    const environmentPath = join(directory, "github-env.txt");

    try {
      const { state, statePath } = prepareAction(
        {
          GITHUB_ENV: environmentPath,
          GITHUB_WORKSPACE: directory,
          RUNNER_TEMP: directory,
          WARDEN_INPUT_CLI_VERSION: "0.1.0",
          WARDEN_INPUT_FAIL_ON: "warning",
          WARDEN_INPUT_JSON_OUTPUT_PATH: "reports/conformance.json",
          WARDEN_INPUT_PROBE: "false",
          WARDEN_INPUT_URL: "https://service.example",
          WARDEN_INPUT_WORKING_DIRECTORY: ".",
        },
        directory,
      );

      expect(state.reportPath).toBe(join(directory, "reports/conformance.json"));
      expect(statePath).toMatch(new RegExp(`^${directory}/warden-action-`));
      expect(readFileSync(environmentPath, "utf8")).toContain("WARDEN_ACTION_STATE_PATH<<");
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it("keeps the default check read-only and invokes the pinned published CLI", () => {
    const argumentsForCli = buildCliArguments(inputs, "/tmp/conformance.json");

    expect(argumentsForCli).toEqual([
      "--yes",
      "--package",
      "@warden/cli@0.1.0",
      "--",
      "authmd",
      "check",
      "https://service.example",
      "--json",
      "--output",
      "/tmp/conformance.json",
      "--fail-on",
      "error",
    ]);
    expect(argumentsForCli).not.toContain("--probe");
  });

  it("renders counts and every actionable finding in the job summary", () => {
    const presentation = buildPresentation({
      report: {
        findings: [
          {
            message: "Missing an authorization server declaration",
            ruleId: "AUTHMD-101",
            severity: "error",
          },
          {
            message: "The protected-resource document does not name a resource",
            ruleId: "AUTHMD-202",
            severity: "warning",
          },
          {
            message: "Probe was skipped",
            ruleId: "AUTHMD-301",
            severity: "info",
          },
        ],
        schemaVersion: 1,
        subject: "https://service.example",
        summary: { errorCount: 1, infoCount: 1, warningCount: 1 },
      },
      reportError: undefined,
      state: { check: { exitCode: 1 }, inputs },
    });

    expect(presentation.result).toBe("failure");
    expect(presentation.errorCount).toBe(1);
    expect(presentation.warningCount).toBe(1);
    expect(presentation.markdown).toContain("| failure | 1 | 1 |");
    expect(presentation.markdown).toContain(
      "| error | AUTHMD-101 | Missing an authorization server declaration |",
    );
    expect(presentation.markdown).toContain(
      "| warning | AUTHMD-202 | The protected-resource document does not name a resource |",
    );
    expect(presentation.markdown).not.toContain("AUTHMD-301");
    expect(presentation.annotations).toEqual([
      "::error title=warden%3A AUTHMD-101::[AUTHMD-101] Missing an authorization server declaration",
      "::warning title=warden%3A AUTHMD-202::[AUTHMD-202] The protected-resource document does not name a resource",
    ]);
  });

  it("fails safely when the CLI did not produce a report", () => {
    const presentation = buildPresentation({
      report: undefined,
      reportError: "Report was not written: /tmp/conformance.json",
      state: { check: { exitCode: 0 }, inputs },
    });

    expect(presentation.result).toBe("failure");
    expect(presentation.markdown).toContain("### Report unavailable");
    expect(presentation.errorCount).toBe(0);
    expect(presentation.warningCount).toBe(0);
  });

  it("escapes annotation messages so a finding cannot add a workflow command", () => {
    expect(
      annotationForFinding({
        message: "bad\n::error::injected",
        ruleId: "AUTHMD:303",
        severity: "error",
      }),
    ).toBe("::error title=warden%3A AUTHMD%3A303::[AUTHMD:303] bad%0A::error::injected");
  });

  it("rejects a JSON file that does not meet the report contract", () => {
    const directory = mkdtempSync(join(tmpdir(), "warden-action-test-"));
    const reportPath = join(directory, "report.json");

    try {
      writeFileSync(reportPath, JSON.stringify({ findings: [] }));
      expect(readReport(reportPath)).toMatchObject({
        error: "Report is not a valid Warden JSON report: Report schemaVersion must be 1",
      });
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });

  it("writes outputs and a summary after a successful CLI check", () => {
    const directory = mkdtempSync(join(tmpdir(), "warden-action-test-"));
    const reportPath = join(directory, "report.json");
    const statePath = join(directory, "state.json");
    const stepSummaryPath = join(directory, "step-summary.md");
    const outputPath = join(directory, "output.txt");
    const environment = {
      GITHUB_OUTPUT: outputPath,
      GITHUB_STEP_SUMMARY: stepSummaryPath,
      WARDEN_ACTION_STATE_PATH: statePath,
    };
    const invocations = [];

    try {
      writeActionState(statePath, {
        inputs,
        reportPath,
        schemaVersion: 1,
        workingDirectory: directory,
      });

      expect(
        runCheck(environment, (command, argumentsForCli) => {
          invocations.push({ argumentsForCli, command });
          const outputFlag = argumentsForCli.indexOf("--output");
          const outputFile = argumentsForCli[outputFlag + 1];
          writeFileSync(
            outputFile,
            JSON.stringify({
              durationMs: 12,
              findings: [],
              schemaVersion: 1,
              startedAt: "2026-09-13T00:00:00.000Z",
              subject: "https://service.example",
              summary: { errorCount: 0, infoCount: 0, warningCount: 0 },
            }),
          );
          return { status: 0 };
        }),
      ).toBe(0);

      const presentation = renderReport(environment);
      expect(finishAction(environment)).toBe(0);
      expect(invocations).toEqual([
        {
          argumentsForCli: [
            "--yes",
            "--package",
            "@warden/cli@0.1.0",
            "--",
            "authmd",
            "check",
            "https://service.example",
            "--json",
            "--output",
            reportPath,
            "--fail-on",
            "error",
          ],
          command: "npx",
        },
      ]);
      expect(presentation.result).toBe("success");
      expect(readFileSync(stepSummaryPath, "utf8")).toContain("| success | 0 | 0 |");
      expect(readFileSync(outputPath, "utf8")).toContain("result<<");
      expect(readFileSync(outputPath, "utf8")).toContain("report-path<<");
    } finally {
      rmSync(directory, { force: true, recursive: true });
    }
  });
});
