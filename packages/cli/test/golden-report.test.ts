import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { runConformanceCheck } from "../src/check.js";
import { JsonReporter } from "../src/reporter.js";
import { conformantTransport, response, StubTransport } from "./helpers.js";

const fixtureDirectory = new URL("./fixtures/reports/", import.meta.url);
const fixedNow = () => Date.parse("2026-09-13T00:00:00.000Z");

describe("committed conformance report fixtures", () => {
  it("matches the passing and failing golden reports", async () => {
    const passing = await runConformanceCheck("https://service.test/", {
      transport: conformantTransport(),
      now: fixedNow,
    });
    const failing = await runConformanceCheck("https://service.test/", {
      transport: new StubTransport({
        "https://service.test/auth.md": response("https://service.test/auth.md", 404, "missing", {
          "content-type": "text/markdown",
        }),
      }),
      now: fixedNow,
    });
    const reporter = new JsonReporter();

    expect(JSON.parse(reporter.render(passing))).toEqual(JSON.parse(await fixture("passing.json")));
    expect(JSON.parse(reporter.render(failing))).toEqual(JSON.parse(await fixture("failing.json")));
  });

  it("matches the committed read-only probe trace", async () => {
    const report = await runConformanceCheck("https://service.test/", {
      transport: conformantTransport(),
      now: fixedNow,
      probe: true,
    });

    expect(report.probe).toEqual(JSON.parse(await fixture("probe.json")));
  });

  it("validates JSON reporter output against the committed report schema fixture", async () => {
    const report = await runConformanceCheck("https://service.test/", {
      transport: conformantTransport(),
      now: fixedNow,
    });
    const schema = JSON.parse(await fixture("report.schema.json")) as Record<string, unknown>;
    const output = JSON.parse(new JsonReporter().render(report)) as unknown;

    expect(validateReportSchema(output, schema)).toEqual([]);
  });
});

async function fixture(name: string): Promise<string> {
  return readFile(fileURLToPath(new URL(name, fixtureDirectory)), "utf8");
}

function validateReportSchema(value: unknown, schema: Record<string, unknown>): string[] {
  if (!isRecord(value)) {
    return ["report must be an object"];
  }

  const required = schema.required;
  if (!Array.isArray(required) || !required.every((key) => typeof key === "string")) {
    return ["schema fixture has invalid required keys"];
  }

  const errors: string[] = [];
  for (const key of required) {
    if (!(key in value)) {
      errors.push(`missing ${key}`);
    }
  }
  if (value.schemaVersion !== 1) {
    errors.push("invalid schemaVersion");
  }
  if (typeof value.subject !== "string") {
    errors.push("invalid report identity");
  }
  if (!Array.isArray(value.findings)) {
    errors.push("invalid findings");
  } else {
    for (const finding of value.findings) {
      if (
        !isRecord(finding) ||
        typeof finding.ruleId !== "string" ||
        typeof finding.message !== "string" ||
        !["error", "warning", "info"].includes(finding.severity as string)
      ) {
        errors.push("invalid finding");
      }
    }
  }
  if (!isRecord(value.summary)) {
    errors.push("invalid summary");
  }

  return errors;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
