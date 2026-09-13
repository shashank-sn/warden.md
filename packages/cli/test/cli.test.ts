import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { type CliEnvironment, EXIT_CODES, runCli } from "../src/cli.js";
import { StubTransport } from "./helpers.js";

const fixtureDirectory = new URL("./fixtures/authmd/", import.meta.url);

describe("authmd CLI contract", () => {
  it("emits a versioned JSON report for a valid local fixture", async () => {
    const harness = environment();

    const code = await runCli(["check", fixturePath("valid.md"), "--json"], harness.environment);

    expect(code).toBe(EXIT_CODES.success);
    expect(JSON.parse(harness.stdout.join(""))).toMatchObject({
      schemaVersion: 1,
      findings: [],
      summary: { errorCount: 0, warningCount: 0, infoCount: 0 },
    });
  });

  it("applies warning and never thresholds consistently", async () => {
    const warning = environment();
    const warningCode = await runCli(
      ["check", fixturePath("warning.md"), "--fail-on", "warning"],
      warning.environment,
    );
    expect(warningCode).toBe(EXIT_CODES.findings);

    const never = environment();
    const neverCode = await runCli(
      ["check", fixturePath("invalid-sections.md"), "--fail-on", "never"],
      never.environment,
    );
    expect(neverCode).toBe(EXIT_CODES.success);
  });

  it("loads a config and writes the same JSON report selected for CI", async () => {
    const written: Array<{ path: string; contents: string }> = [];
    const configuredReadFile = (async (path: string | Buffer | URL) => {
      if (String(path) === "check.json") {
        return '{"failOn":"warning"}';
      }
      return readFile(path);
    }) as typeof readFile;
    const configuredWriteFile = (async (path: string | Buffer | URL, contents: string) => {
      written.push({ path: String(path), contents });
    }) as typeof writeFile;
    const harness = environment({
      readFile: configuredReadFile,
      writeFile: configuredWriteFile,
    });

    const code = await runCli(
      ["check", fixturePath("warning.md"), "--config", "check.json", "--output", "report.json"],
      harness.environment,
    );

    expect(code).toBe(EXIT_CODES.findings);
    expect(written).toEqual([
      expect.objectContaining({
        path: "report.json",
        contents: expect.stringContaining('"schemaVersion": 1'),
      }),
    ]);
  });

  it.each([
    [["--unknown"], "Unknown flag"],
    [["check"], "requires a URL or auth.md path"],
    [["check", "not-a-url"], "Expected a valid HTTPS URL or an auth.md file path"],
    [["check", fixturePath("valid.md"), "--timeout", "bad"], "must be a positive integer"],
  ])("returns exit 2 for usage failures: %s", async (argv, message) => {
    const harness = environment();

    const code = await runCli(argv, harness.environment);

    expect(code).toBe(EXIT_CODES.usage);
    expect(harness.stderr.join("")).toContain(message);
    expect(harness.stderr.join("")).not.toContain(" at ");
  });

  it("suppresses color without a TTY and honors FORCE_COLOR", async () => {
    const plain = environment({ stdoutIsTTY: false });
    await runCli(["check", fixturePath("warning.md")], plain.environment);
    expect(plain.stdout.join("")).not.toContain("\u001B[");

    const colored = environment({ stdoutIsTTY: false, forceColor: "1" });
    await runCli(["check", fixturePath("warning.md")], colored.environment);
    expect(colored.stdout.join("")).toContain("\u001B[");
  });

  it("uses exit 3 only for an unexpected internal error", async () => {
    const harness = environment({ forceInternalError: true });

    const code = await runCli(["check", fixturePath("valid.md")], harness.environment);

    expect(code).toBe(EXIT_CODES.internal);
    expect(harness.stderr.join("")).toBe(
      "Unexpected internal error. Run with --verbose for details.\n",
    );
  });

  it("documents every public flag and the exit-code contract", async () => {
    const harness = environment();

    const code = await runCli(["check", "--help"], harness.environment);

    expect(code).toBe(EXIT_CODES.success);
    expect(harness.stdout.join("")).toContain("--json");
    expect(harness.stdout.join("")).toContain("--verbose");
    expect(harness.stdout.join("")).toContain("--quiet");
    expect(harness.stdout.join("")).toContain("--timeout <ms>");
    expect(harness.stdout.join("")).toContain("--config <path>");
    expect(harness.stdout.join("")).toContain("--help, -h");
    expect(harness.stdout.join("")).toContain("--version, -v");
    expect(harness.stdout.join("")).toContain("  3  Unexpected internal failure.");
  });
});

function fixturePath(name: string): string {
  return fileURLToPath(new URL(name, fixtureDirectory));
}

function environment(overrides: Partial<CliEnvironment> = {}) {
  const stdout: string[] = [];
  const stderr: string[] = [];
  const environment: CliEnvironment = {
    transport: new StubTransport({}),
    stdout: (value) => stdout.push(value),
    stderr: (value) => stderr.push(value),
    stdoutIsTTY: false,
    readFile,
    writeFile,
    forceInternalError: false,
    ...overrides,
  };

  return { environment, stdout, stderr };
}
