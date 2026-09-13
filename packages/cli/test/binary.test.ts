import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

const packageDirectory = fileURLToPath(new URL("..", import.meta.url));
const repositoryDirectory = fileURLToPath(new URL("../../..", import.meta.url));
const tscPath = join(repositoryDirectory, "node_modules", "typescript", "bin", "tsc");
const binaryPath = join(packageDirectory, "dist", "index.js");
const fixtureDirectory = fileURLToPath(new URL("./fixtures/authmd/", import.meta.url));

describe("built authmd binary", () => {
  beforeAll(async () => {
    await run(process.execPath, [tscPath, "-p", "packages/cli/tsconfig.json"], repositoryDirectory);
    await access(binaryPath);
  });

  it.each([
    [0, "no findings", [fixturePath("valid.md")]],
    [1, "findings", [fixturePath("invalid-sections.md")]],
    [2, "usage failure", ["--unknown"]],
    [3, "unexpected failure", [fixturePath("valid.md")]],
  ])("exits %i for %s", async (expectedCode, name, args) => {
    const result = await run(
      process.execPath,
      [binaryPath, "check", ...args],
      repositoryDirectory,
      name === "unexpected failure" ? { AUTHMD_TEST_FORCE_INTERNAL_ERROR: "1" } : {},
    );

    expect(result.code).toBe(expectedCode);
    if (expectedCode === 2) {
      expect(result.stderr).toContain("Unknown flag");
      expect(result.stderr).not.toContain(" at ");
    }
  });

  it("does not run the command-line program when imported as a library", async () => {
    const program = [
      `const initialExitCode = process.exitCode;`,
      `const api = await import(${JSON.stringify(pathToFileURL(binaryPath).href)});`,
      `if (typeof api.runConformanceCheck !== "function" || process.exitCode !== initialExitCode) {`,
      `  process.exitCode = 11;`,
      `}`,
    ].join("\n");
    const result = await run(
      process.execPath,
      ["--input-type=module", "--eval", program],
      repositoryDirectory,
    );

    expect(result.code).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("");
  });
});

function fixturePath(name: string): string {
  return join(fixtureDirectory, name);
}

async function run(
  command: string,
  args: readonly string[],
  cwd: string,
  additionalEnvironment: NodeJS.ProcessEnv = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...additionalEnvironment },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", rejectPromise);
    child.on("close", (code) => {
      resolvePromise({ code, stdout, stderr });
    });
  });
}
