import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";

import { DEFAULT_CLI_VERSION } from "./version.mjs";

const DEFAULTS = {
  cliVersion: DEFAULT_CLI_VERSION,
  failOn: "error",
  jsonOutputPath: ".warden/conformance.json",
  probe: "false",
  workingDirectory: ".",
};

const VALID_FAIL_ON = new Set(["error", "warning", "never"]);
const EXACT_NPM_VERSION =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;

function value(env, name, fallback) {
  return (env[`WARDEN_INPUT_${name}`] ?? fallback).trim();
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function requireDirectory(pathname) {
  if (!existsSync(pathname) || !statSync(pathname).isDirectory()) {
    throw new Error(`working-directory does not exist or is not a directory: ${pathname}`);
  }
}

export function readInputs(env = process.env) {
  const url = value(env, "URL", "");
  const failOn = value(env, "FAIL_ON", DEFAULTS.failOn).toLowerCase();
  const probeValue = value(env, "PROBE", DEFAULTS.probe).toLowerCase();
  const jsonOutputPath = value(env, "JSON_OUTPUT_PATH", DEFAULTS.jsonOutputPath);
  const cliVersion = value(env, "CLI_VERSION", DEFAULTS.cliVersion);
  const workingDirectory = value(env, "WORKING_DIRECTORY", DEFAULTS.workingDirectory);

  if (!url) {
    throw new Error("url is required");
  }

  if (!VALID_FAIL_ON.has(failOn)) {
    throw new Error("fail-on must be one of: error, warning, never");
  }

  if (probeValue !== "true" && probeValue !== "false") {
    throw new Error("probe must be true or false");
  }

  if (!jsonOutputPath) {
    throw new Error("json-output-path must not be empty");
  }

  if (!EXACT_NPM_VERSION.test(cliVersion)) {
    throw new Error("cli-version must be an exact npm version such as 0.1.0");
  }

  if (!workingDirectory) {
    throw new Error("working-directory must not be empty");
  }

  return {
    cliVersion,
    failOn,
    jsonOutputPath,
    probe: probeValue === "true",
    url,
    workingDirectory,
  };
}

export function buildCliArguments(inputs, reportPath) {
  const argumentsForCli = [
    "--yes",
    "--package",
    `@warden/cli@${inputs.cliVersion}`,
    "--",
    "authmd",
    "check",
    inputs.url,
    "--json",
    "--output",
    reportPath,
    "--fail-on",
    inputs.failOn,
  ];

  if (inputs.probe) {
    argumentsForCli.push("--probe");
  }

  return argumentsForCli;
}

export function writeActionState(statePath, state) {
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`, "utf8");
}

export function readActionState(env = process.env) {
  const statePath = env.WARDEN_ACTION_STATE_PATH;

  if (!statePath) {
    throw new Error("Warden action state is unavailable; the prepare step did not complete");
  }

  return {
    path: statePath,
    state: JSON.parse(readFileSync(statePath, "utf8")),
  };
}

function appendKeyValue(pathname, key, entry) {
  const delimiter = `WARDEN_${randomUUID().replaceAll("-", "")}`;
  appendFileSync(pathname, `${key}<<${delimiter}\n${entry}\n${delimiter}\n`, "utf8");
}

function appendEnvironment(env, key, entry) {
  if (!env.GITHUB_ENV) {
    throw new Error("GITHUB_ENV is unavailable; this command must run in GitHub Actions");
  }

  appendKeyValue(env.GITHUB_ENV, key, entry);
}

export function appendOutput(env, key, entry) {
  if (!env.GITHUB_OUTPUT) {
    return;
  }

  appendKeyValue(env.GITHUB_OUTPUT, key, entry);
}

export function prepareAction(env = process.env, currentDirectory = process.cwd()) {
  const inputs = readInputs(env);
  const workspace = env.GITHUB_WORKSPACE ?? currentDirectory;
  const workingDirectory = resolve(workspace, inputs.workingDirectory);
  requireDirectory(workingDirectory);

  const reportPath = resolve(workingDirectory, inputs.jsonOutputPath);
  mkdirSync(dirname(reportPath), { recursive: true });

  const temporaryDirectory = env.RUNNER_TEMP ?? tmpdir();
  mkdirSync(temporaryDirectory, { recursive: true });
  const statePath = resolve(temporaryDirectory, `warden-action-${randomUUID()}.json`);
  const state = {
    schemaVersion: 1,
    inputs,
    reportPath,
    workingDirectory,
  };

  writeActionState(statePath, state);
  appendEnvironment(env, "WARDEN_ACTION_STATE_PATH", statePath);

  return { state, statePath };
}

function deletePriorReport(reportPath) {
  if (!existsSync(reportPath)) {
    return;
  }

  if (!statSync(reportPath).isFile()) {
    throw new Error(`json-output-path must name a file: ${reportPath}`);
  }

  rmSync(reportPath);
}

function invokeNpx(command, argumentsForCli, workingDirectory) {
  return spawnSync(command, argumentsForCli, {
    cwd: workingDirectory,
    stdio: "inherit",
  });
}

function exitCodeFrom(result) {
  return typeof result.status === "number" ? result.status : 1;
}

export function runCheck(env = process.env, invoke = invokeNpx) {
  const { path: statePath, state } = readActionState(env);

  try {
    deletePriorReport(state.reportPath);
    const argumentsForCli = buildCliArguments(state.inputs, state.reportPath);
    const command = env.WARDEN_NPX_COMMAND ?? "npx";
    const result = invoke(command, argumentsForCli, state.workingDirectory);

    state.check = {
      command,
      exitCode: exitCodeFrom(result),
      finishedAt: new Date().toISOString(),
      spawnError: result.error ? errorMessage(result.error) : undefined,
    };
  } catch (error) {
    state.check = {
      command: null,
      exitCode: 1,
      finishedAt: new Date().toISOString(),
      spawnError: errorMessage(error),
    };
  }

  writeActionState(statePath, state);
  return state.check.exitCode;
}

export function finishAction(env = process.env) {
  const { state } = readActionState(env);
  return state.presentation?.result === "success" ? 0 : 1;
}
