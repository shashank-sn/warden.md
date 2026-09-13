import { readFileSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";

import { CheckInputError, DEFAULT_CHECK_OPTIONS, runConformanceCheck } from "./check.js";
import { createReporter, JsonReporter } from "./reporter.js";
import { createFetchTransport, type Transport } from "./transport.js";

export const CLI_VERSION = readPackageVersion();

export const EXIT_CODES = {
  success: 0,
  findings: 1,
  usage: 2,
  internal: 3,
} as const;

const failOnValues = new Set(["error", "warning", "never"]);

type FailOn = "error" | "warning" | "never";

type ParsedArgs = {
  command?: string;
  subject?: string;
  json: boolean;
  verbose: boolean;
  quiet: boolean;
  probe: boolean;
  help: boolean;
  version: boolean;
  timeoutMs?: number;
  configPath?: string;
  outputPath?: string;
  failOn?: FailOn;
};

type FileConfig = {
  timeoutMs?: number;
  maxBytes?: number;
  maxRedirects?: number;
  probe?: boolean;
  failOn?: FailOn;
};

export type CliEnvironment = {
  transport: Transport;
  stdout: (value: string) => void;
  stderr: (value: string) => void;
  stdoutIsTTY: boolean;
  forceColor?: string;
  readFile: typeof readFile;
  writeFile: typeof writeFile;
  forceInternalError: boolean;
};

class UsageError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

function readPackageVersion(): string {
  try {
    const parsed: unknown = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    );
    if (isRecord(parsed) && typeof parsed.version === "string") {
      return parsed.version;
    }
  } catch {
    // A version string is unavailable only in a malformed local development checkout.
  }
  return "0.0.0";
}

export async function runCli(
  argv: readonly string[],
  environment: CliEnvironment = createCliEnvironment(),
): Promise<number> {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (error) {
    return writeUsageError(environment, error);
  }

  if (parsed.help) {
    environment.stdout(helpText());
    return EXIT_CODES.success;
  }

  if (parsed.version) {
    environment.stdout(`${CLI_VERSION}\n`);
    return EXIT_CODES.success;
  }

  try {
    if (parsed.command !== "check") {
      throw new UsageError("Expected the check command.");
    }
    if (parsed.subject === undefined) {
      throw new UsageError("authmd check requires a URL or auth.md path.");
    }

    const fileConfig = await loadConfig(parsed.configPath, environment);
    const config = mergeConfig(fileConfig, parsed);

    if (environment.forceInternalError) {
      throw new Error("Forced internal error for binary integration testing.");
    }

    const report = await runConformanceCheck(parsed.subject, {
      transport: environment.transport,
      timeoutMs: config.timeoutMs,
      maxBytes: config.maxBytes,
      maxRedirects: config.maxRedirects,
      probe: config.probe,
    });
    const reporter = createReporter(parsed.json, {
      color: shouldUseColor(environment),
      verbose: parsed.verbose,
      quiet: parsed.quiet,
    });
    environment.stdout(reporter.render(report));

    if (parsed.outputPath !== undefined) {
      await environment.writeFile(parsed.outputPath, new JsonReporter().render(report), "utf8");
    }

    return exitCodeFor(report.summary.errorCount, report.summary.warningCount, config.failOn);
  } catch (error) {
    if (error instanceof UsageError || error instanceof CheckInputError) {
      return writeUsageError(environment, error);
    }

    environment.stderr(internalErrorMessage(error, parsed.verbose));
    return EXIT_CODES.internal;
  }
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    json: false,
    verbose: false,
    quiet: false,
    probe: false,
    help: false,
    version: false,
  };
  const positionals: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === undefined) {
      continue;
    }

    if (!argument.startsWith("-") || argument === "-") {
      positionals.push(argument);
      continue;
    }

    const [flag, inlineValue] = splitFlag(argument);
    if (flag === "--json") {
      rejectValue(flag, inlineValue);
      parsed.json = true;
    } else if (flag === "--verbose") {
      rejectValue(flag, inlineValue);
      parsed.verbose = true;
    } else if (flag === "--quiet") {
      rejectValue(flag, inlineValue);
      parsed.quiet = true;
    } else if (flag === "--probe") {
      rejectValue(flag, inlineValue);
      parsed.probe = true;
    } else if (flag === "--help" || flag === "-h") {
      rejectValue(flag, inlineValue);
      parsed.help = true;
    } else if (flag === "--version" || flag === "-v") {
      rejectValue(flag, inlineValue);
      parsed.version = true;
    } else if (flag === "--timeout") {
      parsed.timeoutMs = parsePositiveInteger(flag, valueForFlag(argv, index, inlineValue));
      if (inlineValue === undefined) {
        index += 1;
      }
    } else if (flag === "--config") {
      parsed.configPath = valueForFlag(argv, index, inlineValue);
      if (inlineValue === undefined) {
        index += 1;
      }
    } else if (flag === "--output") {
      parsed.outputPath = valueForFlag(argv, index, inlineValue);
      if (inlineValue === undefined) {
        index += 1;
      }
    } else if (flag === "--fail-on") {
      const value = valueForFlag(argv, index, inlineValue);
      if (!failOnValues.has(value)) {
        throw new UsageError("--fail-on must be error, warning, or never.");
      }
      parsed.failOn = value as FailOn;
      if (inlineValue === undefined) {
        index += 1;
      }
    } else {
      throw new UsageError(`Unknown flag: ${argument}`);
    }
  }

  parsed.command = positionals[0];
  parsed.subject = positionals[1];
  if (positionals.length > 2) {
    throw new UsageError("check accepts exactly one URL or auth.md path.");
  }

  return parsed;
}

function createCliEnvironment(): CliEnvironment {
  return {
    transport: createFetchTransport(),
    stdout: (value) => process.stdout.write(value),
    stderr: (value) => process.stderr.write(value),
    stdoutIsTTY: process.stdout.isTTY === true,
    ...(process.env.FORCE_COLOR === undefined ? {} : { forceColor: process.env.FORCE_COLOR }),
    readFile,
    writeFile,
    forceInternalError: process.env.AUTHMD_TEST_FORCE_INTERNAL_ERROR === "1",
  };
}

async function loadConfig(
  path: string | undefined,
  environment: CliEnvironment,
): Promise<FileConfig> {
  if (path === undefined) {
    return {};
  }

  let source: string;
  try {
    source = await environment.readFile(path, "utf8");
  } catch {
    throw new UsageError(`Could not read config file: ${path}`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new UsageError(`Config file is not valid JSON: ${path}`);
  }

  if (!isRecord(parsed)) {
    throw new UsageError("Config file must contain a JSON object.");
  }

  const config: FileConfig = {};
  if (parsed.timeoutMs !== undefined) {
    config.timeoutMs = configInteger(parsed.timeoutMs, "timeoutMs");
  }
  if (parsed.maxBytes !== undefined) {
    config.maxBytes = configInteger(parsed.maxBytes, "maxBytes");
  }
  if (parsed.maxRedirects !== undefined) {
    config.maxRedirects = configInteger(parsed.maxRedirects, "maxRedirects", true);
  }
  if (parsed.probe !== undefined) {
    if (typeof parsed.probe !== "boolean") {
      throw new UsageError("config.probe must be a boolean.");
    }
    config.probe = parsed.probe;
  }
  if (parsed.failOn !== undefined) {
    if (typeof parsed.failOn !== "string" || !failOnValues.has(parsed.failOn)) {
      throw new UsageError("config.failOn must be error, warning, or never.");
    }
    config.failOn = parsed.failOn as FailOn;
  }

  return config;
}

function mergeConfig(fileConfig: FileConfig, parsed: ParsedArgs): Required<FileConfig> {
  return {
    timeoutMs: parsed.timeoutMs ?? fileConfig.timeoutMs ?? DEFAULT_CHECK_OPTIONS.timeoutMs,
    maxBytes: fileConfig.maxBytes ?? DEFAULT_CHECK_OPTIONS.maxBytes,
    maxRedirects: fileConfig.maxRedirects ?? DEFAULT_CHECK_OPTIONS.maxRedirects,
    probe: parsed.probe || fileConfig.probe === true,
    failOn: parsed.failOn ?? fileConfig.failOn ?? "error",
  };
}

function exitCodeFor(errorCount: number, warningCount: number, failOn: FailOn): number {
  if (failOn === "never") {
    return EXIT_CODES.success;
  }
  if (errorCount > 0 || (failOn === "warning" && warningCount > 0)) {
    return EXIT_CODES.findings;
  }
  return EXIT_CODES.success;
}

function writeUsageError(environment: CliEnvironment, error: unknown): number {
  const message = error instanceof Error ? error.message : "Invalid command.";
  environment.stderr(`${message}\nRun authmd check --help for usage.\n`);
  return EXIT_CODES.usage;
}

function internalErrorMessage(error: unknown, verbose: boolean): string {
  if (verbose && error instanceof Error && error.stack !== undefined) {
    return `Unexpected internal error:\n${error.stack}\n`;
  }
  return "Unexpected internal error. Run with --verbose for details.\n";
}

function splitFlag(argument: string): [string, string | undefined] {
  const equals = argument.indexOf("=");
  return equals === -1
    ? [argument, undefined]
    : [argument.slice(0, equals), argument.slice(equals + 1)];
}

function rejectValue(flag: string, value: string | undefined): void {
  if (value !== undefined) {
    throw new UsageError(`${flag} does not accept a value.`);
  }
}

function valueForFlag(
  argv: readonly string[],
  index: number,
  inlineValue: string | undefined,
): string {
  if (inlineValue !== undefined) {
    if (inlineValue.length === 0) {
      throw new UsageError("Missing value for flag.");
    }
    return inlineValue;
  }

  const value = argv[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new UsageError("Missing value for flag.");
  }
  return value;
}

function parsePositiveInteger(flag: string, value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new UsageError(`${flag} must be a positive integer.`);
  }
  return parsed;
}

function configInteger(value: unknown, name: string, allowZero = false): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) {
    throw new UsageError(
      `config.${name} must be a ${allowZero ? "non-negative" : "positive"} integer.`,
    );
  }
  return value;
}

function shouldUseColor(environment: CliEnvironment): boolean {
  return (
    environment.stdoutIsTTY ||
    (environment.forceColor !== undefined && environment.forceColor !== "0")
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function helpText(): string {
  return [
    "Usage:",
    "  authmd check <url-or-path> [options]",
    "",
    "Options:",
    "  --json                 Emit the versioned JSON report.",
    "  --verbose              Include remediation and specification references.",
    "  --quiet                Suppress human report output.",
    "  --timeout <ms>         Per-request timeout in milliseconds.",
    "  --config <path>        Read JSON check configuration.",
    "  --fail-on <threshold>  error (default), warning, or never.",
    "  --probe                Print the read-only discovery trace.",
    "  --output <path>        Write the JSON report to a file.",
    "  --help, -h             Show this help.",
    "  --version, -v          Show the CLI version.",
    "",
    "Exit codes:",
    "  0  No findings at the selected threshold.",
    "  1  Findings meet the selected failure threshold.",
    "  2  Usage, URL, or configuration failure.",
    "  3  Unexpected internal failure.",
    "",
    "The default run only reads auth.md and public discovery metadata. --probe adds",
    "a timing and redirect trace; it never registers, requests a token, or writes remotely.",
    "",
  ].join("\n");
}
