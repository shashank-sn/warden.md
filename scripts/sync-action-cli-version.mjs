import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const ACTION_DEFAULT =
  /(^ {2}cli-version:\n(?:(?: {4}.*\n)*) {4}default: )"[^"]+"( # warden-cli-version$)/mu;
const RUNTIME_DEFAULT = /^export const DEFAULT_CLI_VERSION = "[^"]+";$/mu;
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function requireVersion(version) {
  if (typeof version !== "string" || !SEMVER.test(version)) {
    throw new Error("@warden/cli package version must be exact semver.");
  }
  return version;
}

function replaceOnce(source, expression, replacement, name) {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  const matches = [...source.matchAll(new RegExp(expression.source, flags))];
  if (matches.length !== 1) {
    throw new Error(`Could not find one marked ${name} default to synchronize.`);
  }
  return source.replace(expression, replacement);
}

export function synchronizeActionCliVersion(version, files) {
  const exactVersion = requireVersion(version);
  return {
    action: replaceOnce(
      files.action,
      ACTION_DEFAULT,
      `$1"${exactVersion}"$2`,
      "action.yml cli-version",
    ),
    runtime: replaceOnce(
      files.runtime,
      RUNTIME_DEFAULT,
      `export const DEFAULT_CLI_VERSION = "${exactVersion}";`,
      "action runtime cli-version",
    ),
  };
}

export function synchronizeRepository(root = repositoryRoot) {
  const packagePath = resolve(root, "packages/cli/package.json");
  const actionPath = resolve(root, "action.yml");
  const runtimePath = resolve(root, "action/lib/version.mjs");
  const packageJson = JSON.parse(readFileSync(packagePath, "utf8"));
  const version = requireVersion(packageJson.version);
  const synchronized = synchronizeActionCliVersion(version, {
    action: readFileSync(actionPath, "utf8"),
    runtime: readFileSync(runtimePath, "utf8"),
  });

  writeFileSync(actionPath, synchronized.action, "utf8");
  writeFileSync(runtimePath, synchronized.runtime, "utf8");
  return version;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const version = synchronizeRepository();
  console.log(`Synchronized composite action CLI default to ${version}.`);
}
