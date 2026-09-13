import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const semver =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u;
const commitSha = /^[0-9a-f]{40}$/iu;

export function releasePlan(publishedPackages, target) {
  let packages;
  try {
    packages = JSON.parse(publishedPackages);
  } catch {
    throw new Error("WARDEN_PUBLISHED_PACKAGES must be a JSON array.");
  }
  if (!Array.isArray(packages)) {
    throw new Error("WARDEN_PUBLISHED_PACKAGES must be a JSON array.");
  }

  const publishedCli = packages.filter(
    (entry) =>
      entry &&
      typeof entry === "object" &&
      entry.name === "@warden/cli" &&
      typeof entry.version === "string",
  );
  if (publishedCli.length !== 1) {
    throw new Error(
      "Expected exactly one published @warden/cli package to tag the composite action.",
    );
  }

  const version = publishedCli[0].version;
  if (!semver.test(version)) {
    throw new Error("Published @warden/cli version is not valid semver.");
  }
  if (!commitSha.test(target)) {
    throw new Error("WARDEN_RELEASE_TARGET must be a full commit SHA.");
  }
  return { tag: `v${version}`, target };
}

export function createActionRelease(plan, run = spawnSync) {
  if (hasMatchingActionRelease(plan, run)) {
    return { created: false, tag: plan.tag };
  }
  assertExistingTagTarget(plan, run);

  const created = run(
    "gh",
    ["release", "create", plan.tag, "--generate-notes", "--target", plan.target],
    { encoding: "utf8", stdio: "inherit" },
  );
  if (created.status !== 0) {
    throw new Error(`Could not create composite action release ${plan.tag}.`);
  }
  assertActionTagTarget(plan, run);
  return { created: true, tag: plan.tag };
}

function hasMatchingActionRelease(plan, run) {
  if (
    !remoteResourceExists(
      plan,
      run,
      `repos/{owner}/{repo}/releases/tags/${plan.tag}`,
      ".id",
      "release",
    )
  ) {
    return false;
  }

  assertActionTagTarget(plan, run);
  return true;
}

function assertExistingTagTarget(plan, run) {
  const tagExists = remoteResourceExists(
    plan,
    run,
    `repos/{owner}/{repo}/git/ref/tags/${plan.tag}`,
    ".object.sha",
    "tag",
  );
  if (tagExists) {
    assertActionTagTarget(plan, run);
  }
}

function remoteResourceExists(plan, run, path, query, resource) {
  const result = run("gh", ["api", path, "--jq", query], { encoding: "utf8" });
  if (result.status === 0) {
    return true;
  }
  if (isNotFound(result)) {
    return false;
  }
  throw new Error(`Could not verify composite action ${resource} ${plan.tag}.`);
}

function isNotFound(result) {
  return `${result.stdout ?? ""}\n${result.stderr ?? ""}`.includes("HTTP 404");
}

function assertActionTagTarget(plan, run) {
  const tag = run("gh", ["api", `repos/{owner}/{repo}/commits/${plan.tag}`, "--jq", ".sha"], {
    encoding: "utf8",
  });
  if (tag.status !== 0) {
    throw new Error(`Could not resolve composite action tag ${plan.tag}.`);
  }

  const tagTarget = tag.stdout?.trim() ?? "";
  if (tagTarget.toLowerCase() !== plan.target.toLowerCase()) {
    throw new Error(
      `Composite action tag ${plan.tag} targets ${tagTarget || "an unknown revision"}, not ${plan.target}.`,
    );
  }
}

export function main(environment = process.env, run = spawnSync) {
  const plan = releasePlan(
    environment.WARDEN_PUBLISHED_PACKAGES ?? "[]",
    environment.WARDEN_RELEASE_TARGET ?? "",
  );
  const result = createActionRelease(plan, run);
  console.log(
    result.created
      ? `Created composite action release ${result.tag}.`
      : `Composite action release ${result.tag} already exists.`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
