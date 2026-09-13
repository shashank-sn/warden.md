import { describe, expect, it } from "vitest";

import { createActionRelease, releasePlan } from "./release-action-tag.mjs";

const target = "a".repeat(40);

describe("composite action release tag", () => {
  it("derives a v-prefixed immutable tag from exactly one published CLI", () => {
    expect(
      releasePlan(JSON.stringify([{ name: "@warden/cli", version: "0.1.0" }]), target),
    ).toEqual({ tag: "v0.1.0", target });
  });

  it("rejects missing, duplicated, or unsafe published release data", () => {
    expect(() => releasePlan("[]", target)).toThrow("exactly one published @warden/cli");
    expect(() =>
      releasePlan(
        JSON.stringify([
          { name: "@warden/cli", version: "0.1.0" },
          { name: "@warden/cli", version: "0.1.1" },
        ]),
        target,
      ),
    ).toThrow("exactly one published @warden/cli");
    expect(() =>
      releasePlan(JSON.stringify([{ name: "@warden/cli", version: "latest" }]), target),
    ).toThrow("not valid semver");
    expect(() =>
      releasePlan(JSON.stringify([{ name: "@warden/cli", version: "0.1.0" }]), "main"),
    ).toThrow("full commit SHA");
  });

  it("does not duplicate a release on workflow retry", () => {
    const calls = [];
    const result = createActionRelease({ tag: "v0.1.0", target }, (...argumentsList) => {
      calls.push(argumentsList);
      return calls.length === 1 ? { status: 0 } : { status: 0, stdout: `${target}\n` };
    });

    expect(result).toEqual({ created: false, tag: "v0.1.0" });
    expect(calls).toEqual([
      [
        "gh",
        ["api", "repos/{owner}/{repo}/releases/tags/v0.1.0", "--jq", ".id"],
        { encoding: "utf8" },
      ],
      ["gh", ["api", "repos/{owner}/{repo}/commits/v0.1.0", "--jq", ".sha"], { encoding: "utf8" }],
    ]);
  });

  it("refuses a retry when an existing action release targets another revision", () => {
    let call = 0;
    expect(() =>
      createActionRelease({ tag: "v0.1.0", target }, () => {
        call += 1;
        return call === 1 ? { status: 0 } : { status: 0, stdout: `${"b".repeat(40)}\n` };
      }),
    ).toThrow(`Composite action tag v0.1.0 targets ${"b".repeat(40)}, not ${target}`);
  });

  it("creates a generated-notes release when no tag exists", () => {
    const calls = [];
    const result = createActionRelease({ tag: "v0.1.0", target }, (...argumentsList) => {
      calls.push(argumentsList);
      if (calls.length <= 2) {
        return { status: 1, stderr: "HTTP 404" };
      }
      if (calls.length === 3) {
        return { status: 0 };
      }
      return { status: 0, stdout: `${target}\n` };
    });

    expect(result).toEqual({ created: true, tag: "v0.1.0" });
    expect(calls[2]).toEqual([
      "gh",
      ["release", "create", "v0.1.0", "--generate-notes", "--target", target],
      { encoding: "utf8", stdio: "inherit" },
    ]);
    expect(calls[3]).toEqual([
      "gh",
      ["api", "repos/{owner}/{repo}/commits/v0.1.0", "--jq", ".sha"],
      { encoding: "utf8" },
    ]);
  });

  it("refuses a mismatched existing tag before it can receive a release", () => {
    const calls = [];
    expect(() =>
      createActionRelease({ tag: "v0.1.0", target }, (...argumentsList) => {
        calls.push(argumentsList);
        if (calls.length === 1) {
          return { status: 1, stderr: "HTTP 404" };
        }
        if (calls.length === 2) {
          return { status: 0, stdout: "tag-object\n" };
        }
        return { status: 0, stdout: `${"b".repeat(40)}\n` };
      }),
    ).toThrow(`Composite action tag v0.1.0 targets ${"b".repeat(40)}, not ${target}`);
    expect(calls.some(([, argumentsForGh]) => argumentsForGh[1] === "create")).toBe(false);
  });
});
