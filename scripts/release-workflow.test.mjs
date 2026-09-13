import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("version PR workflow", () => {
  it("can prepare a version pull request without publishing, tagging, or requesting OIDC", async () => {
    const workflow = await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
      "utf8",
    );

    expect(workflow).toContain("contents: write");
    expect(workflow).toContain("pull-requests: write");
    expect(workflow).toContain("uses: changesets/action@v1");
    expect(workflow).toContain("version: pnpm release:version");
    expect(workflow).toContain("createGithubReleases: false");
    expect(workflow).not.toContain("publish:");
    expect(workflow).not.toContain("release:publish");
    expect(workflow).not.toContain("registry-url:");
    expect(workflow).not.toContain("id-token: write");
    expect(workflow).not.toContain("NPM_CONFIG_PROVENANCE");
    expect(workflow).not.toContain("release-action-tag.mjs");
    expect(workflow).not.toMatch(/\b(?:npm|pnpm|changeset)\s+publish\b/u);
    expect(workflow).not.toMatch(/\bgit\s+tag\b/u);
    expect(workflow).not.toMatch(/\bgh\s+release\s+create\b/u);
  });
});
