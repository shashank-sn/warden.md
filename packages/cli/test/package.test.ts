import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";
import { CLI_VERSION } from "../src/cli.js";

describe("published CLI package metadata", () => {
  it("declares the canonical repository needed for npm trusted publishing", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { repository?: { type?: string; url?: string } };

    expect(packageJson.repository).toEqual({
      type: "git",
      url: "git+https://github.com/shashank-sn/warden.md.git",
    });
  });

  it("reports the installed package version rather than a release-time source constant", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version?: string };

    expect(CLI_VERSION).toBe(packageJson.version);
  });
});
