import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { synchronizeActionCliVersion, synchronizeRepository } from "./sync-action-cli-version.mjs";

const files = {
  action: [
    "inputs:",
    "  cli-version:",
    "    description: exact version",
    "    required: false",
    '    default: "0.1.0" # warden-cli-version',
    "  working-directory:",
    "    default: .",
    "",
  ].join("\n"),
  runtime: 'export const DEFAULT_CLI_VERSION = "0.1.0";\n',
};

describe("composite action version synchronization", () => {
  it("keeps the tag's action metadata and runtime fallback aligned with its CLI package", () => {
    expect(synchronizeActionCliVersion("0.1.1", files)).toEqual({
      action: expect.stringContaining('default: "0.1.1" # warden-cli-version'),
      runtime: 'export const DEFAULT_CLI_VERSION = "0.1.1";\n',
    });
  });

  it("rejects unsafe versions and unmarked action defaults instead of silently drifting", () => {
    expect(() => synchronizeActionCliVersion("latest", files)).toThrow("exact semver");
    expect(() =>
      synchronizeActionCliVersion("0.1.1", {
        ...files,
        action: files.action.replace(" # warden-cli-version", ""),
      }),
    ).toThrow("marked action.yml cli-version");
  });

  it("writes both action surfaces from the versioned CLI package during a version PR", () => {
    const root = mkdtempSync(join(tmpdir(), "warden-version-sync-"));
    const packageDirectory = join(root, "packages", "cli");
    const runtimeDirectory = join(root, "action", "lib");

    try {
      mkdirSync(packageDirectory, { recursive: true });
      mkdirSync(runtimeDirectory, { recursive: true });
      writeFileSync(join(packageDirectory, "package.json"), '{"version":"0.1.1"}\n');
      writeFileSync(join(root, "action.yml"), files.action);
      writeFileSync(join(runtimeDirectory, "version.mjs"), files.runtime);

      expect(synchronizeRepository(root)).toBe("0.1.1");
      expect(readFileSync(join(root, "action.yml"), "utf8")).toContain('default: "0.1.1"');
      expect(readFileSync(join(runtimeDirectory, "version.mjs"), "utf8")).toContain(
        'DEFAULT_CLI_VERSION = "0.1.1"',
      );
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  });
});
