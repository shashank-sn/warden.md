import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { parseAuthMd, REQUIRED_AUTHMD_SECTIONS, validateAuthMdDocument } from "../src/authmd.js";

const fixtureDirectory = new URL("./fixtures/authmd/", import.meta.url);

describe("auth.md parser and section validator", () => {
  it("parses ordered headings, links, metadata references, and registration modes", async () => {
    const document = parseAuthMd("https://service.test/auth.md", await fixture("valid.md"));

    expect(document.sections.map((section) => section.canonicalName)).toEqual([
      ...REQUIRED_AUTHMD_SECTIONS,
    ]);
    expect(document.metadataReferences).toMatchObject([
      {
        kind: "protected-resource",
        url: "https://service.test/.well-known/oauth-protected-resource",
      },
    ]);
    expect(document.issuerReferences[0]).toMatchObject({ url: "https://auth.service.test" });
    expect(document.registrationModes).toEqual(["identity_assertion", "service_auth", "anonymous"]);
  });

  it("accepts the valid corpus fixture without section findings", async () => {
    const document = parseAuthMd("https://service.test/auth.md", await fixture("valid.md"));

    expect(validateAuthMdDocument(document)).toEqual([]);
  });

  it("returns stable rule ids and locations for each invalid section case", async () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      await fixture("invalid-sections.md"),
    );
    const findings = validateAuthMdDocument(document);

    expect(findings.map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining([
        "AUTHMD_DUPLICATE_SECTION",
        "AUTHMD_EMPTY_SECTION",
        "AUTHMD_UNKNOWN_SECTION",
        "AUTHMD_METADATA_URL",
      ]),
    );
    expect(
      findings.find((finding) => finding.ruleId === "AUTHMD_DUPLICATE_SECTION")?.location,
    ).toMatchObject({
      section: "Discover",
      line: 7,
    });
    expect(
      findings.find((finding) => finding.ruleId === "AUTHMD_METADATA_URL")?.location,
    ).toMatchObject({
      line: 5,
    });
  });

  it("reports a missing required section from its dedicated fixture", async () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      await fixture("missing-section.md"),
    );

    expect(validateAuthMdDocument(document)).toContainEqual(
      expect.objectContaining({
        ruleId: "AUTHMD_REQUIRED_SECTION",
        message: "Missing required section: Revocation.",
      }),
    );
  });

  it("does not treat fenced examples as auth.md headings or discovery declarations", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "```md",
        ...REQUIRED_AUTHMD_SECTIONS.flatMap((section) => [`## ${section}`, "Example guidance."]),
        "[Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource)",
        "Issuer: https://auth.service.test",
        "identity_assertion service_auth anonymous",
        "```",
      ].join("\n"),
    );

    expect(document.headings).toEqual([]);
    expect(document.metadataReferences).toEqual([]);
    expect(document.issuerReferences).toEqual([]);
    expect(document.registrationModes).toEqual([]);
    expect(validateAuthMdDocument(document)).toContainEqual(
      expect.objectContaining({
        ruleId: "AUTHMD_REQUIRED_SECTION",
        message: "Missing required section: Discover.",
      }),
    );
  });

  it("does not extract discovery declarations from indented code blocks", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "    [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource)",
        "    Issuer: https://auth.service.test",
        "    identity_assertion service_auth anonymous",
      ].join("\n"),
    );

    expect(document.metadataReferences).toEqual([]);
    expect(document.issuerReferences).toEqual([]);
    expect(document.registrationModes).toEqual([]);
  });

  it("does not extract discovery declarations from quoted code blocks", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "> ```md",
        "> [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource)",
        "> Issuer: https://auth.service.test",
        "> identity_assertion service_auth anonymous",
        "> ```",
        "",
        ">     [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource)",
        ">     Issuer: https://auth.service.test",
        ">     identity_assertion service_auth anonymous",
      ].join("\n"),
    );

    expect(document.metadataReferences).toEqual([]);
    expect(document.issuerReferences).toEqual([]);
    expect(document.registrationModes).toEqual([]);
  });

  it("does not extract discovery declarations from fenced code inside a list", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "- ```md",
        "  [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource)",
        "  Issuer: https://auth.service.test",
        "  identity_assertion service_auth anonymous",
        "  ```",
      ].join("\n"),
    );

    expect(document.metadataReferences).toEqual([]);
    expect(document.issuerReferences).toEqual([]);
    expect(document.registrationModes).toEqual([]);
  });

  it("keeps discovery declarations in a quoted paragraph continuation", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "> Read this declaration:",
        ">     [Protected Resource Metadata](https://custom.service.test/.well-known/oauth-protected-resource)",
        ">     Issuer: https://auth.service.test",
        ">     identity_assertion service_auth anonymous",
      ].join("\n"),
    );

    expect(document.metadataReferences).toMatchObject([
      {
        kind: "protected-resource",
        url: "https://custom.service.test/.well-known/oauth-protected-resource",
      },
    ]);
    expect(document.issuerReferences).toMatchObject([{ url: "https://auth.service.test" }]);
    expect(document.registrationModes).toEqual(["identity_assertion", "service_auth", "anonymous"]);
  });

  it("keeps discovery declarations in a valid indented list continuation", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "  - Choose a discovery document.",
        "",
        "    [Protected Resource Metadata](https://custom.service.test/.well-known/oauth-protected-resource)",
        "    Issuer: https://auth.service.test",
        "    identity_assertion service_auth anonymous",
      ].join("\n"),
    );

    expect(document.metadataReferences).toMatchObject([
      {
        kind: "protected-resource",
        url: "https://custom.service.test/.well-known/oauth-protected-resource",
      },
    ]);
    expect(document.issuerReferences).toMatchObject([{ url: "https://auth.service.test" }]);
    expect(document.registrationModes).toEqual(["identity_assertion", "service_auth", "anonymous"]);
  });

  it("keeps discovery declarations in a normal paragraph continuation", () => {
    const document = parseAuthMd(
      "https://service.test/auth.md",
      [
        "Read this declaration:",
        "    [Protected Resource Metadata](https://custom.service.test/.well-known/oauth-protected-resource)",
        "    Issuer: https://auth.service.test",
        "    identity_assertion service_auth anonymous",
      ].join("\n"),
    );

    expect(document.metadataReferences).toMatchObject([
      {
        kind: "protected-resource",
        url: "https://custom.service.test/.well-known/oauth-protected-resource",
      },
    ]);
    expect(document.issuerReferences).toMatchObject([{ url: "https://auth.service.test" }]);
    expect(document.registrationModes).toEqual(["identity_assertion", "service_auth", "anonymous"]);
  });
});

async function fixture(name: string): Promise<string> {
  return readFile(fileURLToPath(new URL(name, fixtureDirectory)), "utf8");
}
