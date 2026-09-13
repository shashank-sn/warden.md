import { describe, expect, it } from "vitest";

import { runConformanceCheck } from "../src/check.js";
import {
  conformantTransport,
  response,
  StubTransport,
  validAuthMd,
  validAuthorizationServerMetadata,
  validProtectedResourceMetadata,
} from "./helpers.js";

const fixedNow = () => Date.parse("2026-09-13T00:00:00.000Z");

describe("conformance orchestration", () => {
  it("runs the read-only discovery chain and produces a passing stable report", async () => {
    const transport = conformantTransport();
    const report = await runConformanceCheck("https://service.test/", {
      transport,
      now: fixedNow,
    });

    expect(report).toMatchObject({
      schemaVersion: 1,
      subject: "https://service.test/",
      startedAt: "2026-09-13T00:00:00.000Z",
      durationMs: 0,
      findings: [],
      summary: { errorCount: 0, warningCount: 0, infoCount: 0 },
    });
    expect(transport.requests.map((request) => request.url)).toEqual([
      "https://service.test/auth.md",
      "https://service.test/.well-known/oauth-protected-resource",
      "https://auth.service.test/.well-known/oauth-authorization-server",
    ]);
    const requestedUrls = transport.requests.map((request) => request.url);
    for (const forbiddenUrl of [
      "https://auth.service.test/agent/identity",
      "https://auth.service.test/agent/identity/claim",
      "https://auth.service.test/oauth2/token",
      "https://auth.service.test/oauth2/revoke",
    ]) {
      expect(requestedUrls).not.toContain(forbiddenUrl);
    }
  });

  it("tries path-aware and root PRM locations, then falls back to OIDC metadata", async () => {
    const plainDocument = validAuthMd().replace(
      "Read [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource).",
      "Read the Protected Resource Metadata.",
    );
    const transport = new StubTransport({
      "https://service.test/auth.md": response("https://service.test/auth.md", 200, plainDocument, {
        "content-type": "text/markdown",
      }),
      "https://service.test/.well-known/oauth-protected-resource/api": response(
        "https://service.test/.well-known/oauth-protected-resource/api",
        404,
        "missing",
        { "content-type": "application/json" },
      ),
      "https://service.test/.well-known/oauth-protected-resource": response(
        "https://service.test/.well-known/oauth-protected-resource",
        200,
        validProtectedResourceMetadata("https://service.test/api"),
        { "content-type": "application/json" },
      ),
      "https://auth.service.test/.well-known/oauth-authorization-server": response(
        "https://auth.service.test/.well-known/oauth-authorization-server",
        404,
        "missing",
        { "content-type": "application/json" },
      ),
      "https://auth.service.test/.well-known/openid-configuration": response(
        "https://auth.service.test/.well-known/openid-configuration",
        200,
        validAuthorizationServerMetadata(),
        { "content-type": "application/json" },
      ),
    });

    const report = await runConformanceCheck("https://service.test/api", {
      transport,
      now: fixedNow,
    });

    expect(report.findings).toEqual([]);
    expect(transport.requests.map((request) => request.url)).toEqual([
      "https://service.test/auth.md",
      "https://service.test/.well-known/oauth-protected-resource/api",
      "https://service.test/.well-known/oauth-protected-resource",
      "https://auth.service.test/.well-known/oauth-authorization-server",
      "https://auth.service.test/.well-known/openid-configuration",
    ]);
  });

  it("adds a deterministic trace only when probe is explicit", async () => {
    const report = await runConformanceCheck("https://service.test/", {
      transport: conformantTransport(),
      now: fixedNow,
      probe: true,
    });

    expect(report.probe).toEqual([
      expect.objectContaining({
        url: "https://service.test/auth.md",
        status: 200,
        durationMs: 4,
        contentType: "text/markdown",
      }),
      expect.objectContaining({
        url: "https://service.test/.well-known/oauth-protected-resource",
        status: 200,
      }),
      expect.objectContaining({
        url: "https://auth.service.test/.well-known/oauth-authorization-server",
        status: 200,
      }),
    ]);
  });
});
