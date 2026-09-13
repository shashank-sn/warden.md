import { describe, expect, it } from "vitest";

import { parseAuthMd } from "../src/authmd.js";
import {
  authorizationServerMetadataUrls,
  protectedResourceMetadataUrls,
  validateAuthorizationServerMetadata,
  validateProtectedResourceMetadata,
} from "../src/metadata.js";
import {
  validAuthMd,
  validAuthorizationServerMetadata,
  validProtectedResourceMetadata,
} from "./helpers.js";

describe("metadata validators", () => {
  it("accepts a conformant protected-resource and authorization-server pair", () => {
    const protectedResource = JSON.parse(validProtectedResourceMetadata()) as Record<
      string,
      unknown
    >;
    const authorizationServer = JSON.parse(validAuthorizationServerMetadata()) as Record<
      string,
      unknown
    >;
    const authDocument = parseAuthMd("https://service.test/auth.md", validAuthMd());

    expect(validateProtectedResourceMetadata(protectedResource, "https://service.test/")).toEqual(
      [],
    );
    expect(
      validateAuthorizationServerMetadata(authorizationServer, {
        authDocument,
        protectedResourceMetadata: protectedResource,
      }),
    ).toEqual([]);
  });

  it("returns distinct RFC-cited findings for bad resource URLs and identity mismatches", () => {
    const protectedResource = JSON.parse(validProtectedResourceMetadata()) as Record<
      string,
      unknown
    >;
    protectedResource.resource = "http://wrong.test/#fragment";

    const findings = validateProtectedResourceMetadata(protectedResource, "https://service.test/");

    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "PRM_RESOURCE_URL",
        location: { jsonPath: "$.resource" },
        specReference: "RFC 9728 §2",
      }),
    );

    protectedResource.resource = "https://other.test/";
    expect(
      validateProtectedResourceMetadata(protectedResource, "https://service.test/"),
    ).toContainEqual(expect.objectContaining({ ruleId: "PRM_RESOURCE_MISMATCH" }));
  });

  it("reports missing agent_auth keys individually and rejects unknown registration modes", () => {
    const protectedResource = JSON.parse(validProtectedResourceMetadata()) as Record<
      string,
      unknown
    >;
    const authorizationServer = JSON.parse(validAuthorizationServerMetadata()) as Record<
      string,
      unknown
    >;
    const agentAuth = authorizationServer.agent_auth as Record<string, unknown>;
    delete agentAuth.claim_endpoint;
    delete agentAuth.events_endpoint;
    agentAuth.identity_types_supported = ["did_key"];

    const findings = validateAuthorizationServerMetadata(authorizationServer, {
      authDocument: parseAuthMd("https://service.test/auth.md", validAuthMd()),
      protectedResourceMetadata: protectedResource,
    });

    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "AGENT_AUTH_MISSING_KEY",
        location: { jsonPath: "$.agent_auth.claim_endpoint" },
      }),
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "AGENT_AUTH_MISSING_KEY",
        location: { jsonPath: "$.agent_auth.events_endpoint" },
      }),
    );
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "AGENT_AUTH_UNKNOWN_REGISTRATION_MODE",
        location: { jsonPath: "$.agent_auth.identity_types_supported[0]" },
      }),
    );
  });

  it("reports distinct issuer mismatches for PRM and auth.md references", () => {
    const protectedResource = JSON.parse(validProtectedResourceMetadata()) as Record<
      string,
      unknown
    >;
    protectedResource.authorization_servers = ["https://other-auth.service.test"];
    const authorizationServer = JSON.parse(validAuthorizationServerMetadata()) as Record<
      string,
      unknown
    >;
    const authDocument = parseAuthMd(
      "https://service.test/auth.md",
      validAuthMd().replace(
        "Issuer: https://auth.service.test",
        "Issuer: https://another-auth.service.test",
      ),
    );

    const findings = validateAuthorizationServerMetadata(authorizationServer, {
      authDocument,
      protectedResourceMetadata: protectedResource,
    });

    expect(findings).toContainEqual(expect.objectContaining({ ruleId: "PRM_ISSUER_MISMATCH" }));
    expect(findings).toContainEqual(expect.objectContaining({ ruleId: "AUTHMD_ISSUER_MISMATCH" }));
  });

  it("offers path-aware, root, and OIDC discovery variants", () => {
    expect(protectedResourceMetadataUrls("https://service.test/api/v1")).toEqual([
      "https://service.test/.well-known/oauth-protected-resource/api/v1",
      "https://service.test/.well-known/oauth-protected-resource",
    ]);
    expect(authorizationServerMetadataUrls("https://auth.service.test/tenant")).toEqual([
      "https://auth.service.test/.well-known/oauth-authorization-server/tenant",
      "https://auth.service.test/.well-known/oauth-authorization-server",
      "https://auth.service.test/.well-known/openid-configuration/tenant",
      "https://auth.service.test/.well-known/openid-configuration",
    ]);
  });
});
