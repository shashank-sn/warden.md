import type { Transport, TransportRequest, TransportResponse } from "../src/transport.js";

export class StubTransport implements Transport {
  public readonly requests: TransportRequest[] = [];

  public constructor(
    private readonly handlers: Record<
      string,
      TransportResponse | Error | ((request: TransportRequest) => TransportResponse)
    >,
  ) {}

  public async get(request: TransportRequest): Promise<TransportResponse> {
    this.requests.push(request);
    const handler = this.handlers[request.url];
    if (handler === undefined) {
      return response(request.url, 404, "not found", { "content-type": "text/plain" });
    }
    if (handler instanceof Error) {
      throw handler;
    }
    return typeof handler === "function" ? handler(request) : handler;
  }
}

export function response(
  url: string,
  status: number,
  body: string,
  headers: Record<string, string | undefined>,
  durationMs = 4,
): TransportResponse {
  return { url, status, body, headers, durationMs };
}

export function validAuthMd(sourceUrl = "https://service.test/auth.md"): string {
  return [
    "# auth.md",
    "",
    "A registration guide for agents.",
    "",
    "## Discover",
    "Read [Protected Resource Metadata](https://service.test/.well-known/oauth-protected-resource).",
    "Issuer: https://auth.service.test",
    "",
    "## Pick a method",
    "Use identity_assertion, service_auth, or anonymous registration as appropriate.",
    "",
    "## Register",
    "Register at the identity endpoint described in metadata.",
    "",
    "## Claim ceremony",
    "Present the verification URI and user code to the user.",
    "",
    "## Exchange the assertion",
    "Exchange an identity assertion at the token endpoint.",
    "",
    "## Use the access_token",
    "Present a bearer access token to the resource server.",
    "",
    "## Errors",
    "Handle documented OAuth and registration errors.",
    "",
    "## Revocation",
    "Use the published revocation endpoint.",
    "",
    `Source: ${sourceUrl}`,
    "",
  ].join("\n");
}

export function validProtectedResourceMetadata(subject = "https://service.test/"): string {
  return JSON.stringify({
    resource: subject,
    authorization_servers: ["https://auth.service.test"],
    scopes_supported: ["read"],
    bearer_methods_supported: ["header"],
  });
}

export function validAuthorizationServerMetadata(skill = "https://service.test/auth.md"): string {
  return JSON.stringify({
    issuer: "https://auth.service.test",
    token_endpoint: "https://auth.service.test/oauth2/token",
    revocation_endpoint: "https://auth.service.test/oauth2/revoke",
    grant_types_supported: [
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "urn:workos:agent-auth:grant-type:claim",
    ],
    token_endpoint_auth_methods_supported: ["none"],
    agent_auth: {
      skill,
      identity_endpoint: "https://auth.service.test/agent/identity",
      claim_endpoint: "https://auth.service.test/agent/identity/claim",
      events_endpoint: "https://auth.service.test/agent/events",
      identity_types_supported: ["identity_assertion", "service_auth", "anonymous"],
      identity_assertion: {
        assertion_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"],
      },
      events_supported: ["https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"],
    },
  });
}

export function conformantTransport(): StubTransport {
  return new StubTransport({
    "https://service.test/auth.md": response("https://service.test/auth.md", 200, validAuthMd(), {
      "content-type": "text/markdown",
    }),
    "https://service.test/.well-known/oauth-protected-resource": response(
      "https://service.test/.well-known/oauth-protected-resource",
      200,
      validProtectedResourceMetadata(),
      { "content-type": "application/json" },
    ),
    "https://auth.service.test/.well-known/oauth-authorization-server": response(
      "https://auth.service.test/.well-known/oauth-authorization-server",
      200,
      validAuthorizationServerMetadata(),
      { "content-type": "application/json" },
    ),
  });
}
