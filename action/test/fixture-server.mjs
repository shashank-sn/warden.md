import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:https";

const keyPath = requiredEnvironment("WARDEN_FIXTURE_KEY");
const certificatePath = requiredEnvironment("WARDEN_FIXTURE_CERT");
const outputPath = requiredEnvironment("WARDEN_FIXTURE_OUTPUT");

function requiredEnvironment(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required.`);
  }
  return value;
}

function authMd(origin) {
  return [
    "# auth.md",
    "",
    "A fixture registration guide for agents.",
    "",
    "## Discover",
    "Read the Protected Resource Metadata document.",
    `Issuer: ${origin}`,
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
  ].join("\n");
}

function authorizationServerMetadata(origin) {
  return {
    issuer: origin,
    token_endpoint: `${origin}/oauth2/token`,
    revocation_endpoint: `${origin}/oauth2/revoke`,
    grant_types_supported: [
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
      "urn:workos:agent-auth:grant-type:claim",
    ],
    token_endpoint_auth_methods_supported: ["none"],
    agent_auth: {
      skill: `${origin}/auth.md`,
      identity_endpoint: `${origin}/agent/identity`,
      claim_endpoint: `${origin}/agent/identity/claim`,
      events_endpoint: `${origin}/agent/events`,
      identity_types_supported: ["identity_assertion", "service_auth", "anonymous"],
      identity_assertion: {
        assertion_types_supported: ["urn:ietf:params:oauth:token-type:id-jag"],
      },
      events_supported: ["https://schemas.workos.com/events/agent/auth/identity/assertion/revoked"],
    },
  };
}

function sendJson(response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

const server = createServer(
  {
    cert: readFileSync(certificatePath),
    key: readFileSync(keyPath),
  },
  (request, response) => {
    const origin = `https://127.0.0.1:${server.address().port}`;
    const path = new URL(request.url ?? "/", origin).pathname;
    if (path === "/auth.md") {
      response.writeHead(200, { "content-type": "text/markdown; charset=utf-8" });
      response.end(authMd(origin));
      return;
    }
    if (path === "/.well-known/oauth-protected-resource/valid") {
      sendJson(response, 200, {
        resource: `${origin}/valid`,
        authorization_servers: [origin],
        scopes_supported: ["read"],
        bearer_methods_supported: ["header"],
      });
      return;
    }
    if (path === "/.well-known/oauth-protected-resource/broken") {
      sendJson(response, 200, {
        resource: `${origin}/not-broken`,
        authorization_servers: [origin],
        scopes_supported: ["read"],
        bearer_methods_supported: ["header"],
      });
      return;
    }
    if (path === "/.well-known/oauth-authorization-server") {
      sendJson(response, 200, authorizationServerMetadata(origin));
      return;
    }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
  },
);

server.listen(0, "127.0.0.1", () => {
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Fixture server did not receive a TCP port.");
  }
  writeFileSync(outputPath, `https://127.0.0.1:${address.port}`, "utf8");
});

function stop() {
  server.close();
}

process.once("SIGINT", stop);
process.once("SIGTERM", stop);
