import type { AuthMdDocument } from "./authmd.js";
import type { Finding, FindingLocation } from "./model.js";

export type JsonObject = Record<string, unknown>;

export type AuthorizationServerValidationContext = {
  authDocument: AuthMdDocument;
  protectedResourceMetadata: JsonObject;
};

const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const claimGrant = "urn:workos:agent-auth:grant-type:claim";
const registrationModes = new Set(["identity_assertion", "service_auth", "anonymous"]);
const agentAuthRequiredKeys = [
  "skill",
  "identity_endpoint",
  "claim_endpoint",
  "events_endpoint",
  "identity_types_supported",
  "identity_assertion",
  "events_supported",
] as const;

export function protectedResourceMetadataUrls(subject: string): string[] {
  const resource = new URL(subject);
  const path = normalizedPath(resource.pathname);
  const root = new URL("/.well-known/oauth-protected-resource", resource.origin).toString();
  const pathAware =
    path === ""
      ? root
      : new URL(`/.well-known/oauth-protected-resource${path}`, resource.origin).toString();

  return uniqueUrls([pathAware, root]);
}

export function authorizationServerMetadataUrls(issuer: string): string[] {
  const url = new URL(issuer);
  const path = normalizedPath(url.pathname);
  const oauthRoot = new URL("/.well-known/oauth-authorization-server", url.origin).toString();
  const oidcRoot = new URL("/.well-known/openid-configuration", url.origin).toString();
  const oauthPathAware =
    path === ""
      ? oauthRoot
      : new URL(`/.well-known/oauth-authorization-server${path}`, url.origin).toString();
  const oidcPathAware =
    path === ""
      ? oidcRoot
      : new URL(`/.well-known/openid-configuration${path}`, url.origin).toString();

  return uniqueUrls([oauthPathAware, oauthRoot, oidcPathAware, oidcRoot]);
}

export function validateProtectedResourceMetadata(metadata: unknown, subject: string): Finding[] {
  if (!isJsonObject(metadata)) {
    return [
      metadataFinding(
        "PRM_OBJECT",
        "error",
        "Protected Resource Metadata must be a JSON object.",
        "$",
        "RFC 9728 §2",
      ),
    ];
  }

  const findings: Finding[] = [];
  const resource = metadata.resource;
  if (typeof resource !== "string") {
    findings.push(
      metadataFinding(
        "PRM_RESOURCE_REQUIRED",
        "error",
        "Protected Resource Metadata requires a string resource.",
        "$.resource",
        "RFC 9728 §2",
      ),
    );
  } else if (!isAbsoluteHttpsUrlWithoutFragment(resource)) {
    findings.push(
      metadataFinding(
        "PRM_RESOURCE_URL",
        "error",
        "resource must be an absolute HTTPS URL without a fragment.",
        "$.resource",
        "RFC 9728 §2",
      ),
    );
  } else if (!sameResource(resource, subject)) {
    findings.push(
      metadataFinding(
        "PRM_RESOURCE_MISMATCH",
        "error",
        "resource does not match the URL under test.",
        "$.resource",
        "RFC 8707 §2.1",
      ),
    );
  }

  const authorizationServers = metadata.authorization_servers;
  if (!Array.isArray(authorizationServers) || authorizationServers.length === 0) {
    findings.push(
      metadataFinding(
        "PRM_AUTHORIZATION_SERVERS_REQUIRED",
        "error",
        "Protected Resource Metadata requires a non-empty authorization_servers array.",
        "$.authorization_servers",
        "RFC 9728 §2",
      ),
    );
  } else {
    authorizationServers.forEach((value, index) => {
      if (typeof value !== "string" || !isAbsoluteHttpsUrlWithoutFragment(value)) {
        findings.push(
          metadataFinding(
            "PRM_AUTHORIZATION_SERVER_URL",
            "error",
            "authorization_servers entries must be absolute HTTPS URLs without fragments.",
            `$.authorization_servers[${index}]`,
            "RFC 9728 §2",
          ),
        );
      }
    });
  }

  validateStringArray(
    metadata,
    "scopes_supported",
    "$.scopes_supported",
    "PRM_SCOPES_TYPE",
    findings,
    "RFC 9728 §2",
    false,
  );
  validateStringArray(
    metadata,
    "bearer_methods_supported",
    "$.bearer_methods_supported",
    "PRM_BEARER_METHODS_TYPE",
    findings,
    "RFC 9728 §2",
    false,
  );

  return findings;
}

export function validateAuthorizationServerMetadata(
  metadata: unknown,
  context: AuthorizationServerValidationContext,
): Finding[] {
  if (!isJsonObject(metadata)) {
    return [
      metadataFinding(
        "AS_OBJECT",
        "error",
        "Authorization Server Metadata must be a JSON object.",
        "$",
        "RFC 8414 §2",
      ),
    ];
  }

  const findings: Finding[] = [];
  const issuer = metadata.issuer;
  if (typeof issuer !== "string") {
    findings.push(
      metadataFinding(
        "AS_ISSUER_REQUIRED",
        "error",
        "Authorization Server Metadata requires an issuer.",
        "$.issuer",
        "RFC 8414 §2",
      ),
    );
  } else if (!isAbsoluteHttpsUrlWithoutFragment(issuer)) {
    findings.push(
      metadataFinding(
        "AS_ISSUER_URL",
        "error",
        "issuer must be an absolute HTTPS URL without a fragment.",
        "$.issuer",
        "RFC 8414 §2",
      ),
    );
  }

  validateUrlField(
    metadata,
    "token_endpoint",
    "$.token_endpoint",
    "AS_TOKEN_ENDPOINT",
    findings,
    "RFC 8414 §2",
  );
  validateUrlField(
    metadata,
    "revocation_endpoint",
    "$.revocation_endpoint",
    "AS_REVOCATION_ENDPOINT",
    findings,
    "RFC 7009 §2",
  );
  const grants = validateStringArray(
    metadata,
    "grant_types_supported",
    "$.grant_types_supported",
    "AS_GRANT_TYPES",
    findings,
    "RFC 8414 §2",
    true,
  );
  const tokenAuthMethods = validateStringArray(
    metadata,
    "token_endpoint_auth_methods_supported",
    "$.token_endpoint_auth_methods_supported",
    "AS_TOKEN_AUTH_METHODS",
    findings,
    "RFC 8414 §2",
    true,
  );

  const agentAuth = metadata.agent_auth;
  if (!isJsonObject(agentAuth)) {
    findings.push(
      metadataFinding(
        "AGENT_AUTH_REQUIRED",
        "error",
        "Authorization Server Metadata requires an agent_auth object.",
        "$.agent_auth",
        "auth.md agent_auth profile",
      ),
    );
  } else {
    validateAgentAuth(agentAuth, issuer, context, findings);
  }

  validateGrantCoherence(grants, context.authDocument, findings);
  if (context.authDocument.registrationModes.length > 0 && !tokenAuthMethods.includes("none")) {
    findings.push(
      metadataFinding(
        "AS_TOKEN_AUTH_PUBLIC_CLIENT",
        "error",
        "auth.md promises agent registration but token_endpoint_auth_methods_supported does not include none.",
        "$.token_endpoint_auth_methods_supported",
        "RFC 8414 §2",
      ),
    );
  }

  if (typeof issuer === "string" && isAbsoluteHttpsUrlWithoutFragment(issuer)) {
    validateIdentityConsistency(issuer, context, findings);
  }

  return findings;
}

function validateAgentAuth(
  agentAuth: JsonObject,
  issuer: unknown,
  context: AuthorizationServerValidationContext,
  findings: Finding[],
): void {
  for (const key of agentAuthRequiredKeys) {
    if (key in agentAuth) {
      continue;
    }

    findings.push(
      metadataFinding(
        "AGENT_AUTH_MISSING_KEY",
        "error",
        `agent_auth is missing required key ${key}.`,
        `$.agent_auth.${key}`,
        "auth.md agent_auth profile",
      ),
    );
  }

  const endpointKeys = ["skill", "identity_endpoint", "claim_endpoint", "events_endpoint"] as const;
  for (const key of endpointKeys) {
    const value = agentAuth[key];
    if (typeof value !== "string" || !isAbsoluteHttpsUrlWithoutFragment(value)) {
      findings.push(
        metadataFinding(
          "AGENT_AUTH_ENDPOINT_URL",
          "error",
          `agent_auth.${key} must be an absolute HTTPS URL without a fragment.`,
          `$.agent_auth.${key}`,
          "auth.md agent_auth profile",
        ),
      );
      continue;
    }

    if (
      key !== "skill" &&
      typeof issuer === "string" &&
      isAbsoluteHttpsUrlWithoutFragment(issuer) &&
      !sameOrigin(value, issuer)
    ) {
      findings.push(
        metadataFinding(
          "AGENT_AUTH_ENDPOINT_ISSUER",
          "error",
          `agent_auth.${key} must resolve to the metadata issuer.`,
          `$.agent_auth.${key}`,
          "auth.md agent_auth profile",
        ),
      );
    }

    if (key === "skill" && !sameUrl(value, context.authDocument.sourceUrl)) {
      findings.push(
        metadataFinding(
          "AGENT_AUTH_SKILL_MISMATCH",
          "error",
          "agent_auth.skill does not match the fetched auth.md document.",
          "$.agent_auth.skill",
          "auth.md agent_auth profile",
        ),
      );
    }
  }

  const modes = validateStringArray(
    agentAuth,
    "identity_types_supported",
    "$.agent_auth.identity_types_supported",
    "AGENT_AUTH_IDENTITY_TYPES",
    findings,
    "auth.md agent_auth profile",
    true,
  );
  modes.forEach((mode, index) => {
    if (registrationModes.has(mode)) {
      return;
    }
    findings.push(
      metadataFinding(
        "AGENT_AUTH_UNKNOWN_REGISTRATION_MODE",
        "error",
        `agent_auth.identity_types_supported contains an unknown registration mode: ${mode}.`,
        `$.agent_auth.identity_types_supported[${index}]`,
        "auth.md agent_auth profile",
      ),
    );
  });

  const assertion = agentAuth.identity_assertion;
  if (!isJsonObject(assertion)) {
    findings.push(
      metadataFinding(
        "AGENT_AUTH_ASSERTION_OBJECT",
        "error",
        "agent_auth.identity_assertion must be an object.",
        "$.agent_auth.identity_assertion",
        "auth.md agent_auth profile",
      ),
    );
  } else {
    validateStringArray(
      assertion,
      "assertion_types_supported",
      "$.agent_auth.identity_assertion.assertion_types_supported",
      "AGENT_AUTH_ASSERTION_TYPES",
      findings,
      "auth.md agent_auth profile",
      true,
    );
  }

  validateStringArray(
    agentAuth,
    "events_supported",
    "$.agent_auth.events_supported",
    "AGENT_AUTH_EVENTS",
    findings,
    "auth.md agent_auth profile",
    true,
  );

  for (const promisedMode of context.authDocument.registrationModes) {
    if (modes.includes(promisedMode)) {
      continue;
    }
    findings.push(
      metadataFinding(
        "AUTHMD_REGISTRATION_MODE_MISMATCH",
        "error",
        `auth.md mentions ${promisedMode} but agent_auth does not offer it.`,
        "$.agent_auth.identity_types_supported",
        "auth.md agent_auth profile",
      ),
    );
  }
}

function validateGrantCoherence(
  grants: string[],
  document: AuthMdDocument,
  findings: Finding[],
): void {
  if (
    document.registrationModes.includes("identity_assertion") &&
    !grants.includes(jwtBearerGrant)
  ) {
    findings.push(
      metadataFinding(
        "AS_GRANT_TYPE_MISMATCH",
        "error",
        "auth.md promises identity_assertion but grant_types_supported omits the JWT bearer grant.",
        "$.grant_types_supported",
        "RFC 7523 §2.1",
      ),
    );
  }

  if (
    (document.registrationModes.includes("anonymous") ||
      document.registrationModes.includes("service_auth")) &&
    !grants.includes(claimGrant)
  ) {
    findings.push(
      metadataFinding(
        "AS_GRANT_TYPE_MISMATCH",
        "error",
        "auth.md promises a claimed registration flow but grant_types_supported omits the claim grant.",
        "$.grant_types_supported",
        "auth.md claim grant profile",
      ),
    );
  }
}

function validateIdentityConsistency(
  issuer: string,
  context: AuthorizationServerValidationContext,
  findings: Finding[],
): void {
  const authorizationServers = context.protectedResourceMetadata.authorization_servers;
  if (Array.isArray(authorizationServers)) {
    const declaredIssuer = authorizationServers.find(
      (value): value is string =>
        typeof value === "string" && isAbsoluteHttpsUrlWithoutFragment(value),
    );
    if (declaredIssuer !== undefined && !sameUrl(declaredIssuer, issuer)) {
      findings.push(
        metadataFinding(
          "PRM_ISSUER_MISMATCH",
          "error",
          "Authorization Server issuer does not match the server declared by Protected Resource Metadata.",
          "$.issuer",
          "RFC 9728 §2",
        ),
      );
    }
  }

  const issuerReference = context.authDocument.issuerReferences[0];
  if (
    issuerReference !== undefined &&
    isAbsoluteHttpsUrlWithoutFragment(issuerReference.url) &&
    !sameUrl(issuerReference.url, issuer)
  ) {
    findings.push({
      ruleId: "AUTHMD_ISSUER_MISMATCH",
      severity: "error",
      message: "Authorization Server issuer does not match the issuer published in auth.md.",
      location: {
        document: context.authDocument.sourceUrl,
        line: issuerReference.line,
        jsonPath: "$.issuer",
      },
      help: "Use the same issuer URL in auth.md and Authorization Server Metadata.",
      specReference: "RFC 8414 §2",
    });
  }
}

function validateUrlField(
  metadata: JsonObject,
  field: string,
  path: string,
  rulePrefix: string,
  findings: Finding[],
  specReference: string,
): void {
  const value = metadata[field];
  if (typeof value !== "string") {
    findings.push(
      metadataFinding(
        `${rulePrefix}_REQUIRED`,
        "error",
        `${field} is required and must be a string.`,
        path,
        specReference,
      ),
    );
    return;
  }

  if (!isAbsoluteHttpsUrlWithoutFragment(value)) {
    findings.push(
      metadataFinding(
        `${rulePrefix}_URL`,
        "error",
        `${field} must be an absolute HTTPS URL without a fragment.`,
        path,
        specReference,
      ),
    );
  }
}

function validateStringArray(
  metadata: JsonObject,
  field: string,
  path: string,
  ruleId: string,
  findings: Finding[],
  specReference: string,
  required: boolean,
): string[] {
  const value = metadata[field];
  if (value === undefined && !required) {
    return [];
  }

  if (
    !Array.isArray(value) ||
    value.length === 0 ||
    !value.every((item) => typeof item === "string")
  ) {
    findings.push(
      metadataFinding(
        ruleId,
        "error",
        `${field} must be a non-empty array of strings.`,
        path,
        specReference,
      ),
    );
    return [];
  }

  return value;
}

function metadataFinding(
  ruleId: string,
  severity: Finding["severity"],
  message: string,
  jsonPath: string,
  specReference: string,
): Finding {
  const location: FindingLocation = { jsonPath };
  return {
    ruleId,
    severity,
    message,
    location,
    help: `Correct the value at ${jsonPath}.`,
    specReference,
  };
}

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAbsoluteHttpsUrlWithoutFragment(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin !== "null" && url.hash.length === 0;
  } catch {
    return false;
  }
}

function sameResource(left: string, right: string): boolean {
  return normalizeResourceUrl(left) === normalizeResourceUrl(right);
}

function sameUrl(left: string, right: string): boolean {
  return normalizeResourceUrl(left) === normalizeResourceUrl(right);
}

function normalizeResourceUrl(value: string): string {
  const url = new URL(value);
  url.hash = "";
  url.search = "";
  if (url.pathname.length > 1 && url.pathname.endsWith("/")) {
    url.pathname = url.pathname.slice(0, -1);
  }
  return url.toString();
}

function sameOrigin(left: string, right: string): boolean {
  return new URL(left).origin === new URL(right).origin;
}

function normalizedPath(pathname: string): string {
  if (pathname === "/" || pathname === "/auth.md") {
    return "";
  }
  return pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
}

function uniqueUrls(urls: readonly string[]): string[] {
  return [...new Set(urls)];
}
