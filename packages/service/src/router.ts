import { decodeJson, sha256 } from "./encoding.js";
import { errorResponse, isOAuthError, OAuthError } from "./errors.js";
import {
  createStaticVerificationKeys,
  createVerificationKeysFromJwks,
  importEs256SigningKey,
} from "./jose.js";
import { D1FixedWindowRateLimiter } from "./rate-limit.js";
import {
  type ClaimRouteRepository,
  ClaimStateServiceStore,
  D1ClaimRouteRepository,
  D1ServiceStore,
} from "./repository.js";
import {
  type AgentAuthService,
  createService,
  SharedSecretServiceAuthenticator,
} from "./service.js";
import type {
  ClaimRepository,
  D1Database,
  DurableObjectNamespace,
  PublicJwk,
  ServiceOptions,
  VerificationKeyResolver,
} from "./types.js";

export interface WorkerEnvironment {
  DB: D1Database;
  CLAIM_CEREMONY: DurableObjectNamespace;
  EVENT_DELIVERY: DurableObjectNamespace;
  ISSUER?: string;
  PROTECTED_RESOURCES?: string;
  SERVICE_SIGNING_JWK: string;
  SERVICE_SIGNING_KID?: string;
  SERVICE_RETIRED_JWKS?: string;
  SERVICE_AUTH_TOKEN?: string;
  SERVICE_AUTH_SUBJECT?: string;
  SERVICE_AUTH_SCOPE?: string;
  SERVICE_AUTH_RESOURCE?: string;
  TRUSTED_ASSERTION_ISSUER?: string;
  TRUSTED_ASSERTION_JWKS?: string;
}

export interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
}

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
    },
  });
}

function emptyResponse(status = 204): Response {
  return new Response(null, { status, headers: { "cache-control": "no-store" } });
}

async function readJson(request: Request): Promise<JsonObject> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    throw new OAuthError("invalid_request");
  }
  if (!isObject(body)) {
    throw new OAuthError("invalid_request");
  }
  return body;
}

async function readOAuthFields(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.startsWith("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(await request.text()));
  }
  const body = await readJson(request);
  const fields: Record<string, string> = {};
  for (const [key, value] of Object.entries(body)) {
    if (typeof value === "string") {
      fields[key] = value;
    }
  }
  return fields;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || !value) {
    throw new OAuthError("invalid_request");
  }
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function clientRateLimitKey(request: Request): string {
  return (
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    "unknown"
  );
}

function getIssuer(request: Request, configuredIssuer: string | undefined): string {
  return configuredIssuer?.replace(/\/+$/u, "") ?? new URL(request.url).origin;
}

async function trustedKeys(
  issuer: string,
  signingKey: Awaited<ReturnType<typeof importEs256SigningKey>>,
  environment: WorkerEnvironment,
  retiredSigningKeys: readonly PublicJwk[],
): Promise<{ issuer: string; resolver: VerificationKeyResolver }> {
  const trustedIssuer = environment.TRUSTED_ASSERTION_ISSUER ?? issuer;
  if (!environment.TRUSTED_ASSERTION_JWKS) {
    if (trustedIssuer !== issuer) {
      throw new Error("TRUSTED_ASSERTION_JWKS is required for an external assertion issuer");
    }
    return {
      issuer,
      resolver: await createStaticVerificationKeys(issuer, signingKey, retiredSigningKeys),
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(environment.TRUSTED_ASSERTION_JWKS);
  } catch {
    throw new Error("TRUSTED_ASSERTION_JWKS is not valid JSON");
  }
  if (!isObject(parsed) || !Array.isArray(parsed.keys)) {
    throw new Error("TRUSTED_ASSERTION_JWKS needs a keys array");
  }
  return {
    issuer: trustedIssuer,
    resolver: await createVerificationKeysFromJwks(trustedIssuer, {
      keys: parsed.keys as PublicJwk[],
    }),
  };
}

function parseProtectedResources(value: string | undefined, issuer: string): readonly string[] {
  if (!value) {
    return [issuer];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("PROTECTED_RESOURCES must be a JSON array of resource URLs");
  }
  if (
    !Array.isArray(parsed) ||
    parsed.some((resource) => typeof resource !== "string" || !resource)
  ) {
    throw new Error("PROTECTED_RESOURCES must be a JSON array of resource URLs");
  }
  return parsed;
}

function parseRetiredSigningKeys(value: string | undefined): readonly PublicJwk[] {
  if (!value) {
    return [];
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("SERVICE_RETIRED_JWKS must be JSON");
  }
  const keys = isObject(parsed) && Array.isArray(parsed.keys) ? parsed.keys : parsed;
  if (!Array.isArray(keys) || keys.some((key) => !isObject(key))) {
    throw new Error("SERVICE_RETIRED_JWKS must be a JWKS object or array of public JWKs");
  }
  return keys as PublicJwk[];
}

function activeSigningKey(environment: WorkerEnvironment): { kid: string; privateJwk: JsonWebKey } {
  let privateJwk: unknown;
  try {
    privateJwk = JSON.parse(environment.SERVICE_SIGNING_JWK);
  } catch {
    throw new Error("SERVICE_SIGNING_JWK must be valid JSON");
  }
  if (!isObject(privateJwk)) {
    throw new Error("SERVICE_SIGNING_JWK must be a JWK object");
  }

  const configuredKid = environment.SERVICE_SIGNING_KID;
  const jwkKid = privateJwk.kid;
  if (configuredKid !== undefined && (!configuredKid || typeof configuredKid !== "string")) {
    throw new Error("SERVICE_SIGNING_KID must be a non-empty string when configured");
  }
  if (jwkKid !== undefined && (typeof jwkKid !== "string" || !jwkKid)) {
    throw new Error("SERVICE_SIGNING_JWK kid must be a non-empty string when present");
  }
  if (configuredKid && jwkKid && configuredKid !== jwkKid) {
    throw new Error("SERVICE_SIGNING_KID must match the active SERVICE_SIGNING_JWK kid");
  }

  return {
    kid: configuredKid ?? (jwkKid as string | undefined) ?? "service-es256-1",
    privateJwk,
  };
}

export async function createWorkerService(
  environment: WorkerEnvironment,
  issuer: string,
  claimRepository?: ClaimRepository,
): Promise<AgentAuthService> {
  const activeKey = activeSigningKey(environment);
  const signingKey = await importEs256SigningKey(activeKey.kid, activeKey.privateJwk);
  const retiredSigningKeys = parseRetiredSigningKeys(environment.SERVICE_RETIRED_JWKS);
  const trusted = await trustedKeys(issuer, signingKey, environment, retiredSigningKeys);
  const authenticator = environment.SERVICE_AUTH_TOKEN
    ? new SharedSecretServiceAuthenticator(environment.SERVICE_AUTH_TOKEN, {
        subject: environment.SERVICE_AUTH_SUBJECT ?? "service-client",
        scopes: environment.SERVICE_AUTH_SCOPE?.split(/\s+/u).filter(Boolean),
        resource: environment.SERVICE_AUTH_RESOURCE,
      })
    : undefined;
  const options: ServiceOptions = {
    issuer,
    supportedScopes: ["agent:read", "agent:write"],
    defaultResource: issuer,
    protectedResources: parseProtectedResources(environment.PROTECTED_RESOURCES, issuer),
    signingKey,
    retiredSigningKeys,
    verificationKeys: trusted.resolver,
    trustedAssertionIssuer: trusted.issuer,
  };
  const d1Store = new D1ServiceStore(environment.DB);
  return createService(options, {
    store: claimRepository
      ? new ClaimStateServiceStore(
          d1Store,
          claimRepository,
          new D1ClaimRouteRepository(environment.DB),
        )
      : d1Store,
    authenticator,
    rateLimiter: new D1FixedWindowRateLimiter(environment.DB),
  });
}

const claimCeremonyPaths = new Set([
  "/agent/identity/claim",
  "/agent/identity/claim/poll",
  "/agent/identity/claim/complete",
  "/agent/claim",
  "/agent/claim/poll",
  "/agent/claim/confirm",
  "/oauth2/token",
  "/token",
]);

const eventDeliveryName = "event-delivery";
const eventDeliverySchedulePath = "/__warden/internal/event-delivery/schedule";

function registrationId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(value)) {
    throw new OAuthError("invalid_request");
  }
  return value;
}

async function forwardFields(request: Request): Promise<Record<string, string>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.startsWith("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(await request.clone().text()));
  }
  const body = await request
    .clone()
    .json()
    .catch(() => {
      throw new OAuthError("invalid_request");
    });
  if (!isObject(body)) {
    throw new OAuthError("invalid_request");
  }
  return Object.fromEntries(
    Object.entries(body).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
}

function identityIdFromClaimGrant(claimGrant: string | undefined): string {
  if (!claimGrant) {
    throw new OAuthError("invalid_request");
  }
  const payload = claimGrant.split(".")[1];
  if (!payload) {
    throw new OAuthError("invalid_grant");
  }
  try {
    return registrationId(decodeJson<Record<string, unknown>>(payload).identity_id);
  } catch (error) {
    if (isOAuthError(error)) {
      throw error;
    }
    throw new OAuthError("invalid_grant");
  }
}

async function registrationFromClaimFields(
  fields: Record<string, string>,
  routes: ClaimRouteRepository,
): Promise<string> {
  let registration: string | undefined;
  if (fields.device_code) {
    registration = await routes.findRegistrationByDeviceCodeHash(
      await sha256(fields.device_code),
      Date.now(),
    );
  } else if (fields.user_code) {
    registration = await routes.findRegistrationByUserCodeHash(
      await sha256(fields.user_code),
      Date.now(),
    );
  } else if (fields.claim_id) {
    registration = await routes.findRegistrationByClaimId(fields.claim_id, Date.now());
  }
  if (!registration) {
    throw new OAuthError("invalid_grant");
  }
  if (fields.identity_id && fields.identity_id !== registration) {
    throw new OAuthError("invalid_grant");
  }
  return registrationId(registration);
}

async function claimRegistrationForRequest(
  request: Request,
  database: D1Database,
): Promise<string | undefined> {
  const path = new URL(request.url).pathname;
  if (request.method !== "POST" || !claimCeremonyPaths.has(path)) {
    return undefined;
  }
  const fields = await forwardFields(request);
  if (path === "/oauth2/token" || path === "/token") {
    return fields.grant_type === "urn:workos:agent-auth:grant-type:claim"
      ? identityIdFromClaimGrant(fields.claim_grant)
      : undefined;
  }
  if (fields.device_code || fields.user_code || fields.claim_id) {
    return registrationFromClaimFields(fields, new D1ClaimRouteRepository(database));
  }
  return registrationId(fields.identity_id);
}

function forwardToClaimCeremony(
  request: Request,
  namespace: DurableObjectNamespace,
  issuer: string,
  registration: string,
): Promise<Response> {
  const headers = new Headers(request.headers);
  headers.set("x-warden-issuer", issuer);
  headers.set("x-warden-registration-id", registration);
  const durableObject = namespace.get(namespace.idFromName(`registration:${registration}`));
  return durableObject.fetch(new Request(request, { headers }));
}

async function scheduleEventDelivery(
  namespace: DurableObjectNamespace,
  issuer: string,
): Promise<void> {
  const durableObject = namespace.get(namespace.idFromName(eventDeliveryName));
  const response = await durableObject.fetch(
    new Request(`https://${eventDeliveryName}.internal${eventDeliverySchedulePath}`, {
      method: "POST",
      headers: { "x-warden-issuer": issuer },
    }),
  );
  if (!response.ok) {
    throw new Error(`event delivery scheduler returned ${response.status}`);
  }
}

export function createRouter(service: AgentAuthService): {
  fetch(request: Request, context?: ExecutionContext): Promise<Response>;
} {
  return {
    async fetch(request: Request, _context?: ExecutionContext): Promise<Response> {
      try {
        const url = new URL(request.url);
        if (request.method === "OPTIONS") {
          return emptyResponse();
        }
        if (request.method === "GET") {
          switch (url.pathname) {
            case "/auth.md":
              return new Response(service.authMd(), {
                headers: {
                  "cache-control": "no-store",
                  "content-type": "text/markdown; charset=utf-8",
                },
              });
            case "/.well-known/oauth-protected-resource":
              return response(service.protectedResourceMetadata());
            case "/.well-known/oauth-authorization-server":
              return response(service.authorizationServerMetadata());
            case "/.well-known/jwks.json":
              return response(service.publicJwks());
            case "/claim":
              return new Response("claim confirmation is performed by the service owner", {
                headers: { "content-type": "text/plain; charset=utf-8" },
              });
            default:
              throw new OAuthError("invalid_request");
          }
        }
        if (request.method !== "POST") {
          throw new OAuthError("invalid_request");
        }
        switch (url.pathname) {
          case "/agent/identity": {
            const body = await readJson(request);
            const identityType = optionalString(body.identity_type);
            if (
              identityType !== "anonymous" &&
              identityType !== "service_auth" &&
              identityType !== "identity_assertion"
            ) {
              throw new OAuthError("invalid_request");
            }
            const result = await service.registerIdentity({
              identityType,
              scope: optionalString(body.scope),
              resource: optionalString(body.resource),
              clientId: optionalString(body.client_id),
              serviceToken: optionalString(body.service_token),
              assertion: optionalString(body.assertion),
              rateLimitKey: clientRateLimitKey(request),
            });
            return response({
              identity_id: result.identity.id,
              identity_type: result.identity.type,
              scope: result.identity.scopes.join(" "),
              ...(result.identity.resource ? { resource: result.identity.resource } : {}),
              ...(result.identity.expiresAt
                ? {
                    expires_in: Math.max(
                      0,
                      Math.floor((result.identity.expiresAt - result.identity.createdAt) / 1000),
                    ),
                  }
                : {}),
              claim_endpoint: service.claimEndpoint,
            });
          }
          case "/agent/identity/claim":
          case "/agent/identity/claim/poll":
          case "/agent/claim":
          case "/agent/claim/poll": {
            const body = await readJson(request);
            const action = optionalString(body.action);
            if (
              url.pathname === "/agent/identity/claim/poll" ||
              url.pathname === "/agent/claim/poll" ||
              action === "poll" ||
              body.device_code
            ) {
              const polled = await service.pollClaim(requiredString(body.device_code));
              if (polled.status === "pending") {
                throw new OAuthError("authorization_pending");
              }
              return response({
                status: "approved",
                claim_grant: polled.claimGrant,
                token_endpoint: service.tokenEndpoint,
              });
            }
            const started = await service.startClaim({
              identityId: requiredString(body.identity_id),
              scope: optionalString(body.scope),
              resource: optionalString(body.resource),
              rateLimitKey: clientRateLimitKey(request),
            });
            return response({
              device_code: started.deviceCode,
              user_code: started.userCode,
              verification_uri: `${new URL(service.claimEndpoint).origin}/claim`,
              verification_uri_complete: `${new URL(service.claimEndpoint).origin}/claim`,
              expires_in: Math.floor((started.claim.expiresAt - started.claim.createdAt) / 1000),
              interval: started.claim.intervalSeconds,
            });
          }
          case "/agent/identity/claim/complete":
          case "/agent/claim/confirm": {
            const body = await readJson(request);
            const action = requiredString(body.action);
            if (action === "verify") {
              const claim = await service.verifyClaimCode(
                requiredString(body.user_code),
                clientRateLimitKey(request),
              );
              return response({ claim_id: claim.id, status: claim.status });
            }
            if (action === "approve" || action === "deny") {
              const claim = await service.decideClaim(
                requiredString(body.claim_id),
                action === "approve" ? "approved" : "denied",
              );
              return response({ claim_id: claim.id, status: claim.status });
            }
            throw new OAuthError("invalid_request");
          }
          case "/oauth2/token":
          case "/token": {
            const fields = await readOAuthFields(request);
            const result = await service.exchangeToken({
              grantType: requiredString(fields.grant_type),
              assertion: fields.assertion,
              claimGrant: fields.claim_grant,
              clientId: fields.client_id,
              scope: fields.scope,
              resource: fields.resource,
            });
            return response({
              access_token: result.accessToken,
              token_type: result.tokenType,
              expires_in: result.expiresIn,
              scope: result.scope,
              resource: result.resource,
            });
          }
          case "/oauth2/revoke":
          case "/revoke": {
            const fields = await readOAuthFields(request);
            await service.revoke(requiredString(fields.token));
            return emptyResponse(200);
          }
          case "/agent/events/subscribe": {
            const body = await readJson(request);
            const subscriber = await service.subscribe(
              requiredString(body.url),
              optionalString(body.service_token),
            );
            return response({ subscriber_id: subscriber.id }, 201);
          }
          case "/agent/event/notify": {
            const body = await readJson(request);
            await service.receiveSecurityEvent(requiredString(body.event));
            return response({ accepted: true });
          }
          default:
            throw new OAuthError("invalid_request");
        }
      } catch (error) {
        if (isOAuthError(error)) {
          return errorResponse(error);
        }
        return errorResponse(new OAuthError("temporarily_unavailable"));
      }
    },
  };
}

export function createWorker(): {
  fetch(
    request: Request,
    environment: WorkerEnvironment,
    context: ExecutionContext,
  ): Promise<Response>;
} {
  let service: Promise<AgentAuthService> | undefined;
  let router: ReturnType<typeof createRouter> | undefined;
  let configuredIssuer: string | undefined;
  return {
    async fetch(
      request: Request,
      environment: WorkerEnvironment,
      context: ExecutionContext,
    ): Promise<Response> {
      try {
        const issuer = getIssuer(request, environment.ISSUER);
        const registration = await claimRegistrationForRequest(request, environment.DB);
        if (registration) {
          return forwardToClaimCeremony(request, environment.CLAIM_CEREMONY, issuer, registration);
        }
        if (!service || configuredIssuer !== issuer) {
          configuredIssuer = issuer;
          service = createWorkerService(environment, issuer);
          router = undefined;
        }
        router ??= createRouter(await service);
        const response = await router.fetch(request, context);
        if (
          response.status === 200 &&
          request.method === "POST" &&
          ["/oauth2/revoke", "/revoke"].includes(new URL(request.url).pathname)
        ) {
          context.waitUntil(scheduleEventDelivery(environment.EVENT_DELIVERY, issuer));
        }
        return response;
      } catch (error) {
        if (isOAuthError(error)) {
          return errorResponse(error);
        }
        return errorResponse(new OAuthError("temporarily_unavailable"));
      }
    },
  };
}
