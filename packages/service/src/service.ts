import { ClaimCeremony } from "./claim.js";
import { constantTimeEqual, decodeJson, splitScope } from "./encoding.js";
import { OAuthError } from "./errors.js";
import {
  createStaticVerificationKeys,
  jwks,
  type StaticVerificationKeys,
  signJwt,
  type VerifiedJwt,
  verifyJwt,
} from "./jose.js";
import { FixedWindowRateLimiter } from "./rate-limit.js";
import type {
  AnonymousOptions,
  ClaimRecord,
  Clock,
  DeliveryFetch,
  EventDelivery,
  EventSubscriber,
  IdentifierGenerator,
  IssuedToken,
  PollResult,
  RateLimiter,
  RegistrationRequest,
  RegistrationResult,
  SecurityEventClaims,
  ServiceAuthenticator,
  ServiceIdentity,
  ServiceOptions,
  ServiceStore,
  StartClaimRequest,
  StartedClaim,
  TokenExchangeRequest,
  TokenExchangeResult,
  TokenOptions,
  VerificationKeyResolver,
} from "./types.js";
import { randomIdentifierGenerator, systemClock } from "./types.js";

export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const CLAIM_GRANT = "urn:workos:agent-auth:grant-type:claim";
export const TOKEN_REVOKED_EVENT = "https://schemas.openid.net/secevent/risc/token-revoked";

const defaultAnonymousOptions: AnonymousOptions = {
  expiresInSeconds: 900,
  maxRegistrationsPerWindow: 10,
  registrationWindowSeconds: 3600,
};

const defaultTokenOptions: TokenOptions = {
  expiresInSeconds: 300,
};

interface Dependencies {
  store: ServiceStore;
  clock?: Clock;
  identifiers?: IdentifierGenerator;
  authenticator?: ServiceAuthenticator;
  rateLimiter?: RateLimiter;
}

interface UnverifiedJwtPayload {
  iss?: unknown;
  aud?: unknown;
}

interface ExchangeAuthorization {
  identity: ServiceIdentity;
  allowedScopes: readonly string[];
  resource?: string;
}

function withoutTrailingSlash(value: string): string {
  return value.replace(/\/+$/u, "");
}

function integerSeconds(milliseconds: number): number {
  return Math.floor(milliseconds / 1000);
}

function scopesWithin(requested: readonly string[], allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return requested.every((scope) => allowedSet.has(scope));
}

function sameScopes(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((scope) => right.includes(scope));
}

function requestedScopes(
  scope: string | undefined,
  fallback: readonly string[],
): readonly string[] {
  const parsed = splitScope(scope);
  return parsed.length > 0 ? parsed : fallback;
}

function optionalText(value: unknown): string | undefined {
  return typeof value === "string" && value ? value : undefined;
}

function normalizeResource(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    const localDevelopmentResource = parsed.protocol === "http:" && parsed.hostname === "localhost";
    if (
      (parsed.protocol !== "https:" && !localDevelopmentResource) ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) {
      return undefined;
    }
    return withoutTrailingSlash(parsed.toString());
  } catch {
    return undefined;
  }
}

function audienceFromPayload(value: unknown): string | undefined {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value) && value.length === 1 && typeof value[0] === "string") {
    return value[0];
  }
  return undefined;
}

export class SharedSecretServiceAuthenticator implements ServiceAuthenticator {
  public constructor(
    private readonly secret: string,
    private readonly result: {
      subject: string;
      clientId?: string;
      scopes?: readonly string[];
      resource?: string;
    },
  ) {}

  public async authenticate(
    token: string,
  ): Promise<{ subject: string; clientId?: string } | undefined> {
    if (!constantTimeEqual(token, this.secret)) {
      return undefined;
    }
    return this.result;
  }
}

export class AgentAuthService {
  private readonly issuer: string;
  private readonly supportedScopes: readonly string[];
  private readonly defaultResource: string;
  private readonly protectedResources: ReadonlySet<string>;
  private readonly anonymousOptions: AnonymousOptions;
  private readonly tokenOptions: TokenOptions;
  private readonly clock: Clock;
  private readonly identifiers: IdentifierGenerator;
  private readonly rateLimiter: RateLimiter;
  private readonly claims: ClaimCeremony;
  private readonly ownVerificationKeys: StaticVerificationKeys;

  private constructor(
    private readonly options: ServiceOptions,
    private readonly store: ServiceStore,
    dependencies: Dependencies,
    ownVerificationKeys: StaticVerificationKeys,
  ) {
    this.issuer = withoutTrailingSlash(options.issuer);
    this.supportedScopes = [...options.supportedScopes];
    this.defaultResource = options.defaultResource;
    this.protectedResources = new Set(options.protectedResources ?? [options.defaultResource]);
    this.anonymousOptions = { ...defaultAnonymousOptions, ...options.anonymous };
    this.tokenOptions = { ...defaultTokenOptions, ...options.token };
    this.clock = dependencies.clock ?? systemClock;
    this.identifiers = dependencies.identifiers ?? randomIdentifierGenerator;
    this.rateLimiter = dependencies.rateLimiter ?? new FixedWindowRateLimiter();
    this.claims = new ClaimCeremony(
      store,
      this.clock,
      this.identifiers,
      this.rateLimiter,
      options.claim,
    );
    this.ownVerificationKeys = ownVerificationKeys;
    this.authenticator = dependencies.authenticator;
  }

  private readonly authenticator: ServiceAuthenticator | undefined;

  public static async create(
    options: ServiceOptions,
    dependencies: Dependencies,
  ): Promise<AgentAuthService> {
    const issuer = withoutTrailingSlash(options.issuer);
    if (!issuer.startsWith("https://") && !issuer.startsWith("http://localhost")) {
      throw new Error("issuer must be an https URL or local development URL");
    }
    if (options.supportedScopes.length === 0) {
      throw new Error("at least one supported scope is required");
    }
    const defaultResource = normalizeResource(options.defaultResource);
    if (!defaultResource) {
      throw new Error(
        "defaultResource must be an https URL or local development URL without query data",
      );
    }
    const protectedResources = [
      ...new Set(
        [defaultResource, ...(options.protectedResources ?? [])].map((resource) => {
          const normalized = normalizeResource(resource);
          if (!normalized) {
            throw new Error(
              "protectedResources must contain https URLs or local development URLs without query data",
            );
          }
          return normalized;
        }),
      ),
    ];
    const retiredSigningKeys = options.retiredSigningKeys ?? [];
    if (retiredSigningKeys.some((key) => key.d !== undefined)) {
      throw new Error("retiredSigningKeys must contain public JWKs only");
    }
    const ownVerificationKeys = await createStaticVerificationKeys(
      issuer,
      options.signingKey,
      retiredSigningKeys,
    );
    return new AgentAuthService(
      { ...options, issuer, defaultResource, protectedResources, retiredSigningKeys },
      dependencies.store,
      dependencies,
      ownVerificationKeys,
    );
  }

  public get identityEndpoint(): string {
    return `${this.issuer}/agent/identity`;
  }

  public get claimEndpoint(): string {
    return `${this.issuer}/agent/identity/claim`;
  }

  public get claimCompleteEndpoint(): string {
    return `${this.claimEndpoint}/complete`;
  }

  public get tokenEndpoint(): string {
    return `${this.issuer}/oauth2/token`;
  }

  public get revocationEndpoint(): string {
    return `${this.issuer}/oauth2/revoke`;
  }

  public get eventEndpoint(): string {
    return `${this.issuer}/agent/event/notify`;
  }

  public protectedResourceMetadata(): Readonly<Record<string, unknown>> {
    return {
      resource: this.defaultResource,
      authorization_servers: [this.issuer],
      bearer_methods_supported: ["header"],
      scopes_supported: this.supportedScopes,
      resource_documentation: `${this.issuer}/auth.md`,
    };
  }

  public authorizationServerMetadata(): Readonly<Record<string, unknown>> {
    return {
      issuer: this.issuer,
      jwks_uri: `${this.issuer}/.well-known/jwks.json`,
      token_endpoint: this.tokenEndpoint,
      revocation_endpoint: this.revocationEndpoint,
      grant_types_supported: [JWT_BEARER_GRANT, CLAIM_GRANT],
      token_endpoint_auth_methods_supported: ["none"],
      agent_auth: {
        identity_endpoint: this.identityEndpoint,
        claim_endpoint: this.claimEndpoint,
        claim_complete_endpoint: this.claimCompleteEndpoint,
        events_endpoint: this.eventEndpoint,
        skill: `${this.issuer}/auth.md`,
        identity_types_supported: ["anonymous", "service_auth", "identity_assertion"],
        identity_assertion: {
          assertion_types_supported: ["urn:ietf:params:oauth:token-type:jwt"],
        },
        events_supported: [TOKEN_REVOKED_EVENT],
      },
    };
  }

  public authMd(): string {
    return [
      "# auth.md",
      "",
      "A self-hosted agent registration service. Credentials are short lived, scoped, and revocable.",
      "",
      "## Discover",
      "",
      `Read [Protected Resource Metadata](${this.issuer}/.well-known/oauth-protected-resource) and ` +
        `[Authorization Server Metadata](${this.issuer}/.well-known/oauth-authorization-server). ` +
        `Issuer: ${this.issuer}`,
      "",
      "## Pick a method",
      "",
      "Register with identity_assertion when a trusted issuer can sign a JWT, service_auth for a configured service, or anonymous for a short-lived human-claim flow.",
      "",
      "## Register",
      "",
      `POST the chosen identity type to ${this.identityEndpoint}. Supported scopes: ${this.supportedScopes.join(", ")}.`,
      "",
      "## Claim ceremony",
      "",
      `POST to ${this.claimEndpoint} to receive a device_code and user_code, then poll only at the published interval. A service owner verifies and approves the code at ${this.claimCompleteEndpoint} before the grant is issued.`,
      "",
      "## Exchange the assertion",
      "",
      `POST a JWT bearer assertion or a one-use claim_grant to ${this.tokenEndpoint}. Requested scope and resource can only narrow the registered values.`,
      "",
      "## Use the access_token",
      "",
      "Send the Bearer access_token to the exact resource audience until it expires or is revoked.",
      "",
      "## Errors",
      "",
      "Responses contain stable OAuth error codes, including authorization_pending, slow_down, access_denied, expired_token, invalid_scope, and invalid_target.",
      "",
      "## Revocation",
      "",
      `POST a token to ${this.revocationEndpoint}. Revocation follows RFC 7009 and emits a signed security event to configured subscribers.`,
      "",
    ].join("\n");
  }

  public publicJwks(): { keys: readonly JsonWebKey[] } {
    return jwks(this.options.signingKey, this.options.retiredSigningKeys);
  }

  public async registerIdentity(request: RegistrationRequest): Promise<RegistrationResult> {
    const now = this.clock.now();
    let identity: ServiceIdentity;
    try {
      const explicitScopes = splitScope(request.scope);
      if (explicitScopes.length > 0 && !scopesWithin(explicitScopes, this.supportedScopes)) {
        throw new OAuthError("invalid_scope");
      }
      const requestedResource = request.resource
        ? this.configuredResource(request.resource)
        : undefined;
      if (request.resource && !requestedResource) {
        throw new OAuthError("invalid_target");
      }
      const resource = requestedResource ?? this.defaultResource;

      switch (request.identityType) {
        case "anonymous": {
          const allowed = await this.rateLimiter.take(
            `anonymous-registration:${request.rateLimitKey}`,
            this.anonymousOptions.maxRegistrationsPerWindow,
            this.anonymousOptions.registrationWindowSeconds,
            now,
          );
          if (!allowed) {
            throw new OAuthError("temporarily_unavailable");
          }
          identity = {
            id: this.identifiers.next("identity"),
            type: "anonymous",
            scopes: explicitScopes.length > 0 ? explicitScopes : this.supportedScopes,
            resource,
            clientId: request.clientId,
            createdAt: now,
            expiresAt: now + this.anonymousOptions.expiresInSeconds * 1000,
          };
          break;
        }
        case "service_auth": {
          if (!request.serviceToken || !this.authenticator) {
            throw new OAuthError("invalid_client");
          }
          const authenticated = await this.authenticator.authenticate(request.serviceToken);
          if (!authenticated) {
            throw new OAuthError("invalid_client");
          }
          const authenticatedScopes = authenticated.scopes ?? this.supportedScopes;
          const registeredScopes = explicitScopes.length > 0 ? explicitScopes : authenticatedScopes;
          if (
            !scopesWithin(authenticatedScopes, this.supportedScopes) ||
            !scopesWithin(registeredScopes, authenticatedScopes)
          ) {
            throw new OAuthError("invalid_scope");
          }
          const authenticatedResource = authenticated.resource
            ? this.configuredResource(authenticated.resource)
            : undefined;
          if (
            (authenticated.resource && !authenticatedResource) ||
            (authenticatedResource &&
              requestedResource &&
              requestedResource !== authenticatedResource)
          ) {
            throw new OAuthError("invalid_target");
          }
          identity = {
            id: this.identifiers.next("identity"),
            type: "service_auth",
            scopes: registeredScopes,
            resource: authenticatedResource ?? resource,
            clientId: authenticated.clientId ?? request.clientId,
            subject: authenticated.subject,
            createdAt: now,
          };
          break;
        }
        case "identity_assertion": {
          if (!request.assertion || !request.clientId) {
            throw new OAuthError("invalid_request");
          }
          const assertion = await verifyJwt(request.assertion, {
            keyResolver: this.options.verificationKeys,
            expectedIssuer: this.options.trustedAssertionIssuer,
            expectedAudience: this.identityEndpoint,
            clock: this.clock,
            replayRepository: this.store,
          });
          const assertionClientId = optionalText(assertion.claims.client_id);
          if (!assertionClientId || assertionClientId !== request.clientId) {
            throw new OAuthError("invalid_grant");
          }
          const assertionScopes = requestedScopes(
            optionalText(assertion.claims.scope),
            this.supportedScopes,
          );
          const registeredScopes = explicitScopes.length > 0 ? explicitScopes : assertionScopes;
          if (
            !scopesWithin(assertionScopes, this.supportedScopes) ||
            !scopesWithin(registeredScopes, assertionScopes)
          ) {
            throw new OAuthError("invalid_scope");
          }
          const assertedResourceValue = optionalText(assertion.claims.resource);
          const assertionResource = assertedResourceValue
            ? this.configuredResource(assertedResourceValue)
            : undefined;
          if (
            (assertedResourceValue && !assertionResource) ||
            (assertionResource && requestedResource && requestedResource !== assertionResource)
          ) {
            throw new OAuthError("invalid_target");
          }
          identity = {
            id: this.identifiers.next("identity"),
            type: "identity_assertion",
            scopes: registeredScopes,
            resource: assertionResource ?? resource,
            clientId: assertionClientId,
            subject: assertion.claims.sub,
            createdAt: now,
          };
          break;
        }
        default: {
          throw new OAuthError("invalid_request");
        }
      }
      await this.store.createIdentity(identity);
    } catch (error) {
      await this.recordIdentityAttempt(request, now, "rejected", error);
      throw error;
    }
    await this.recordIdentityAttempt(request, now, "accepted", undefined, identity);
    return { identity };
  }

  public async startClaim(request: StartClaimRequest): Promise<StartedClaim> {
    const identity = await this.requireActiveIdentity(request.identityId);
    const scopes = requestedScopes(request.scope, identity.scopes);
    if (!scopesWithin(scopes, identity.scopes)) {
      throw new OAuthError("invalid_scope");
    }
    const resource = request.resource
      ? this.configuredResource(request.resource)
      : (identity.resource ?? this.defaultResource);
    if (!resource) {
      throw new OAuthError("invalid_target");
    }
    if (!this.resourceMatches(identity, resource)) {
      throw new OAuthError("invalid_target");
    }
    return this.claims.start(identity.id, scopes, resource, request.rateLimitKey);
  }

  public async verifyClaimCode(userCode: string, rateLimitKey?: string): Promise<ClaimRecord> {
    return this.claims.verifyUserCode(userCode, rateLimitKey);
  }

  public async decideClaim(claimId: string, decision: "approved" | "denied"): Promise<ClaimRecord> {
    return this.claims.decide(claimId, decision);
  }

  public async pollClaim(deviceCode: string): Promise<PollResult & { claimGrant?: string }> {
    const result = await this.claims.poll(deviceCode);
    if (result.status !== "approved" || !result.claim) {
      return result;
    }
    const now = integerSeconds(this.clock.now());
    const claimGrant = await signJwt(
      {
        iss: this.issuer,
        sub: result.claim.identityId,
        aud: this.tokenEndpoint,
        iat: now,
        exp: Math.floor(result.claim.expiresAt / 1000),
        jti: `claim-grant:${result.claim.id}`,
        purpose: "claim_grant",
        claim_id: result.claim.id,
        identity_id: result.claim.identityId,
      },
      this.options.signingKey,
    );
    return { ...result, claimGrant };
  }

  public async issueIdentityAssertion(identityId: string, audience: string): Promise<string> {
    const identity = await this.requireActiveIdentity(identityId);
    if (identity.type !== "identity_assertion" || !identity.subject || !identity.clientId) {
      throw new OAuthError("invalid_grant");
    }
    const now = integerSeconds(this.clock.now());
    return signJwt(
      {
        iss: this.issuer,
        sub: identity.subject,
        aud: audience,
        iat: now,
        exp: now + this.tokenOptions.expiresInSeconds,
        jti: this.identifiers.next("assertion"),
        scope: identity.scopes.join(" "),
        identity_id: identity.id,
        client_id: identity.clientId,
      },
      this.options.signingKey,
    );
  }

  public async exchangeToken(request: TokenExchangeRequest): Promise<TokenExchangeResult> {
    const authorization = await this.identityForExchange(request);
    const { identity } = authorization;
    const scopes = requestedScopes(request.scope, authorization.allowedScopes);
    if (!scopesWithin(scopes, authorization.allowedScopes)) {
      throw new OAuthError("invalid_scope");
    }
    const resource = request.resource
      ? this.configuredResource(request.resource)
      : (authorization.resource ?? identity.resource ?? this.defaultResource);
    if (!resource) {
      throw new OAuthError("invalid_target");
    }
    if (
      !this.resourceMatches(identity, resource) ||
      (authorization.resource !== undefined && authorization.resource !== resource)
    ) {
      throw new OAuthError("invalid_target");
    }
    const now = integerSeconds(this.clock.now());
    const token: IssuedToken = {
      id: this.identifiers.next("token"),
      identityId: identity.id,
      subject: identity.subject ?? identity.id,
      scopes,
      resource,
      issuedAt: now * 1000,
      expiresAt: (now + this.tokenOptions.expiresInSeconds) * 1000,
    };
    await this.store.createToken(token);
    const accessToken = await signJwt(
      {
        iss: this.issuer,
        sub: token.subject,
        aud: token.resource,
        iat: now,
        exp: now + this.tokenOptions.expiresInSeconds,
        jti: token.id,
        scope: token.scopes.join(" "),
        identity_id: token.identityId,
      },
      this.options.signingKey,
    );
    return {
      accessToken,
      tokenType: "Bearer",
      expiresIn: this.tokenOptions.expiresInSeconds,
      scope: token.scopes.join(" "),
      resource,
    };
  }

  /**
   * Resource-side enforcement: signature checks alone are insufficient because
   * revocation is persisted independently of the signed token.
   */
  public async validateAccessToken(
    token: string,
    expectedResource = this.defaultResource,
  ): Promise<IssuedToken> {
    const resource = this.configuredResource(expectedResource);
    if (!resource) {
      throw new OAuthError("invalid_target");
    }
    let verified: VerifiedJwt;
    try {
      verified = await verifyJwt(token, {
        keyResolver: this.ownVerificationKeys,
        expectedIssuer: this.issuer,
        expectedAudience: resource,
        clock: this.clock,
      });
    } catch {
      throw new OAuthError("invalid_token");
    }
    const stored = await this.store.findTokenById(verified.claims.jti);
    const tokenScopes = splitScope(optionalText(verified.claims.scope));
    if (
      !stored ||
      stored.revokedAt !== undefined ||
      stored.expiresAt <= this.clock.now() ||
      stored.resource !== resource ||
      stored.subject !== verified.claims.sub ||
      stored.identityId !== optionalText(verified.claims.identity_id) ||
      !sameScopes(stored.scopes, tokenScopes)
    ) {
      throw new OAuthError("invalid_token");
    }
    return stored;
  }

  public async revoke(token: string): Promise<void> {
    const claims = await this.verifyOwnTokenForRevocation(token);
    if (!claims) {
      return;
    }
    const revoked = await this.store.revokeToken(claims.jti, this.clock.now());
    if (!revoked) {
      return;
    }
    const storedToken = await this.store.findTokenById(claims.jti);
    if (!storedToken || storedToken.subject !== claims.sub || storedToken.resource !== claims.aud) {
      return;
    }
    const event = {
      id: this.identifiers.next("event"),
      tokenId: storedToken.id,
      subject: storedToken.subject,
      occurredAt: this.clock.now(),
    };
    if (!(await this.store.createEvent(event))) {
      return;
    }
    const subscribers = await this.store.listSubscribers();
    await Promise.all(
      subscribers.map((subscriber) =>
        this.store.createDelivery({
          id: this.identifiers.next("delivery"),
          eventId: event.id,
          subscriberId: subscriber.id,
          status: "pending",
          attempts: 0,
          nextAttemptAt: event.occurredAt,
        }),
      ),
    );
  }

  public async subscribe(url: string, serviceToken: string | undefined): Promise<EventSubscriber> {
    if (
      !serviceToken ||
      !this.authenticator ||
      !(await this.authenticator.authenticate(serviceToken))
    ) {
      throw new OAuthError("invalid_client");
    }
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new OAuthError("invalid_request");
    }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
      throw new OAuthError("invalid_request");
    }
    const subscriber: EventSubscriber = {
      id: this.identifiers.next("subscriber"),
      url: parsed.toString(),
      createdAt: this.clock.now(),
    };
    await this.store.createSubscriber(subscriber);
    return subscriber;
  }

  public async deliverDueEvents(
    fetcher: DeliveryFetch,
    limit = 25,
  ): Promise<readonly EventDelivery[]> {
    const now = this.clock.now();
    const due = await this.store.listDueDeliveries(now, limit);
    const completed: EventDelivery[] = [];
    for (const delivery of due) {
      const subscriber = await this.store.findSubscriber(delivery.subscriberId);
      const event = await this.store.findEventById(delivery.eventId);
      if (!subscriber || !event) {
        const failed = { ...delivery, status: "failed" as const, lastAttemptAt: now };
        await this.store.saveDelivery(failed);
        completed.push(failed);
        continue;
      }
      const set = await this.signSecurityEvent(event, subscriber, delivery.id, now);
      let response: Response | undefined;
      try {
        response = await fetcher(subscriber.url, {
          method: "POST",
          headers: {
            "content-type": "application/secevent+jwt",
            "idempotency-key": delivery.id,
          },
          body: set,
        });
      } catch {
        response = undefined;
      }
      const attempts = delivery.attempts + 1;
      const receipt = response?.headers.get("x-request-id")?.slice(0, 128) ?? undefined;
      const next: EventDelivery = response?.ok
        ? {
            ...delivery,
            status: "delivered",
            attempts,
            lastAttemptAt: now,
            receipt,
          }
        : attempts >= 5
          ? { ...delivery, status: "failed", attempts, lastAttemptAt: now }
          : {
              ...delivery,
              status: "pending",
              attempts,
              lastAttemptAt: now,
              nextAttemptAt: now + Math.min(300, 2 ** attempts) * 1000,
            };
      await this.store.saveDelivery(next);
      completed.push(next);
    }
    return completed;
  }

  public nextEventDeliveryAt(): Promise<number | undefined> {
    return this.store.nextPendingDeliveryAt();
  }

  public async receiveSecurityEvent(token: string): Promise<{ replayed: boolean }> {
    const verified = await verifyJwt(token, {
      keyResolver: this.options.verificationKeys,
      expectedIssuer: this.options.trustedAssertionIssuer,
      expectedAudience: this.eventEndpoint,
      clock: this.clock,
    });
    const events = verified.claims.events;
    if (
      !events ||
      typeof events !== "object" ||
      Array.isArray(events) ||
      !(TOKEN_REVOKED_EVENT in events)
    ) {
      throw new OAuthError("invalid_request");
    }
    const unused = await this.store.markIfUnused(
      {
        id: `set:${verified.claims.iss}:${verified.claims.jti}`,
        expiresAt: verified.claims.exp * 1000,
      },
      this.clock.now(),
    );
    if (!unused) {
      throw new OAuthError("invalid_grant");
    }
    return { replayed: false };
  }

  private async identityForExchange(request: TokenExchangeRequest): Promise<ExchangeAuthorization> {
    if (request.grantType === CLAIM_GRANT) {
      if (!request.claimGrant) {
        throw new OAuthError("invalid_request");
      }
      const verified = await verifyJwt(request.claimGrant, {
        keyResolver: this.ownVerificationKeys,
        expectedIssuer: this.issuer,
        expectedAudience: this.tokenEndpoint,
        clock: this.clock,
      });
      if (
        verified.claims.purpose !== "claim_grant" ||
        typeof verified.claims.claim_id !== "string" ||
        verified.claims.sub !== verified.claims.identity_id
      ) {
        throw new OAuthError("invalid_grant");
      }
      const claim = await this.claims.consumeApprovedClaim(verified.claims.claim_id);
      if (claim.identityId !== verified.claims.sub) {
        throw new OAuthError("invalid_grant");
      }
      const identity = await this.requireActiveIdentity(claim.identityId);
      return {
        identity,
        allowedScopes: claim.scopes,
        ...(claim.resource === undefined ? {} : { resource: claim.resource }),
      };
    }
    if (request.grantType === JWT_BEARER_GRANT) {
      if (!request.assertion || !request.clientId) {
        throw new OAuthError("invalid_request");
      }
      const verified = await verifyJwt(request.assertion, {
        keyResolver: this.options.verificationKeys,
        expectedIssuer: this.options.trustedAssertionIssuer,
        expectedAudience: this.tokenEndpoint,
        clock: this.clock,
        replayRepository: this.store,
      });
      const identityId = optionalText(verified.claims.identity_id);
      const assertionClientId = optionalText(verified.claims.client_id);
      if (!identityId || !assertionClientId || assertionClientId !== request.clientId) {
        throw new OAuthError("invalid_grant");
      }
      const activeIdentity = await this.requireActiveIdentity(identityId);
      if (
        activeIdentity.type !== "identity_assertion" ||
        activeIdentity.subject !== verified.claims.sub ||
        activeIdentity.clientId !== assertionClientId
      ) {
        throw new OAuthError("invalid_grant");
      }
      const assertionScopes = requestedScopes(
        optionalText(verified.claims.scope),
        activeIdentity.scopes,
      );
      if (!scopesWithin(assertionScopes, activeIdentity.scopes)) {
        throw new OAuthError("invalid_scope");
      }
      const assertionResourceValue = optionalText(verified.claims.resource);
      const assertionResource = assertionResourceValue
        ? this.configuredResource(assertionResourceValue)
        : undefined;
      if (
        (assertionResourceValue && !assertionResource) ||
        (assertionResource && !this.resourceMatches(activeIdentity, assertionResource))
      ) {
        throw new OAuthError("invalid_target");
      }
      return {
        identity: activeIdentity,
        allowedScopes: assertionScopes,
        ...(assertionResource === undefined ? {} : { resource: assertionResource }),
      };
    }
    throw new OAuthError("unsupported_grant_type");
  }

  private async requireActiveIdentity(id: string): Promise<ServiceIdentity> {
    const identity = await this.store.findIdentityById(id);
    if (
      !identity ||
      identity.revokedAt !== undefined ||
      (identity.expiresAt !== undefined && identity.expiresAt <= this.clock.now())
    ) {
      throw new OAuthError("invalid_grant");
    }
    return identity;
  }

  private resourceMatches(identity: ServiceIdentity, resource: string): boolean {
    const configured = this.configuredResource(resource);
    return (
      configured !== undefined &&
      (identity.resource === undefined || identity.resource === configured)
    );
  }

  private configuredResource(resource: string): string | undefined {
    const normalized = normalizeResource(resource);
    return normalized && this.protectedResources.has(normalized) ? normalized : undefined;
  }

  private async recordIdentityAttempt(
    request: RegistrationRequest,
    occurredAt: number,
    outcome: "accepted" | "rejected",
    error?: unknown,
    identity?: ServiceIdentity,
  ): Promise<void> {
    try {
      await this.store.createIdentityAttempt({
        id: identity
          ? `identity-attempt:${identity.id}`
          : this.identifiers.next("identity-attempt"),
        identityType: request.identityType,
        clientId: identity?.clientId ?? request.clientId,
        subject: identity?.subject,
        outcome,
        ...(error instanceof OAuthError ? { errorCode: error.code } : {}),
        occurredAt,
      });
    } catch (auditError) {
      if (outcome === "accepted") {
        throw auditError;
      }
    }
  }

  private async verifyOwnTokenForRevocation(
    token: string,
  ): Promise<{ jti: string; sub: string; aud: string } | undefined> {
    const parts = token.split(".");
    if (parts.length !== 3 || !parts[1]) {
      return undefined;
    }
    let payload: UnverifiedJwtPayload;
    try {
      payload = decodeJson<UnverifiedJwtPayload>(parts[1]);
    } catch {
      return undefined;
    }
    const audience = audienceFromPayload(payload.aud);
    const resource = audience ? this.configuredResource(audience) : undefined;
    if (payload.iss !== this.issuer || !resource) {
      return undefined;
    }
    try {
      const verified = await verifyJwt(token, {
        keyResolver: this.ownVerificationKeys,
        expectedIssuer: this.issuer,
        expectedAudience: resource,
        clock: this.clock,
      });
      return { jti: verified.claims.jti, sub: verified.claims.sub, aud: resource };
    } catch {
      return undefined;
    }
  }

  private async signSecurityEvent(
    event: { id: string; tokenId: string; subject: string; occurredAt: number },
    subscriber: EventSubscriber,
    deliveryId: string,
    deliveredAt: number,
  ): Promise<string> {
    const claims: SecurityEventClaims = {
      iss: this.issuer,
      aud: subscriber.url,
      sub: event.subject,
      jti: deliveryId,
      iat: integerSeconds(deliveredAt),
      exp: integerSeconds(deliveredAt) + 300,
      events: { [TOKEN_REVOKED_EVENT]: {} },
      sid: event.tokenId,
    };
    return signJwt(claims, this.options.signingKey);
  }
}

export async function createService(
  options: ServiceOptions,
  dependencies: Dependencies,
): Promise<AgentAuthService> {
  return AgentAuthService.create(options, dependencies);
}

export type { VerificationKeyResolver };
