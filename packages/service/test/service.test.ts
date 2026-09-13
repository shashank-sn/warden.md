import { describe, expect, it } from "vitest";

import { parseAuthMd, validateAuthMdDocument } from "../../cli/src/authmd.js";
import {
  validateAuthorizationServerMetadata,
  validateProtectedResourceMetadata,
} from "../../cli/src/metadata.js";
import {
  type AgentAuthService,
  CLAIM_GRANT,
  ClaimCeremonyDurableObject,
  type ClaimRecord,
  type Clock,
  createEs256SigningKey,
  createRouter,
  createService,
  createStaticVerificationKeys,
  createWorker,
  createWorkerService,
  type D1Database,
  type D1PreparedStatement,
  DurableObjectClaimState,
  type DurableObjectState,
  type DurableObjectStorage,
  EventDeliveryDurableObject,
  encodeJson,
  type IdentifierGenerator,
  InMemoryServiceStore,
  JWT_BEARER_GRANT,
  OAuthError,
  type ServiceOptions,
  SharedSecretServiceAuthenticator,
  type SigningKey,
  sha256,
  signJwt,
  TOKEN_REVOKED_EVENT,
  verifyJwt,
  type WorkerEnvironment,
} from "../src/index.js";

class TestClock implements Clock {
  public constructor(private value = Date.UTC(2026, 0, 1, 0, 0, 0)) {}

  public now(): number {
    return this.value;
  }

  public advance(milliseconds: number): void {
    this.value += milliseconds;
  }
}

class SequenceIdentifiers implements IdentifierGenerator {
  private count = 0;

  public next(prefix: string): string {
    this.count += 1;
    return `${prefix}_${this.count.toString().padStart(12, "0")}`;
  }
}

class FakeDurableObjectStorage implements DurableObjectStorage {
  private readonly values = new Map<string, unknown>();
  public readonly alarms: (number | Date)[] = [];
  public deleteAlarmCalls = 0;

  public async get<T>(key: string): Promise<T | undefined> {
    const value = this.values.get(key);
    return value === undefined ? undefined : (structuredClone(value) as T);
  }

  public put<T>(key: string, value: T): Promise<void>;
  public put(entries: Readonly<Record<string, unknown>>): Promise<void>;
  public async put<T>(
    keyOrEntries: string | Readonly<Record<string, unknown>>,
    value?: T,
  ): Promise<void> {
    if (typeof keyOrEntries === "string") {
      this.values.set(keyOrEntries, structuredClone(value));
      return;
    }
    for (const [key, entry] of Object.entries(keyOrEntries)) {
      this.values.set(key, structuredClone(entry));
    }
  }

  public async delete(keyOrKeys: string | readonly string[]): Promise<void> {
    for (const key of typeof keyOrKeys === "string" ? [keyOrKeys] : keyOrKeys) {
      this.values.delete(key);
    }
  }

  public async setAlarm(scheduledTime: number | Date): Promise<void> {
    this.alarms.push(scheduledTime);
  }

  public async deleteAlarm(): Promise<void> {
    this.deleteAlarmCalls += 1;
  }
}

class FakeDurableObjectState implements DurableObjectState {
  public readonly storage = new FakeDurableObjectStorage();

  public blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
    return callback();
  }
}

class ClaimRouteDatabase implements D1Database {
  public readonly queries: string[] = [];

  public constructor(private readonly registrations: ReadonlyMap<string, string>) {}

  public prepare(query: string): D1PreparedStatement {
    this.queries.push(query);
    const registrations = this.registrations;
    let values: readonly unknown[] = [];
    const statement: D1PreparedStatement = {
      bind(...nextValues: readonly unknown[]): D1PreparedStatement {
        values = nextValues;
        return statement;
      },
      async first<T>(): Promise<T | null> {
        const routeType = query.includes("device_code_hash")
          ? "device"
          : query.includes("user_code_hash")
            ? "user"
            : "claim";
        const registration = registrations.get(`${routeType}:${String(values[0])}`);
        return registration ? ({ identity_id: registration } as T) : null;
      },
      async all<T>(): Promise<{ results: readonly T[] }> {
        return { results: [] };
      },
      async run(): Promise<{ success: boolean; meta?: { changes?: number } }> {
        return { success: true };
      },
    };
    return statement;
  }
}

interface Fixture {
  clock: TestClock;
  signingKey: SigningKey;
  store: InMemoryServiceStore;
  service: AgentAuthService;
  serviceSecret: string;
}

async function fixture(
  overrides: Partial<
    Pick<ServiceOptions, "anonymous" | "claim" | "token" | "protectedResources">
  > = {},
): Promise<Fixture> {
  const clock = new TestClock();
  const signingKey = await createEs256SigningKey("test-es256-1");
  const verifier = await createStaticVerificationKeys("https://service.test", signingKey);
  const store = new InMemoryServiceStore();
  const serviceSecret = crypto.randomUUID();
  const service = await createService(
    {
      issuer: "https://service.test",
      defaultResource: "https://service.test",
      supportedScopes: ["agent:read", "agent:write"],
      signingKey,
      verificationKeys: verifier,
      trustedAssertionIssuer: "https://service.test",
      ...overrides,
    },
    {
      store,
      clock,
      identifiers: new SequenceIdentifiers(),
      authenticator: new SharedSecretServiceAuthenticator(serviceSecret, {
        subject: "service-subject",
        scopes: ["agent:read"],
      }),
    },
  );
  return { clock, signingKey, store, service, serviceSecret };
}

async function approvedClaim(
  service: AgentAuthService,
): Promise<{ claimGrant: string; identityId: string }> {
  const registered = await service.registerIdentity({
    identityType: "anonymous",
    scope: "agent:read agent:write",
    rateLimitKey: "agent-a",
  });
  const started = await service.startClaim({
    identityId: registered.identity.id,
    rateLimitKey: "agent-a",
  });
  const verified = await service.verifyClaimCode(started.userCode);
  await service.decideClaim(verified.id, "approved");
  const polled = await service.pollClaim(started.deviceCode);
  if (!polled.claimGrant) {
    throw new Error("test fixture did not issue a claim grant");
  }
  return { claimGrant: polled.claimGrant, identityId: registered.identity.id };
}

describe("auth.md service discovery and registration", () => {
  it("serves standards-shaped discovery, a private-key-free JWKS, and stable envelopes", async () => {
    const { service } = await fixture();
    const router = createRouter(service);

    const authMd = await router.fetch(new Request("https://service.test/auth.md"));
    const metadata = await router.fetch(
      new Request("https://service.test/.well-known/oauth-authorization-server"),
    );
    const jwks = await router.fetch(new Request("https://service.test/.well-known/jwks.json"));
    const invalid = await router.fetch(new Request("https://service.test/does-not-exist"));

    expect(authMd.status).toBe(200);
    expect(await authMd.text()).toContain("## Claim ceremony");
    expect(await metadata.json()).toMatchObject({
      issuer: "https://service.test",
      token_endpoint: "https://service.test/oauth2/token",
      agent_auth: {
        skill: "https://service.test/auth.md",
        claim_endpoint: "https://service.test/agent/identity/claim",
        claim_complete_endpoint: "https://service.test/agent/identity/claim/complete",
        identity_types_supported: ["anonymous", "service_auth", "identity_assertion"],
      },
    });
    expect(JSON.stringify(await jwks.json())).not.toContain('"d"');
    expect(await invalid.json()).toEqual({ error: "invalid_request" });
  });

  it("passes the repository's read-only auth.md conformance validators", async () => {
    const { service } = await fixture();
    const document = parseAuthMd("https://service.test/auth.md", service.authMd());
    const resourceMetadata = service.protectedResourceMetadata();
    const authorizationMetadata = service.authorizationServerMetadata();

    expect(validateAuthMdDocument(document)).toEqual([]);
    expect(validateProtectedResourceMetadata(resourceMetadata, "https://service.test/")).toEqual(
      [],
    );
    expect(
      validateAuthorizationServerMetadata(authorizationMetadata, {
        authDocument: document,
        protectedResourceMetadata: resourceMetadata,
      }),
    ).toEqual([]);
  });

  it("limits and expires anonymous identities, and validates service_auth", async () => {
    const { clock, service, serviceSecret } = await fixture({
      anonymous: { expiresInSeconds: 1, maxRegistrationsPerWindow: 1 },
    });
    const anonymous = await service.registerIdentity({
      identityType: "anonymous",
      scope: "agent:read",
      rateLimitKey: "same-ip",
    });
    await expect(
      service.registerIdentity({ identityType: "anonymous", rateLimitKey: "same-ip" }),
    ).rejects.toMatchObject({ code: "temporarily_unavailable" });
    const serviceIdentity = await service.registerIdentity({
      identityType: "service_auth",
      serviceToken: serviceSecret,
      rateLimitKey: "service",
    });
    expect(serviceIdentity.identity.subject).toBe("service-subject");
    await expect(
      service.registerIdentity({
        identityType: "service_auth",
        serviceToken: "incorrect",
        rateLimitKey: "service",
      }),
    ).rejects.toMatchObject({ code: "invalid_client" });

    clock.advance(1_001);
    await expect(
      service.startClaim({ identityId: anonymous.identity.id, rateLimitKey: "same-ip" }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("registers a signed identity assertion exactly once", async () => {
    const { clock, signingKey, service } = await fixture();
    const now = Math.floor(clock.now() / 1000);
    const assertion = await signJwt(
      {
        iss: "https://service.test",
        sub: "asserted-subject",
        aud: service.identityEndpoint,
        iat: now,
        exp: now + 60,
        jti: "identity-registration-1",
        scope: "agent:read",
        client_id: "agent-client",
      },
      signingKey,
    );

    const registered = await service.registerIdentity({
      identityType: "identity_assertion",
      assertion,
      clientId: "agent-client",
      rateLimitKey: "agent",
    });

    expect(registered.identity).toMatchObject({
      type: "identity_assertion",
      subject: "asserted-subject",
      scopes: ["agent:read"],
    });
    await expect(
      service.registerIdentity({
        identityType: "identity_assertion",
        assertion,
        clientId: "agent-client",
        rateLimitKey: "agent",
      }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("only permits configured protected-resource audiences and records safe registration outcomes", async () => {
    const { service, store } = await fixture({
      protectedResources: ["https://service.test", "https://records.service.test/api"],
    });
    await expect(
      service.registerIdentity({
        identityType: "anonymous",
        resource: "https://unrelated.example.test",
        rateLimitKey: "agent-a",
      }),
    ).rejects.toMatchObject({ code: "invalid_target" });
    const accepted = await service.registerIdentity({
      identityType: "anonymous",
      resource: "https://records.service.test/api/",
      rateLimitKey: "agent-b",
    });

    expect(accepted.identity.resource).toBe("https://records.service.test/api");
    expect(await store.listIdentityAttempts()).toEqual([
      expect.objectContaining({ outcome: "rejected", errorCode: "invalid_target" }),
      expect.objectContaining({ outcome: "accepted", identityType: "anonymous" }),
    ]);
  });

  it("serves the canonical identity-claim, token, and revocation routes", async () => {
    const { service } = await fixture();
    const router = createRouter(service);
    const identityResponse = await router.fetch(
      new Request("https://service.test/agent/identity", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identity_type: "anonymous", scope: "agent:read" }),
      }),
    );
    const identity = (await identityResponse.json()) as { identity_id: string };
    const claimResponse = await router.fetch(
      new Request("https://service.test/agent/identity/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identity_id: identity.identity_id }),
      }),
    );
    const claim = (await claimResponse.json()) as { device_code: string; user_code: string };
    const verifiedResponse = await router.fetch(
      new Request("https://service.test/agent/identity/claim/complete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "verify", user_code: claim.user_code }),
      }),
    );
    const verified = (await verifiedResponse.json()) as { claim_id: string };
    const approvedResponse = await router.fetch(
      new Request("https://service.test/agent/identity/claim/complete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "approve", claim_id: verified.claim_id }),
      }),
    );
    expect(approvedResponse.status).toBe(200);
    const pollResponse = await router.fetch(
      new Request("https://service.test/agent/identity/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_code: claim.device_code }),
      }),
    );
    const polled = (await pollResponse.json()) as { claim_grant: string };
    const tokenResponse = await router.fetch(
      new Request("https://service.test/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: CLAIM_GRANT, claim_grant: polled.claim_grant }),
      }),
    );
    const token = (await tokenResponse.json()) as { access_token: string };
    const revokeResponse = await router.fetch(
      new Request("https://service.test/oauth2/revoke", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token: token.access_token }),
      }),
    );

    expect(tokenResponse.status).toBe(200);
    expect(revokeResponse.status).toBe(200);
  });
});

describe("claim ceremony", () => {
  it("enforces the pending to verified to approved state machine and slow polling", async () => {
    const { clock, service } = await fixture();
    const registered = await service.registerIdentity({
      identityType: "anonymous",
      rateLimitKey: "agent-a",
    });
    const started = await service.startClaim({
      identityId: registered.identity.id,
      rateLimitKey: "agent-a",
    });

    await expect(service.pollClaim(started.deviceCode)).resolves.toMatchObject({
      status: "pending",
    });
    await expect(service.pollClaim(started.deviceCode)).rejects.toMatchObject({
      code: "slow_down",
    });

    const verified = await service.verifyClaimCode(started.userCode);
    expect(verified.status).toBe("user_verified");
    await expect(service.verifyClaimCode(started.userCode)).rejects.toMatchObject({
      code: "invalid_grant",
    });
    const approved = await service.decideClaim(verified.id, "approved");
    expect(approved.status).toBe("approved");

    clock.advance(10_000);
    await expect(service.pollClaim(started.deviceCode)).resolves.toMatchObject({
      status: "approved",
      claimGrant: expect.any(String),
    });
  });

  it("returns the RFC 8628 expiry code and rate limits claim starts", async () => {
    const { clock, service } = await fixture({
      claim: { expiresInSeconds: 1, maxStartsPerWindow: 1 },
    });
    const registered = await service.registerIdentity({
      identityType: "anonymous",
      rateLimitKey: "agent-a",
    });
    const started = await service.startClaim({
      identityId: registered.identity.id,
      rateLimitKey: "agent-a",
    });
    await expect(
      service.startClaim({ identityId: registered.identity.id, rateLimitKey: "agent-a" }),
    ).rejects.toMatchObject({ code: "temporarily_unavailable" });

    clock.advance(1_001);
    await expect(service.pollClaim(started.deviceCode)).rejects.toMatchObject({
      code: "expired_token",
    });
  });

  it("denies a completed claim and bounds user-code guessing attempts", async () => {
    const { service } = await fixture({ claim: { maxVerificationAttempts: 1 } });
    const registered = await service.registerIdentity({
      identityType: "anonymous",
      rateLimitKey: "agent-a",
    });
    const denied = await service.startClaim({
      identityId: registered.identity.id,
      rateLimitKey: "agent-a",
    });
    const verified = await service.verifyClaimCode(denied.userCode, "approver");
    await service.decideClaim(verified.id, "denied");
    await expect(service.pollClaim(denied.deviceCode)).rejects.toMatchObject({
      code: "access_denied",
    });

    const guessed = await service.startClaim({
      identityId: registered.identity.id,
      rateLimitKey: "agent-b",
    });
    await expect(service.verifyClaimCode(crypto.randomUUID(), "guesser")).rejects.toMatchObject({
      code: "invalid_grant",
    });
    await expect(service.verifyClaimCode(guessed.userCode, "guesser")).rejects.toMatchObject({
      code: "access_denied",
    });
  });
});

describe("Durable Object claim state", () => {
  it("indexes a claim in fake Durable Object storage and enforces versions", async () => {
    const state = new FakeDurableObjectState();
    const claims = new DurableObjectClaimState(state);
    const initial: ClaimRecord = {
      id: "claim_1",
      identityId: "identity_1",
      userCodeHash: "user-code-hash",
      deviceCodeHash: "device-code-hash",
      status: "pending",
      scopes: ["agent:read"],
      resource: "https://service.test",
      createdAt: 1,
      expiresAt: 2,
      intervalSeconds: 5,
      verificationAttempts: 0,
      version: 1,
    };

    await claims.createClaim(initial);
    expect(state.storage.alarms).toEqual([initial.expiresAt]);
    expect(await claims.findByUserCodeHash(initial.userCodeHash)).toEqual(initial);
    expect(await claims.findByDeviceCodeHash(initial.deviceCodeHash)).toEqual(initial);
    await expect(claims.createClaim({ ...initial, id: "claim_2" })).rejects.toThrow(
      "conflicts with existing state",
    );

    const verified = {
      ...initial,
      status: "user_verified" as const,
      userCodeUsedAt: 1,
      verificationAttempts: 1,
      version: 2,
    };
    expect(await claims.compareAndSet(initial, verified)).toBe(true);
    expect(await claims.compareAndSet(initial, verified)).toBe(false);
    expect(await claims.findClaimById(initial.id)).toEqual(verified);
    expect(await claims.removeExpiredClaims(initial.expiresAt)).toBe(1);
    expect(await claims.findClaimById(initial.id)).toBeUndefined();
    expect(state.storage.deleteAlarmCalls).toBe(1);
  });

  it("removes expired hash-only claim routes from the claim Durable Object alarm", async () => {
    const database = new ClaimRouteDatabase(new Map());
    const namespace = {
      idFromName() {
        return {};
      },
      get() {
        throw new Error("claim route cleanup does not fetch another Durable Object");
      },
    };
    const ceremony = new ClaimCeremonyDurableObject(new FakeDurableObjectState(), {
      DB: database,
      CLAIM_CEREMONY: namespace,
      EVENT_DELIVERY: namespace,
      SERVICE_SIGNING_JWK: "{}",
    });

    await ceremony.alarm();

    expect(database.queries).toContain("DELETE FROM claim_routes WHERE expires_at <= ?");
  });

  it("routes each registration and claim grant through its own claim Durable Object", async () => {
    const names: string[] = [];
    const forwarded: Request[] = [];
    const routes = new Map<string, string>([
      [`device:${await sha256("device-for-identity-b")}`, "identity_b"],
      [`user:${await sha256("user-for-identity-a")}`, "identity_a"],
      ["claim:claim-for-identity-b", "identity_b"],
    ]);
    const environment: WorkerEnvironment = {
      DB: new ClaimRouteDatabase(routes),
      CLAIM_CEREMONY: {
        idFromName(name: string) {
          names.push(name);
          return {};
        },
        get() {
          return {
            async fetch(request: Request): Promise<Response> {
              forwarded.push(request);
              return new Response(JSON.stringify({ delegated: true }), {
                headers: { "content-type": "application/json" },
              });
            },
          };
        },
      },
      EVENT_DELIVERY: {
        idFromName() {
          throw new Error("event delivery must not run during claim routing");
        },
        get() {
          throw new Error("event delivery must not run during claim routing");
        },
      },
      SERVICE_SIGNING_JWK: "{}",
    };
    const worker = createWorker();
    const first = await worker.fetch(
      new Request("https://service.test/agent/identity/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identity_id: "identity_a" }),
      }),
      environment,
      { waitUntil: () => undefined },
    );
    const second = await worker.fetch(
      new Request("https://service.test/agent/identity/claim", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ identity_id: "identity_b" }),
      }),
      environment,
      { waitUntil: () => undefined },
    );
    const poll = await worker.fetch(
      new Request("https://service.test/agent/identity/claim/poll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ device_code: "device-for-identity-b" }),
      }),
      environment,
      { waitUntil: () => undefined },
    );
    const verify = await worker.fetch(
      new Request("https://service.test/agent/identity/claim/complete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "verify", user_code: "user-for-identity-a" }),
      }),
      environment,
      { waitUntil: () => undefined },
    );
    const approve = await worker.fetch(
      new Request("https://service.test/agent/identity/claim/complete", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "approve", claim_id: "claim-for-identity-b" }),
      }),
      environment,
      { waitUntil: () => undefined },
    );
    const mismatchedIdentity = await worker.fetch(
      new Request("https://service.test/agent/identity/claim/poll", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          identity_id: "identity_a",
          device_code: "device-for-identity-b",
        }),
      }),
      environment,
      { waitUntil: () => undefined },
    );
    const grant = `${encodeJson({ alg: "ES256", kid: "test" })}.${encodeJson({
      identity_id: "identity_b",
    })}.ignored`;
    const token = await worker.fetch(
      new Request("https://service.test/oauth2/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: CLAIM_GRANT, claim_grant: grant }),
      }),
      environment,
      { waitUntil: () => undefined },
    );

    expect(await first.json()).toEqual({ delegated: true });
    expect(await second.json()).toEqual({ delegated: true });
    expect(await poll.json()).toEqual({ delegated: true });
    expect(await verify.json()).toEqual({ delegated: true });
    expect(await approve.json()).toEqual({ delegated: true });
    expect(await token.json()).toEqual({ delegated: true });
    expect(mismatchedIdentity.status).toBe(400);
    expect(await mismatchedIdentity.json()).toEqual({ error: "invalid_grant" });
    expect(names).toEqual([
      "registration:identity_a",
      "registration:identity_b",
      "registration:identity_b",
      "registration:identity_a",
      "registration:identity_b",
      "registration:identity_b",
    ]);
    expect(forwarded).toHaveLength(6);
    expect(forwarded[0]?.headers.get("x-warden-issuer")).toBe("https://service.test");
    expect(forwarded[1]?.headers.get("x-warden-registration-id")).toBe("identity_b");
    expect(forwarded[2]?.headers.get("x-warden-registration-id")).toBe("identity_b");
    expect(forwarded[3]?.headers.get("x-warden-registration-id")).toBe("identity_a");
  });
});

describe("token narrowing and adversarial JWTs", () => {
  it("mints only narrowed claim tokens and consumes each grant once", async () => {
    const { service } = await fixture();
    const { claimGrant } = await approvedClaim(service);

    const token = await service.exchangeToken({
      grantType: CLAIM_GRANT,
      claimGrant,
      scope: "agent:read",
      resource: "https://service.test",
    });
    expect(token).toMatchObject({ tokenType: "Bearer", scope: "agent:read" });
    await expect(
      service.exchangeToken({ grantType: CLAIM_GRANT, claimGrant }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("rejects upscoping and an unrelated resource before it creates a token", async () => {
    const { service } = await fixture();
    const { claimGrant } = await approvedClaim(service);
    await expect(
      service.exchangeToken({
        grantType: CLAIM_GRANT,
        claimGrant,
        scope: "agent:admin",
      }),
    ).rejects.toMatchObject({ code: "invalid_scope" });

    const next = await approvedClaim(service);
    await expect(
      service.exchangeToken({
        grantType: CLAIM_GRANT,
        claimGrant: next.claimGrant,
        resource: "https://other.example.test",
      }),
    ).rejects.toMatchObject({ code: "invalid_target" });
  });

  it("verifies JWT bearer assertions and rejects expiry, audience, issuer, replay, and alg none", async () => {
    const { clock, signingKey, service, store } = await fixture();
    const now = Math.floor(clock.now() / 1000);
    const base = {
      iss: "https://service.test",
      sub: "asserted-subject",
      aud: service.identityEndpoint,
      iat: now,
      exp: now + 60,
      jti: "registration",
      client_id: "asserted-client",
    };
    const registration = await signJwt(base, signingKey);
    const registered = await service.registerIdentity({
      identityType: "identity_assertion",
      assertion: registration,
      clientId: "asserted-client",
      rateLimitKey: "agent",
    });
    const bearer = await signJwt(
      {
        ...base,
        aud: service.tokenEndpoint,
        jti: "bearer-1",
        scope: "agent:read",
        identity_id: registered.identity.id,
      },
      signingKey,
    );
    await expect(
      service.exchangeToken({
        grantType: JWT_BEARER_GRANT,
        assertion: bearer,
        clientId: "asserted-client",
      }),
    ).resolves.toMatchObject({ scope: "agent:read" });
    await expect(
      service.exchangeToken({
        grantType: JWT_BEARER_GRANT,
        assertion: bearer,
        clientId: "asserted-client",
      }),
    ).rejects.toMatchObject({ code: "invalid_grant" });

    const verifier = await createStaticVerificationKeys("https://service.test", signingKey);
    const verification = {
      keyResolver: verifier,
      expectedIssuer: "https://service.test",
      expectedAudience: service.tokenEndpoint,
      clock,
      replayRepository: store,
    };
    const expired = await signJwt(
      { ...base, aud: service.tokenEndpoint, jti: "expired", exp: now - 1 },
      signingKey,
    );
    const wrongAudience = await signJwt(
      { ...base, aud: "https://other.example.test", jti: "wrong-audience" },
      signingKey,
    );
    const wrongIssuer = await signJwt(
      {
        ...base,
        iss: "https://evil.example.test",
        aud: service.tokenEndpoint,
        jti: "wrong-issuer",
      },
      signingKey,
    );
    const algNone = `${encodeJson({ alg: "none", kid: "test-es256-1" })}.${encodeJson({
      ...base,
      aud: service.tokenEndpoint,
      jti: "alg-none",
    })}.ignored`;

    await expect(verifyJwt(expired, verification)).rejects.toMatchObject({ code: "invalid_grant" });
    await expect(verifyJwt(wrongAudience, verification)).rejects.toMatchObject({
      code: "invalid_grant",
    });
    await expect(verifyJwt(wrongIssuer, verification)).rejects.toMatchObject({
      code: "invalid_grant",
    });
    await expect(verifyJwt(algNone, verification)).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("binds a JWT bearer exchange to the originating asserted registration, client, and subject", async () => {
    const { clock, signingKey, service } = await fixture();
    const now = Math.floor(clock.now() / 1000);
    const register = async (clientId: string, jti: string) => {
      const assertion = await signJwt(
        {
          iss: "https://service.test",
          sub: "shared-subject",
          aud: service.identityEndpoint,
          iat: now,
          exp: now + 60,
          jti,
          client_id: clientId,
          scope: "agent:read",
        },
        signingKey,
      );
      return service.registerIdentity({
        identityType: "identity_assertion",
        assertion,
        clientId,
        rateLimitKey: clientId,
      });
    };
    const first = await register("client-a", "registration-a");
    const second = await register("client-b", "registration-b");
    const bearer = async (
      jti: string,
      identityId: string,
      clientId: string,
      subject = "shared-subject",
    ) =>
      signJwt(
        {
          iss: "https://service.test",
          sub: subject,
          aud: service.tokenEndpoint,
          iat: now,
          exp: now + 60,
          jti,
          client_id: clientId,
          identity_id: identityId,
          scope: "agent:read",
        },
        signingKey,
      );

    await expect(
      service.exchangeToken({
        grantType: JWT_BEARER_GRANT,
        assertion: await bearer("bearer-a", first.identity.id, "client-a"),
        clientId: "client-a",
      }),
    ).resolves.toMatchObject({ scope: "agent:read" });
    await expect(
      service.exchangeToken({
        grantType: JWT_BEARER_GRANT,
        assertion: await bearer("wrong-client", first.identity.id, "client-a"),
        clientId: "client-b",
      }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
    await expect(
      service.exchangeToken({
        grantType: JWT_BEARER_GRANT,
        assertion: await bearer("wrong-registration", second.identity.id, "client-a"),
        clientId: "client-a",
      }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
    await expect(
      service.exchangeToken({
        grantType: JWT_BEARER_GRANT,
        assertion: await bearer("wrong-subject", first.identity.id, "client-a", "other-subject"),
        clientId: "client-a",
      }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("validates persisted token state and accepts retired public signing keys during rotation", async () => {
    const clock = new TestClock();
    const active = await createEs256SigningKey("active-key");
    const retired = await createEs256SigningKey("retired-key");
    const service = await createService(
      {
        issuer: "https://service.test",
        defaultResource: "https://service.test",
        supportedScopes: ["agent:read"],
        signingKey: active,
        retiredSigningKeys: [retired.publicJwk],
        verificationKeys: await createStaticVerificationKeys("https://service.test", active),
        trustedAssertionIssuer: "https://service.test",
      },
      { store: new InMemoryServiceStore(), clock },
    );
    const now = Math.floor(clock.now() / 1000);
    const rotatedToken = await signJwt(
      {
        iss: "https://service.test",
        sub: "subject",
        aud: "https://service.test",
        iat: now,
        exp: now + 60,
        jti: "retired-token",
        identity_id: "identity",
        scope: "agent:read",
      },
      retired,
    );
    const store = new InMemoryServiceStore();
    const validatingService = await createService(
      {
        issuer: "https://service.test",
        defaultResource: "https://service.test",
        supportedScopes: ["agent:read"],
        signingKey: active,
        retiredSigningKeys: [retired.publicJwk],
        verificationKeys: await createStaticVerificationKeys("https://service.test", active),
        trustedAssertionIssuer: "https://service.test",
      },
      { store, clock },
    );
    await store.createToken({
      id: "retired-token",
      identityId: "identity",
      subject: "subject",
      scopes: ["agent:read"],
      resource: "https://service.test",
      issuedAt: now * 1000,
      expiresAt: (now + 60) * 1000,
    });

    expect(validatingService.publicJwks().keys.map((key) => key.kid)).toEqual([
      "active-key",
      "retired-key",
    ]);
    await expect(validatingService.validateAccessToken(rotatedToken)).resolves.toMatchObject({
      id: "retired-token",
    });
    await validatingService.revoke(rotatedToken);
    await expect(validatingService.validateAccessToken(rotatedToken)).rejects.toMatchObject({
      code: "invalid_token",
    });
    expect(service.publicJwks().keys.map((key) => key.kid)).toEqual(["active-key", "retired-key"]);
  });

  it("uses the active private JWK kid during Worker rotation and rejects conflicting fallback configuration", async () => {
    const active = await createEs256SigningKey("active-key");
    const retired = await createEs256SigningKey("retired-key");
    const privateJwk = {
      ...(await crypto.subtle.exportKey("jwk", active.privateKey)),
      kid: active.kid,
    };
    const namespace = {
      idFromName() {
        return {};
      },
      get() {
        throw new Error("claim namespace is not used while initializing keys");
      },
    };
    const environment: WorkerEnvironment = {
      DB: new ClaimRouteDatabase(new Map()),
      CLAIM_CEREMONY: namespace,
      EVENT_DELIVERY: namespace,
      SERVICE_SIGNING_JWK: JSON.stringify(privateJwk),
      SERVICE_RETIRED_JWKS: JSON.stringify({ keys: [retired.publicJwk] }),
    };

    const service = await createWorkerService(environment, "https://service.test");
    expect(service.publicJwks().keys.map((key) => key.kid)).toEqual(["active-key", "retired-key"]);
    await expect(
      createWorkerService(
        { ...environment, SERVICE_SIGNING_KID: "unexpected-key" },
        "https://service.test",
      ),
    ).rejects.toThrow("SERVICE_SIGNING_KID must match");
  });
});

describe("revocation and security event delivery", () => {
  it("is idempotent, retries delivery with an idempotency key, and rejects SET replays", async () => {
    const { clock, signingKey, service, store, serviceSecret } = await fixture();
    const { claimGrant } = await approvedClaim(service);
    const token = await service.exchangeToken({ grantType: CLAIM_GRANT, claimGrant });
    await service.subscribe("https://subscriber.example.test/events", serviceSecret);

    await service.revoke(token.accessToken);
    await service.revoke(token.accessToken);
    let calls = 0;
    const first = await service.deliverDueEvents(async (_url, init) => {
      calls += 1;
      expect(init?.headers).toMatchObject({ "idempotency-key": expect.any(String) });
      return new Response("not yet", { status: 503 });
    });
    expect(first[0]).toMatchObject({ status: "pending", attempts: 1 });
    clock.advance(2_000);
    const second = await service.deliverDueEvents(async () => {
      calls += 1;
      return new Response(null, { status: 202, headers: { "x-request-id": "receipt-1" } });
    });
    expect(second[0]).toMatchObject({ status: "delivered", attempts: 2, receipt: "receipt-1" });
    expect(calls).toBe(2);

    const now = Math.floor(clock.now() / 1000);
    const event = await signJwt(
      {
        iss: "https://service.test",
        sub: "subject",
        aud: service.eventEndpoint,
        iat: now,
        exp: now + 60,
        jti: "set-1",
        events: { [TOKEN_REVOKED_EVENT]: {} },
      },
      signingKey,
    );
    await expect(service.receiveSecurityEvent(event)).resolves.toEqual({ replayed: false });
    await expect(service.receiveSecurityEvent(event)).rejects.toMatchObject({
      code: "invalid_grant",
    });

    const serializedStore = JSON.stringify(store);
    expect(serializedStore).not.toContain(serviceSecret);
    expect(serializedStore).not.toContain(token.accessToken);
  });

  it("retries failed event delivery from a Durable Object alarm without another revoke request", async () => {
    const { clock, service, serviceSecret } = await fixture();
    const { claimGrant } = await approvedClaim(service);
    const token = await service.exchangeToken({ grantType: CLAIM_GRANT, claimGrant });
    await service.subscribe("https://subscriber.example.test/events", serviceSecret);
    await service.revoke(token.accessToken);

    const state = new FakeDurableObjectState();
    let attempts = 0;
    const delivery = new EventDeliveryDurableObject(
      state,
      {} as WorkerEnvironment,
      async () => service,
      async () => {
        attempts += 1;
        return attempts === 1
          ? new Response(null, { status: 503 })
          : new Response(null, { status: 202 });
      },
    );
    const scheduled = await delivery.fetch(
      new Request("https://event-delivery.internal/__warden/internal/event-delivery/schedule", {
        method: "POST",
        headers: { "x-warden-issuer": "https://service.test" },
      }),
    );

    expect(scheduled.status).toBe(204);
    expect(attempts).toBe(1);
    expect(state.storage.alarms.at(-1)).toBe(clock.now() + 2_000);
    clock.advance(2_000);
    await delivery.alarm();
    expect(attempts).toBe(2);
    expect(state.storage.deleteAlarmCalls).toBe(1);
  });
});

describe("stable error type", () => {
  it("only exposes the OAuth code at the boundary", () => {
    const error = new OAuthError("invalid_scope");
    expect({ error: error.code, status: error.status }).toEqual({
      error: "invalid_scope",
      status: 400,
    });
  });
});
