import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { Es256CapabilitySigner } from "../src/crypto.js";
import type {
  DurableObjectId,
  DurableObjectNamespace,
  DurableObjectState,
  DurableObjectStorage,
  DurableObjectStub,
} from "../src/durable-object.js";
import type {
  BrokerD1Database,
  BrokerD1PreparedStatement,
  BrokerRuntimeEnvironment,
  ServiceBinding,
} from "../src/runtime.js";
import worker, { BrokerCoordinatorDurableObject, GrantExpiryDurableObject } from "../src/worker.js";

class FakeStorage implements DurableObjectStorage {
  public readonly values = new Map<string, unknown>();
  public readonly alarms: (number | Date)[] = [];

  public async get<T>(key: string): Promise<T | undefined> {
    return this.values.get(key) as T | undefined;
  }

  public async put<T>(key: string, value: T): Promise<void> {
    this.values.set(key, value);
  }

  public async setAlarm(scheduledTime: number | Date): Promise<void> {
    this.alarms.push(scheduledTime);
  }
}

class FakeState implements DurableObjectState {
  public readonly storage = new FakeStorage();
}

class FakeNamespace implements DurableObjectNamespace {
  private readonly stubs = new Map<string, DurableObjectStub>();

  public constructor(private readonly create?: (name: string) => DurableObjectStub) {}

  public idFromName(name: string): DurableObjectId {
    return { name };
  }

  public get(id: DurableObjectId): DurableObjectStub {
    const name = id.name;
    if (!name) {
      throw new Error("test durable object has no name");
    }
    let stub = this.stubs.get(name);
    if (!stub && this.create) {
      stub = this.create(name);
      this.stubs.set(name, stub);
    }
    if (!stub) {
      throw new Error(`missing durable object ${name}`);
    }
    return stub;
  }

  public set(name: string, stub: DurableObjectStub): void {
    this.stubs.set(name, stub);
  }
}

type LedgerCall = {
  query: string;
  values: readonly unknown[];
};

class FakeStatement implements BrokerD1PreparedStatement {
  private values: readonly unknown[] = [];

  public constructor(
    private readonly query: string,
    private readonly calls: LedgerCall[],
  ) {}

  public bind(...values: readonly unknown[]): BrokerD1PreparedStatement {
    this.values = values;
    return this;
  }

  public async run(): Promise<unknown> {
    this.calls.push({ query: this.query, values: this.values });
    return { success: true };
  }
}

class FakeLedger implements BrokerD1Database {
  public readonly calls: LedgerCall[] = [];

  public prepare(query: string): BrokerD1PreparedStatement {
    return new FakeStatement(query, this.calls);
  }
}

function authorityBinding(): ServiceBinding {
  return {
    async fetch(request: Request): Promise<Response> {
      const body = (await request.json()) as {
        agentId: string;
        subjectId: string;
        subjectTokenId: string;
      };
      return Response.json({
        agentId: body.agentId,
        subjectId: body.subjectId,
        subjectTokenId: body.subjectTokenId,
        registrationScopes: ["records:write"],
        subjectScopes: ["records:write"],
        resources: ["https://resource.example.test"],
      });
    },
  };
}

function approvalBinding(): ServiceBinding {
  return {
    async fetch(): Promise<Response> {
      return Response.json({ approver: "person-a" });
    },
  };
}

function operatorBinding(): ServiceBinding {
  return {
    async fetch(): Promise<Response> {
      return Response.json({ operator: "operator-a" });
    },
  };
}

async function privateJwk(): Promise<string> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  return JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey));
}

async function runtimeHarness(
  options: {
    authority?: ServiceBinding;
    approval?: ServiceBinding;
    operator?: ServiceBinding;
    ledger?: BrokerD1Database;
    policy?: string;
    revocationTargets?: string;
    revocation?: ServiceBinding;
    scheduleFailure?: boolean;
  } = {},
): Promise<{
  environment: BrokerRuntimeEnvironment;
  coordinatorNamespace: FakeNamespace;
  coordinatorState: FakeState;
  expiryState(grantId: string): FakeState;
  expiryObject(grantId: string): GrantExpiryDurableObject;
  coordinator(): BrokerCoordinatorDurableObject;
  recreateCoordinator(): void;
}> {
  const coordinatorNamespace = new FakeNamespace();
  const expiryStates = new Map<string, FakeState>();
  const expiryObjects = new Map<string, GrantExpiryDurableObject>();
  let environment: BrokerRuntimeEnvironment;
  const expiryNamespace = new FakeNamespace((grantId) => {
    if (options.scheduleFailure) {
      return {
        async fetch(): Promise<Response> {
          return new Response(null, { status: 503 });
        },
      };
    }
    const state = new FakeState();
    const object = new GrantExpiryDurableObject(state, environment);
    expiryStates.set(grantId, state);
    expiryObjects.set(grantId, object);
    return object;
  });
  const coordinatorState = new FakeState();
  let coordinator: BrokerCoordinatorDurableObject;
  environment = {
    BROKER_COORDINATOR: coordinatorNamespace,
    GRANT_EXPIRY: expiryNamespace,
    BROKER_SIGNING_JWK: await privateJwk(),
    BROKER_INTERNAL_TOKEN: crypto.randomUUID(),
    AUTHORITY: options.authority,
    APPROVAL: options.approval,
    OPERATOR: options.operator,
    BROKER_DB: options.ledger,
    BROKER_POLICY_JSON: options.policy,
    BROKER_REVOCATION_TARGETS: options.revocationTargets,
    REVOCATION: options.revocation,
  };

  const recreateCoordinator = (): void => {
    coordinator = new BrokerCoordinatorDurableObject(coordinatorState, environment);
    coordinatorNamespace.set("broker-coordinator", coordinator);
  };
  recreateCoordinator();

  return {
    environment,
    coordinatorNamespace,
    coordinatorState,
    expiryState(grantId) {
      const state = expiryStates.get(grantId);
      if (!state) {
        throw new Error(`missing expiry state for ${grantId}`);
      }
      return state;
    },
    expiryObject(grantId) {
      const object = expiryObjects.get(grantId);
      if (!object) {
        throw new Error(`missing expiry object for ${grantId}`);
      }
      return object;
    },
    coordinator() {
      return coordinator;
    },
    recreateCoordinator,
  };
}

function exchangeRequest(subjectTokenId = "subject-token-a"): Request {
  return new Request("https://broker.example.test/exchange", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId,
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: "test-dpop-thumbprint",
      expiresInSeconds: 60,
    }),
  });
}

describe("broker Cloudflare runtime", () => {
  it("publishes only the public verification key through the Worker route", async () => {
    const runtime = await runtimeHarness({ authority: authorityBinding() });
    const response = await worker.fetch(
      new Request("https://broker.example.test/.well-known/jwks.json"),
      runtime.environment,
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as { keys: JsonWebKey[] };
    expect(body.keys).toHaveLength(1);
    const [publicKey] = body.keys;
    if (!publicKey) {
      throw new Error("fixture did not return a verification key");
    }
    expect(publicKey).toMatchObject({ kty: "EC", crv: "P-256", kid: "broker-es256-1" });
    expect(publicKey).not.toHaveProperty("d");
  });

  it("routes through the singleton, persists state, and expires a scheduled grant through the internal callback", async () => {
    const runtime = await runtimeHarness({
      authority: authorityBinding(),
      approval: approvalBinding(),
    });
    const exchange = await worker.fetch(exchangeRequest(), runtime.environment);
    expect(exchange.status).toBe(201);
    const body = (await exchange.json()) as { grant: { id: string; expiresAt: number } };

    const approval = await worker.fetch(
      new Request(`https://broker.example.test/grants/${body.grant.id}/approve`, {
        method: "POST",
      }),
      runtime.environment,
    );
    expect(approval.status).toBe(200);
    expect(runtime.expiryState(body.grant.id).storage.alarms).toEqual([
      body.grant.expiresAt,
      body.grant.expiresAt,
    ]);
    expect(
      await worker.fetch(
        new Request("https://broker.example.test/__warden/internal/expire", { method: "POST" }),
        runtime.environment,
      ),
    ).toMatchObject({ status: 404 });

    await runtime.expiryObject(body.grant.id).alarm();
    runtime.recreateCoordinator();

    const evidence = await worker.fetch(
      new Request(`https://broker.example.test/grants/${body.grant.id}/evidence`),
      runtime.environment,
    );
    expect(evidence.status).toBe(200);
    expect(await evidence.json()).toMatchObject({ completionSource: "ttl" });
  });

  it("fails closed when no authority or approval integration is configured", async () => {
    const noAuthority = await runtimeHarness();
    const rejected = await worker.fetch(exchangeRequest(), noAuthority.environment);
    expect(rejected.status).toBe(401);
    expect(await rejected.json()).toEqual({ error: "invalid_credential" });

    const noApproval = await runtimeHarness({ authority: authorityBinding() });
    const exchange = await worker.fetch(exchangeRequest(), noApproval.environment);
    const body = (await exchange.json()) as { grant: { id: string } };
    const approved = await worker.fetch(
      new Request(`https://broker.example.test/grants/${body.grant.id}/approve`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ approver: "attacker-controlled-request-body" }),
      }),
      noApproval.environment,
    );
    expect(approved.status).toBe(403);
    expect(await approved.json()).toEqual({ error: "approval_required" });
  });

  it("requires a trusted operator binding before revocation", async () => {
    const noOperator = await runtimeHarness({ authority: authorityBinding() });
    const exchange = await worker.fetch(exchangeRequest(), noOperator.environment);
    const body = (await exchange.json()) as { grant: { id: string } };
    const denied = await worker.fetch(
      new Request(`https://broker.example.test/grants/${body.grant.id}/revoke`, { method: "POST" }),
      noOperator.environment,
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: "operator_authorization_required" });

    const runtime = await runtimeHarness({
      authority: authorityBinding(),
      operator: operatorBinding(),
    });
    const authorizedExchange = await worker.fetch(exchangeRequest(), runtime.environment);
    const authorizedBody = (await authorizedExchange.json()) as { grant: { id: string } };
    const revoked = await worker.fetch(
      new Request(`https://broker.example.test/grants/${authorizedBody.grant.id}/revoke`, {
        method: "POST",
      }),
      runtime.environment,
    );
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ completionSource: "operator" });
  });

  it("returns a retryable response when the coordinator binding rejects", async () => {
    const runtime = await runtimeHarness();
    runtime.coordinatorNamespace.set("broker-coordinator", {
      async fetch(): Promise<Response> {
        throw new Error("coordinator unavailable");
      },
    });

    const response = await worker.fetch(exchangeRequest(), runtime.environment);
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ error: "temporarily_unavailable" });
  });

  it("does not persist an active grant when required expiry scheduling is unavailable", async () => {
    const missingToken = await runtimeHarness({ authority: authorityBinding() });
    missingToken.environment.BROKER_INTERNAL_TOKEN = undefined;
    const missingTokenResponse = await worker.fetch(exchangeRequest(), missingToken.environment);
    expect(missingTokenResponse.status).toBe(503);
    expect(missingToken.coordinatorState.storage.values.has("broker-runtime-state-v1")).toBe(false);

    const schedulingFailure = await runtimeHarness({
      authority: authorityBinding(),
      scheduleFailure: true,
    });
    const schedulingFailureResponse = await worker.fetch(
      exchangeRequest(),
      schedulingFailure.environment,
    );
    expect(schedulingFailureResponse.status).toBe(503);
    expect(schedulingFailure.coordinatorState.storage.values.has("broker-runtime-state-v1")).toBe(
      false,
    );
  });

  it("projects only non-secret grant and audit data to the configured D1 ledger", async () => {
    const ledger = new FakeLedger();
    const runtime = await runtimeHarness({ authority: authorityBinding(), ledger });
    const exchange = await worker.fetch(
      exchangeRequest("subject-token-must-not-project"),
      runtime.environment,
    );
    expect(exchange.status).toBe(201);

    expect(ledger.calls.some((call) => call.query.includes("INSERT INTO grants"))).toBe(true);
    expect(ledger.calls.some((call) => call.query.includes("broker_audit_events"))).toBe(true);
    expect(JSON.stringify(ledger.calls)).not.toContain("subject-token-must-not-project");
    expect(JSON.stringify(ledger.calls)).not.toContain("credential-must-not-project");
  });

  it("uses validated runtime policy and fails closed for an invalid policy document", async () => {
    const allowed = await runtimeHarness({
      authority: authorityBinding(),
      policy: JSON.stringify({ version: 1, default: "allow", rules: [] }),
    });
    const allowResponse = await worker.fetch(exchangeRequest(), allowed.environment);
    expect(allowResponse.status).toBe(201);
    expect(await allowResponse.json()).toMatchObject({
      grant: { status: "approved" },
      credential: expect.any(String),
    });

    const blocked = await runtimeHarness({
      authority: authorityBinding(),
      policy: JSON.stringify({ version: 1, default: "block", rules: [] }),
    });
    const blockResponse = await worker.fetch(exchangeRequest(), blocked.environment);
    expect(blockResponse.status).toBe(201);
    expect(await blockResponse.json()).toMatchObject({ grant: { status: "denied" } });

    const invalid = await runtimeHarness({ authority: authorityBinding(), policy: "{}" });
    const invalidResponse = await worker.fetch(exchangeRequest(), invalid.environment);
    expect(invalidResponse.status).toBe(503);

    const typoedRule = await runtimeHarness({
      authority: authorityBinding(),
      policy: JSON.stringify({
        version: 1,
        default: "block",
        rules: [
          {
            id: "only-a-typo",
            decision: "allow",
            match: { resouce: "https://resource.example.test" },
          },
        ],
      }),
    });
    const typoedRuleResponse = await worker.fetch(exchangeRequest(), typoedRule.environment);
    expect(typoedRuleResponse.status).toBe(503);
    expect(typoedRule.coordinatorState.storage.values.has("broker-runtime-state-v1")).toBe(false);
  });

  it("retries failed configured revocation delivery through the coordinator alarm", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    try {
      let attempts = 0;
      const callbacks: unknown[] = [];
      const runtime = await runtimeHarness({
        authority: authorityBinding(),
        approval: approvalBinding(),
        revocationTargets: JSON.stringify(["https://subscriber.example.test/events"]),
        revocation: {
          async fetch(request: Request): Promise<Response> {
            callbacks.push(await request.json());
            attempts += 1;
            if (attempts === 1) {
              return new Response(null, { status: 503 });
            }
            return Response.json({ receipt: "receipt-after-retry" });
          },
        },
      });
      const exchange = await worker.fetch(exchangeRequest(), runtime.environment);
      const body = (await exchange.json()) as { grant: { id: string } };
      const approval = await worker.fetch(
        new Request(`https://broker.example.test/grants/${body.grant.id}/approve`, {
          method: "POST",
        }),
        runtime.environment,
      );
      expect(approval.status).toBe(200);

      await runtime.expiryObject(body.grant.id).alarm();
      expect(attempts).toBe(1);
      const scheduled = runtime.coordinatorState.storage.alarms.at(-1);
      expect(typeof scheduled).toBe("number");
      vi.setSystemTime(new Date(scheduled as number));
      await runtime.coordinator().alarm();

      expect(attempts).toBe(2);
      expect(callbacks).toHaveLength(2);
      expect(callbacks[0]).toMatchObject({
        grantId: body.grant.id,
        target: "https://subscriber.example.test/events",
      });
      const evidence = await worker.fetch(
        new Request(`https://broker.example.test/grants/${body.grant.id}/evidence`),
        runtime.environment,
      );
      expect(await evidence.json()).toMatchObject({
        revocationDeliveries: [{ status: "delivered", receipt: "receipt-after-retry" }],
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("imports the same private JWK into equivalent stable signers", async () => {
    const key = await privateJwk();
    const first = await Es256CapabilitySigner.fromPrivateJwk(
      "runtime-kid",
      JSON.parse(key) as JsonWebKey,
    );
    const second = await Es256CapabilitySigner.fromPrivateJwk(
      "runtime-kid",
      JSON.parse(key) as JsonWebKey,
    );

    expect(await first.publicJwk()).toEqual(await second.publicJwk());
  });

  it("keeps the Wrangler entrypoint, bindings, and migration exports aligned", () => {
    const config = JSON.parse(
      readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
    ) as {
      main: string;
      durable_objects: { bindings: { name: string; class_name: string }[] };
      migrations: { new_classes: string[] }[];
      d1_databases: { binding: string; migrations_dir?: string }[];
    };
    const bindings = new Map(
      config.durable_objects.bindings.map((binding) => [binding.name, binding.class_name]),
    );
    const migrated = new Set(config.migrations.flatMap((migration) => migration.new_classes));

    expect(config.main).toBe("src/worker.ts");
    expect(bindings.get("BROKER_COORDINATOR")).toBe("BrokerCoordinatorDurableObject");
    expect(bindings.get("GRANT_EXPIRY")).toBe("GrantExpiryDurableObject");
    expect(migrated.has("BrokerCoordinatorDurableObject")).toBe(true);
    expect(migrated.has("GrantExpiryDurableObject")).toBe(true);
    expect(config.d1_databases.map((database) => database.binding)).toContain("BROKER_DB");
    expect(config.d1_databases[0]?.migrations_dir).toBe("migrations");
  });
});
