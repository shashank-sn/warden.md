import { describe, expect, it } from "vitest";
import {
  Broker,
  BrokerError,
  type Clock,
  CompletionClient,
  createDpopSession,
  type DpopSession,
  type GrantProposal,
  type PolicyDocument,
} from "../src/index.js";
import { createAuthorityResolver } from "./support.js";

class FakeClock implements Clock {
  public constructor(private value = Date.UTC(2026, 0, 1, 0, 0, 0)) {}

  public now(): number {
    return this.value;
  }

  public advance(milliseconds: number): void {
    this.value += milliseconds;
  }
}

const requireApproval: PolicyDocument = {
  version: 1,
  default: "require-approval",
  rules: [],
};

async function proposal(
  session: DpopSession,
  overrides: Partial<GrantProposal> = {},
): Promise<GrantProposal> {
  return {
    agentId: "agent-a",
    subjectId: "person-a",
    subjectTokenId: "subject-token-a",
    resource: "https://resource.example.test",
    action: "POST /records/42",
    requestedScope: ["records:write"],
    dpopThumbprint: session.thumbprint,
    expiresInSeconds: 60,
    ...overrides,
  };
}

async function approvedGrant(clock = new FakeClock()): Promise<{
  broker: Broker;
  clock: FakeClock;
  session: DpopSession;
  credential: string;
  grantId: string;
}> {
  const broker = await Broker.create({
    clock,
    policy: requireApproval,
    authorityResolver: createAuthorityResolver(),
  });
  const session = await createDpopSession();
  const exchanged = await broker.exchange(await proposal(session));
  const approved = await broker.approve(exchanged.grant.id, "person-a");
  if (!approved.credential) {
    throw new Error("test fixture failed to mint");
  }
  return { broker, clock, session, credential: approved.credential, grantId: approved.grant.id };
}

describe("completion-scoped broker", () => {
  it("rejects upscoping before it creates authority", async () => {
    const broker = await Broker.create({
      policy: requireApproval,
      authorityResolver: createAuthorityResolver(),
    });
    const session = await createDpopSession();

    await expect(
      broker.exchange(
        await proposal(session, {
          requestedScope: ["records:write", "admin:all"],
        }),
      ),
    ).rejects.toMatchObject({ code: "scope_not_authorized" });
    expect(broker.store.listGrants()).toEqual([]);
  });

  it("supports allow, require-approval, and block policy decisions", async () => {
    const session = await createDpopSession();
    const broker = await Broker.create({
      policy: {
        version: 1,
        default: "block",
        rules: [
          { id: "automatic-read", decision: "allow", match: { action: "GET /records/42" } },
          {
            id: "human-write",
            decision: "require-approval",
            match: { action: "POST /records/42" },
          },
        ],
      },
      authorityResolver: createAuthorityResolver([
        {},
        { subjectTokenId: "subject-token-b" },
        { subjectTokenId: "subject-token-c" },
      ]),
    });

    const allowed = await broker.exchange(await proposal(session, { action: "GET /records/42" }));
    const approval = await broker.exchange(
      await proposal(session, { action: "POST /records/42", subjectTokenId: "subject-token-b" }),
    );
    const blocked = await broker.exchange(
      await proposal(session, { action: "DELETE /records/42", subjectTokenId: "subject-token-c" }),
    );

    expect(allowed.grant.status).toBe("approved");
    expect(allowed.credential).toBeTypeOf("string");
    expect(approval.grant.status).toBe("proposed");
    expect(approval.approvalReference).toBeTypeOf("string");
    expect(blocked.grant.status).toBe("denied");
    expect(blocked.credential).toBeUndefined();
  });

  it("allows exactly one winner under parallel consume", async () => {
    const { broker, clock, session, credential } = await approvedGrant();
    const first = session.proof("POST", "https://resource.example.test/records/42", clock);
    const second = session.proof("POST", "https://resource.example.test/records/42", clock);

    const results = await Promise.allSettled([
      first.then((proof) =>
        broker.consume({ credential, proof, audience: "https://resource.example.test" }),
      ),
      second.then((proof) =>
        broker.consume({ credential, proof, audience: "https://resource.example.test" }),
      ),
    ]);

    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    const rejected = results.find((result) => result.status === "rejected");
    expect(rejected).toMatchObject({ reason: { code: "grant_already_consumed" } });
  });

  it("rejects wrong audience and DPoP key without consuming the grant", async () => {
    const { broker, clock, session, credential } = await approvedGrant();
    const wrongAudienceProof = await session.proof("POST", "https://other.example.test", clock);

    await expect(
      broker.consume({
        credential,
        proof: wrongAudienceProof,
        audience: "https://other.example.test",
      }),
    ).rejects.toMatchObject({ code: "wrong_audience" });

    const substituted = await createDpopSession();
    await expect(
      broker.consume({
        credential,
        proof: await substituted.proof("POST", "https://resource.example.test/records/42", clock),
        audience: "https://resource.example.test",
      }),
    ).rejects.toMatchObject({ code: "wrong_dpop_key" });
  });

  it("does not let a reused subject token mint a second consumable credential", async () => {
    const { broker } = await approvedGrant();
    const session = await createDpopSession();
    const second = await broker.exchange(
      await proposal(session, {
        subjectTokenId: "subject-token-a",
        dpopThumbprint: session.thumbprint,
      }),
    );

    await expect(broker.approve(second.grant.id, "person-a")).rejects.toMatchObject({
      code: "token_already_exchanged",
    });
  });

  it("expires authority via the TTL fallback and returns a stable error", async () => {
    const { broker, clock, session, credential } = await approvedGrant();
    clock.advance(61_000);
    const evidence = await broker.expireDue();

    expect(evidence).toHaveLength(1);
    expect(evidence[0]?.completionSource).toBe("ttl");
    await expect(
      broker.consume({
        credential,
        proof: await session.proof("POST", "https://resource.example.test/records/42", clock),
        audience: "https://resource.example.test",
      }),
    ).rejects.toMatchObject({ code: "grant_expired" });
  });

  it("makes completion idempotent and retries failed revocation delivery", async () => {
    const clock = new FakeClock();
    let attempts = 0;
    const broker = await Broker.create({
      clock,
      policy: requireApproval,
      authorityResolver: createAuthorityResolver(),
      revocationTargets: ["https://subscriber.example.test/events"],
      revocationTransport: {
        async deliver() {
          attempts += 1;
          if (attempts === 1) {
            throw new Error("temporary failure");
          }
          return { receipt: "receipt-2" };
        },
      },
    });
    const session = await createDpopSession();
    const exchanged = await broker.exchange(await proposal(session));
    const approved = await broker.approve(exchanged.grant.id, "person-a");

    const first = await broker.complete(approved.grant.id);
    const second = await broker.complete(approved.grant.id);
    expect(second.id).toBe(first.id);
    expect(first.revocationDeliveries[0]?.status).toBe("failed");

    clock.advance(3_000);
    await broker.retryRevocations();
    const evidence = await broker.getEvidence(approved.grant.id);
    expect(evidence?.revocationDeliveries[0]).toMatchObject({
      status: "delivered",
      attempts: 2,
      receipt: "receipt-2",
    });
  });

  it("caps requested TTLs rather than letting an agent extend authority", async () => {
    const broker = await Broker.create({
      policy: requireApproval,
      authorityResolver: createAuthorityResolver(),
      maxTtlSeconds: 60,
    });
    const session = await createDpopSession();

    await expect(
      broker.exchange(await proposal(session, { expiresInSeconds: 61 })),
    ).rejects.toMatchObject({
      code: "invalid_request",
    });
    expect(broker.store.listGrants()).toEqual([]);
  });

  it("serializes identical idempotency keys before reserving or minting", async () => {
    const broker = await Broker.create({
      policy: {
        version: 1,
        default: "allow",
        rules: [],
      },
      authorityResolver: createAuthorityResolver([{}, { subjectTokenId: "subject-token-b" }]),
    });
    const firstSession = await createDpopSession();
    const secondSession = await createDpopSession();
    const [first, second] = await Promise.all([
      broker.exchange(await proposal(firstSession, { idempotencyKey: "retry-1" })),
      broker.exchange(
        await proposal(secondSession, {
          subjectTokenId: "subject-token-b",
          dpopThumbprint: secondSession.thumbprint,
          idempotencyKey: "retry-1",
        }),
      ),
    ]);

    expect(first.grant.id).toBe(second.grant.id);
    expect([first.credential, second.credential].filter(Boolean)).toHaveLength(1);
    expect(broker.store.listGrants()).toHaveLength(1);
  });

  it("rejects a valid credential when the DPoP request action differs", async () => {
    const { broker, clock, session, credential } = await approvedGrant();

    await expect(
      broker.consume({
        credential,
        proof: await session.proof("DELETE", "https://resource.example.test/records/42", clock),
        audience: "https://resource.example.test",
      }),
    ).rejects.toMatchObject({ code: "action_not_authorized" });
  });

  it("treats a query string as part of the exact protected action", async () => {
    const { broker, clock, session, credential } = await approvedGrant();

    await expect(
      broker.consume({
        credential,
        proof: await session.proof(
          "POST",
          "https://resource.example.test/records/42?mode=destructive",
          clock,
        ),
        audience: "https://resource.example.test",
      }),
    ).rejects.toMatchObject({ code: "action_not_authorized" });
    expect(broker.store.listGrants()[0]?.status).toBe("approved");
  });

  it("completes an approved grant after the protected call throws", async () => {
    const broker = await Broker.create({
      policy: requireApproval,
      authorityResolver: createAuthorityResolver(),
    });
    const session = await createDpopSession();
    const client = new CompletionClient(broker);

    await expect(
      client.run({
        proposal: await proposal(session),
        approver: "person-a",
        async call() {
          throw new Error("resource failed");
        },
      }),
    ).rejects.toThrow("resource failed");

    const grant = broker.store.listGrants()[0];
    expect(grant?.status).toBe("revoked");
    expect(await broker.getEvidence(grant?.id ?? "")).toMatchObject({ completionSource: "agent" });
  });

  it("reports only stable broker errors at the boundary", () => {
    const error = new BrokerError("wrong_dpop_key");
    expect({ error: error.code, status: error.status }).toEqual({
      error: "wrong_dpop_key",
      status: 401,
    });
  });
});
