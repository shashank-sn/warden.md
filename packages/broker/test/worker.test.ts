import { describe, expect, it } from "vitest";
import { Broker, type Clock, createBrokerWorker, createDpopSession } from "../src/index.js";
import { createAuthorityResolver } from "./support.js";

class FakeClock implements Clock {
  public now(): number {
    return Date.UTC(2026, 0, 1, 0, 0, 0);
  }
}

describe("broker worker completion endpoint", () => {
  it("requires a credential-bound DPoP proof and finalizes idempotently", async () => {
    const clock = new FakeClock();
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver(),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange({
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId: "subject-token-a",
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: session.thumbprint,
    });
    const approved = await broker.approve(proposed.grant.id, "person-a");
    const credential = approved.credential;
    if (!credential) {
      throw new Error("fixture did not mint a credential");
    }
    const worker = createBrokerWorker(broker);
    const endpoint = `https://broker.example.test/grants/${proposed.grant.id}/complete`;
    const unauthenticated = await worker.fetch(
      new Request(endpoint, { method: "POST", body: "{}" }),
    );
    expect(unauthenticated.status).toBe(401);

    const completion = await worker.fetch(
      new Request(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          credential,
          proof: await session.proof("POST", endpoint, clock),
        }),
      }),
    );
    expect(completion.status).toBe(200);
    expect(await completion.json()).toMatchObject({ completionSource: "agent" });
  });

  it("binds completion DPoP to the received endpoint instead of body fields", async () => {
    const clock = new FakeClock();
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver(),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange({
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId: "subject-token-a",
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: session.thumbprint,
    });
    const approved = await broker.approve(proposed.grant.id, "person-a");
    const credential = approved.credential;
    if (!credential) {
      throw new Error("fixture did not mint a credential");
    }
    const endpoint = `https://broker.example.test/grants/${proposed.grant.id}/complete`;
    const worker = createBrokerWorker(broker);
    const crossEndpoint = await worker.fetch(
      new Request(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          credential,
          proof: {
            token: (await session.proof("POST", "https://resource.example.test/records/42", clock))
              .token,
            method: "POST",
            url: "https://resource.example.test/records/42",
          },
        }),
      }),
    );

    expect(crossEndpoint.status).toBe(401);
    expect(await crossEndpoint.json()).toEqual({ error: "dpop_proof_invalid" });
    expect(await broker.getEvidence(proposed.grant.id)).toBeUndefined();
  });

  it("fails closed for approval until a server-side authorizer identifies an approver", async () => {
    const broker = await Broker.create({
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver(),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange({
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId: "subject-token-a",
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: session.thumbprint,
    });
    const endpoint = `https://broker.example.test/grants/${proposed.grant.id}/approve`;
    const denied = await createBrokerWorker(broker).fetch(
      new Request(endpoint, { method: "POST" }),
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: "approval_required" });

    const approved = await createBrokerWorker(broker, {
      approvalAuthorizer: {
        async authorize({ request }) {
          return request.headers.get("x-approved-by") === "person-a" ? "person-a" : undefined;
        },
      },
    }).fetch(new Request(endpoint, { method: "POST", headers: { "x-approved-by": "person-a" } }));
    expect(approved.status).toBe(200);
    expect(await approved.json()).toMatchObject({
      grant: { status: "approved", approver: "person-a" },
    });
  });

  it("fails closed for operator revocation until a server-side authorizer identifies an operator", async () => {
    const broker = await Broker.create({
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver(),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange({
      agentId: "agent-a",
      subjectId: "person-a",
      subjectTokenId: "subject-token-a",
      resource: "https://resource.example.test",
      action: "POST /records/42",
      requestedScope: ["records:write"],
      dpopThumbprint: session.thumbprint,
    });
    const endpoint = `https://broker.example.test/grants/${proposed.grant.id}/revoke`;
    const denied = await createBrokerWorker(broker).fetch(
      new Request(endpoint, { method: "POST" }),
    );
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: "operator_authorization_required" });

    const revoked = await createBrokerWorker(broker, {
      operatorAuthorizer: {
        async authorize({ request }) {
          return request.headers.get("x-operator") === "operator-a" ? "operator-a" : undefined;
        },
      },
    }).fetch(new Request(endpoint, { method: "POST", headers: { "x-operator": "operator-a" } }));
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ completionSource: "operator" });
  });
});
