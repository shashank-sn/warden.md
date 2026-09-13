import { describe, expect, it } from "vitest";
import {
  Broker,
  type Clock,
  createDpopSession,
  createNodeMiddleware,
  createWorkersHandler,
  type DpopSession,
  type GrantProposal,
  WorkerBrokerTransportError,
} from "../src/index.js";
import { createAuthorityResolver } from "./support.js";

class FakeClock implements Clock {
  public now(): number {
    return Date.UTC(2026, 0, 1, 0, 0, 0);
  }
}

async function makeProposal(session: DpopSession): Promise<GrantProposal> {
  return {
    agentId: "agent-a",
    subjectId: "person-a",
    subjectTokenId: "subject-a",
    resource: "https://resource.example.test",
    action: "POST /protected",
    requestedScope: ["records:write"],
    dpopThumbprint: session.thumbprint,
  };
}

describe("resource middleware", () => {
  it("validates and atomically consumes a DPoP-bound one-use credential", async () => {
    const clock = new FakeClock();
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver([{ subjectTokenId: "subject-a" }]),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange(await makeProposal(session));
    const approved = await broker.approve(proposed.grant.id, "person-a");
    const credential = approved.credential;
    if (!credential) {
      throw new Error("fixture did not produce credential");
    }
    const url = "https://resource.example.test/protected";
    const handler = createWorkersHandler(
      { broker, audience: "https://resource.example.test" },
      async () => Response.json({ ok: true }),
    );
    const response = await handler(
      new Request(url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${credential}`,
          dpop: (await session.proof("POST", url, clock)).token,
        },
      }),
    );

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true });
    const replay = await handler(
      new Request(url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${credential}`,
          dpop: (await session.proof("POST", url, clock)).token,
        },
      }),
    );
    expect(replay.status).toBe(409);
    expect(await replay.json()).toEqual({ error: "grant_already_consumed" });
  });

  it("derives an absolute DPoP target for a normal Node relative URL", async () => {
    const clock = new FakeClock();
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver([{ subjectTokenId: "subject-a" }]),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange(await makeProposal(session));
    const approved = await broker.approve(proposed.grant.id, "person-a");
    const credential = approved.credential;
    if (!credential) {
      throw new Error("fixture did not produce credential");
    }
    let proceeded = false;
    const middleware = createNodeMiddleware({ broker, audience: "https://resource.example.test" });
    const response = {
      status() {
        return this;
      },
      json() {},
    };

    await middleware(
      {
        method: "POST",
        originalUrl: "/protected",
        headers: {
          authorization: `Bearer ${credential}`,
          dpop: (await session.proof("POST", "https://resource.example.test/protected", clock))
            .token,
        },
      },
      response,
      () => {
        proceeded = true;
      },
    );

    expect(proceeded).toBe(true);
  });

  it("returns a stable retryable response when the remote broker is unavailable", async () => {
    const middleware = createNodeMiddleware({
      audience: "https://resource.example.test",
      consumer: {
        async consume() {
          throw new WorkerBrokerTransportError();
        },
      },
    });
    let status: number | undefined;
    let body: unknown;
    let nextCalled = false;

    await middleware(
      {
        method: "POST",
        originalUrl: "/protected",
        headers: { authorization: "Bearer credential", dpop: "proof" },
      },
      {
        status(value) {
          status = value;
          return this;
        },
        json(value) {
          body = value;
        },
      },
      () => {
        nextCalled = true;
      },
    );

    expect(status).toBe(503);
    expect(body).toEqual({ error: "temporarily_unavailable" });
    expect(nextCalled).toBe(false);
  });

  it("normalizes unexpected verifier errors without passing them to Node error handling", async () => {
    const middleware = createNodeMiddleware({
      audience: "https://resource.example.test",
      consumer: {
        async consume() {
          throw new Error("consumer should not run");
        },
      },
      verifier: {
        async verify() {
          throw new Error("sentinel verification detail");
        },
      },
    });
    let status: number | undefined;
    let body: unknown;
    let nextArgument: unknown = "not-called";

    await middleware(
      {
        method: "POST",
        originalUrl: "/protected",
        headers: { authorization: "Bearer credential", dpop: "proof" },
      },
      {
        status(value) {
          status = value;
          return this;
        },
        json(value) {
          body = value;
        },
      },
      (error) => {
        nextArgument = error;
      },
    );

    expect(status).toBe(401);
    expect(body).toEqual({ error: "invalid_credential" });
    expect(nextArgument).toBe("not-called");
  });

  it("returns a stable operational error when evidence work fails after a valid consume", async () => {
    const clock = new FakeClock();
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver([{ subjectTokenId: "subject-a" }]),
    });
    const session = await createDpopSession();
    const proposed = await broker.exchange(await makeProposal(session));
    const approved = await broker.approve(proposed.grant.id, "person-a");
    const credential = approved.credential;
    if (!credential) {
      throw new Error("fixture did not produce credential");
    }
    const middleware = createNodeMiddleware({
      broker,
      audience: "https://resource.example.test",
      onEvidence: async () => {
        throw new Error("sentinel evidence detail");
      },
    });
    let status: number | undefined;
    let body: unknown;
    let nextCalled = false;

    await middleware(
      {
        method: "POST",
        originalUrl: "/protected",
        headers: {
          authorization: `Bearer ${credential}`,
          dpop: (await session.proof("POST", "https://resource.example.test/protected", clock))
            .token,
        },
      },
      {
        status(value) {
          status = value;
          return this;
        },
        json(value) {
          body = value;
        },
      },
      () => {
        nextCalled = true;
      },
    );

    expect(status).toBe(503);
    expect(body).toEqual({ error: "temporarily_unavailable" });
    expect(nextCalled).toBe(false);
    expect(broker.store.getGrant(proposed.grant.id)?.status).toBe("consumed");
  });
});
