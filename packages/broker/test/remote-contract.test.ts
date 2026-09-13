import { describe, expect, it } from "vitest";
import {
  Broker,
  type Clock,
  createBrokerWorker,
  createDpopSession,
  createWorkerCompletionClient,
  createWorkersHandler,
  type DpopSession,
  type GrantProposal,
  WorkerBrokerClient,
} from "../src/index.js";
import { createAuthorityResolver } from "./support.js";

class FakeClock implements Clock {
  public now(): number {
    return Date.UTC(2026, 0, 1, 0, 0, 0);
  }
}

async function proposal(session: DpopSession): Promise<GrantProposal> {
  return {
    agentId: "agent-a",
    subjectId: "person-a",
    subjectTokenId: "remote-subject-token",
    resource: "https://resource.example.test",
    action: "POST /protected",
    requestedScope: ["records:write"],
    dpopThumbprint: session.thumbprint,
  };
}

describe("deployed broker contract", () => {
  it("lets a resource use public JWKS and the Worker consume route without a signing key", async () => {
    const clock = new FakeClock();
    const broker = await Broker.create({
      clock,
      policy: { version: 1, default: "require-approval", rules: [] },
      authorityResolver: createAuthorityResolver([{ subjectTokenId: "remote-subject-token" }]),
    });
    const worker = createBrokerWorker(broker, {
      approvalAuthorizer: {
        async authorize({ request }) {
          return request.headers.get("x-approved-by") === "person-a" ? "person-a" : undefined;
        },
      },
    });
    const requestLog: { path: string; approvedBy: string | null }[] = [];
    const workerFetch: typeof fetch = async (input, init) => {
      const request = new Request(input, init);
      requestLog.push({
        path: new URL(request.url).pathname,
        approvedBy: request.headers.get("x-approved-by"),
      });
      return worker.fetch(request);
    };
    const brokerUrl = "https://broker.example.test";
    const resourceClient = new WorkerBrokerClient({ brokerUrl, fetch: workerFetch });
    const jwks = await resourceClient.jwks();
    const [publicKey] = jwks.keys;
    if (!publicKey) {
      throw new Error("fixture did not return a public key");
    }
    expect(publicKey).not.toHaveProperty("d");
    expect(JSON.stringify(jwks)).not.toContain("BROKER_SIGNING_JWK");
    const verifier = await resourceClient.verifier();
    const session = await createDpopSession();
    const resourceHandler = createWorkersHandler(
      {
        audience: "https://resource.example.test",
        consumer: resourceClient,
        now: () => clock.now(),
        verifier,
      },
      async () => Response.json({ protected: true }),
    );
    const completionClient = createWorkerCompletionClient({
      brokerUrl,
      fetch: workerFetch,
      approvalHeaders: { "x-approved-by": "person-a" },
      dpopProof: ({ method, url }) => session.proof(method, url, clock),
    });

    const result = await completionClient.run({
      proposal: await proposal(session),
      async call({ credential }) {
        const url = "https://resource.example.test/protected";
        const response = await resourceHandler(
          new Request(url, {
            method: "POST",
            headers: {
              authorization: `Bearer ${credential}`,
              dpop: (await session.proof("POST", url, clock)).token,
            },
          }),
        );
        expect(response.status).toBe(200);
        return response.json();
      },
    });

    expect(result).toEqual({ protected: true });
    expect(requestLog.find((entry) => entry.path.endsWith("/approve"))?.approvedBy).toBe(
      "person-a",
    );
    expect(
      requestLog
        .filter((entry) => !entry.path.endsWith("/approve"))
        .every((entry) => !entry.approvedBy),
    ).toBe(true);
    const grant = broker.store.listGrants()[0];
    expect(grant?.status).toBe("revoked");
    expect(await broker.getEvidence(grant?.id ?? "")).toMatchObject({ completionSource: "agent" });
  });
});
