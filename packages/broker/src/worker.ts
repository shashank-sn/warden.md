import type { Broker } from "./broker.js";
import { BrokerError, isBrokerError } from "./errors.js";
import type { Grant, GrantProposal } from "./types.js";

export interface ApprovalAuthorizer {
  authorize(input: { request: Request; grantId: string }): Promise<string | undefined>;
}

export interface BrokerWorkerOptions {
  approvalAuthorizer?: ApprovalAuthorizer;
  operatorAuthorizer?: ApprovalAuthorizer;
  onActiveGrant?(grant: Grant): Promise<void> | void;
}

/** Scheduling must reach the coordinator so it can discard an unpersisted transition. */
export class ActiveGrantSchedulingError extends Error {
  public constructor() {
    super("grant expiry scheduling failed");
    this.name = "ActiveGrantSchedulingError";
  }
}

export function createBrokerWorker(
  broker: Broker,
  options: BrokerWorkerOptions = {},
): { fetch(request: Request): Promise<Response> } {
  return {
    fetch: async (request) => {
      try {
        const path = new URL(request.url).pathname;
        if (request.method === "GET" && path === "/.well-known/jwks.json") {
          return json(await broker.jwks());
        }
        if (request.method === "POST" && path === "/exchange") {
          const proposal = (await request.json()) as GrantProposal;
          const result = await broker.exchange(proposal);
          await scheduleActiveGrant(result.grant, options);
          return json(result, 201);
        }
        const approve = path.match(/^\/grants\/([^/]+)\/approve$/u);
        if (request.method === "POST" && approve) {
          const grantId = approve[1];
          const approver = grantId
            ? await options.approvalAuthorizer?.authorize({ request, grantId })
            : undefined;
          if (!grantId || !approver) {
            throw new BrokerError(grantId ? "approval_required" : "invalid_request");
          }
          const result = await broker.approve(grantId, approver);
          await scheduleActiveGrant(result.grant, options);
          return json(result);
        }
        const revoke = path.match(/^\/grants\/([^/]+)\/revoke$/u);
        if (request.method === "POST" && revoke) {
          const grantId = revoke[1];
          const operator = grantId
            ? await options.operatorAuthorizer?.authorize({ request, grantId })
            : undefined;
          if (!grantId || !operator) {
            throw new BrokerError(grantId ? "operator_authorization_required" : "invalid_request");
          }
          return json(await broker.revoke(grantId));
        }
        if (request.method === "POST" && path === "/consume") {
          const body = (await request.json()) as {
            credential: string;
            proof: { token: string; method: string; url: string };
            audience: string;
          };
          const result = await broker.consume(body);
          return json(result);
        }
        const complete = path.match(/^\/grants\/([^/]+)\/complete$/u);
        if (request.method === "POST" && complete) {
          const grantId = complete[1];
          if (!grantId) {
            throw new BrokerError("invalid_request");
          }
          const body = (await request.json()) as {
            credential?: string;
            proof?: { token?: string };
          };
          if (!body.credential || !body.proof?.token) {
            throw new BrokerError("invalid_credential");
          }
          return json(
            await broker.completeAuthenticated(grantId, {
              credential: body.credential,
              proof: {
                token: body.proof.token,
                method: request.method,
                url: request.url,
              },
            }),
          );
        }
        const evidence = path.match(/^\/grants\/([^/]+)\/evidence$/u);
        if (request.method === "GET" && evidence) {
          const grantId = evidence[1];
          if (!grantId) {
            throw new BrokerError("invalid_request");
          }
          const record = await broker.getEvidence(grantId);
          if (!record) {
            throw new BrokerError("grant_not_found");
          }
          return json(record);
        }
        return json({ error: "not_found" }, 404);
      } catch (error) {
        if (error instanceof ActiveGrantSchedulingError) {
          throw error;
        }
        if (isBrokerError(error)) {
          return json({ error: error.code }, error.status);
        }
        return json({ error: "invalid_request" }, 400);
      }
    },
  };
}

async function scheduleActiveGrant(grant: Grant, options: BrokerWorkerOptions): Promise<void> {
  if (["proposed", "approved"].includes(grant.status)) {
    try {
      await options.onActiveGrant?.(grant);
    } catch {
      throw new ActiveGrantSchedulingError();
    }
  }
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}

export { GrantExpiryDurableObject } from "./durable-object.js";
export { BrokerCoordinatorDurableObject, default } from "./runtime.js";
