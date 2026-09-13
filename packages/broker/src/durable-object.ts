import type { Broker } from "./broker.js";

export const BROKER_COORDINATOR_NAME = "broker-coordinator";
export const INTERNAL_EXPIRY_PATH = "/__warden/internal/expire";
export const INTERNAL_EXPIRY_SCHEDULE_PATH = "/__warden/internal/schedule-expiry";
export const INTERNAL_TOKEN_HEADER = "x-warden-internal-token";

export interface DurableObjectStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  setAlarm(scheduledTime: number | Date): Promise<void>;
}

export interface DurableObjectState {
  storage: DurableObjectStorage;
}

export interface DurableObjectId {
  readonly name?: string;
}

export interface DurableObjectStub {
  fetch(request: Request): Promise<Response>;
}

export interface DurableObjectNamespace {
  idFromName(name: string): DurableObjectId;
  get(id: DurableObjectId): DurableObjectStub;
}

/** Environment surface shared by every per-grant expiry object. */
export interface GrantExpiryEnvironment {
  BROKER_COORDINATOR: DurableObjectNamespace;
  BROKER_INTERNAL_TOKEN?: string;
}

type ScheduleInput = {
  grantId: string;
  expiresAt: number;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isScheduleInput(value: unknown): value is ScheduleInput {
  return (
    isObject(value) &&
    typeof value.grantId === "string" &&
    value.grantId.length > 0 &&
    typeof value.expiresAt === "number" &&
    Number.isFinite(value.expiresAt) &&
    value.expiresAt > 0
  );
}

function isBroker(value: Broker | GrantExpiryEnvironment): value is Broker {
  return typeof (value as Broker).expire === "function";
}

function internalRequestIsAuthorized(
  request: Request,
  environment: GrantExpiryEnvironment,
): boolean {
  return Boolean(
    environment.BROKER_INTERNAL_TOKEN &&
      request.headers.get(INTERNAL_TOKEN_HEADER) === environment.BROKER_INTERNAL_TOKEN,
  );
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}

/**
 * One Durable Object per grant owns its alarm. Local callers can still inject a
 * Broker directly; deployed objects call the singleton coordinator over its
 * binding-only internal endpoint instead.
 */
export class GrantExpiryDurableObject {
  private readonly broker: Broker | undefined;
  private readonly environment: GrantExpiryEnvironment | undefined;

  public constructor(
    private readonly state: DurableObjectState,
    brokerOrEnvironment: Broker | GrantExpiryEnvironment,
  ) {
    if (isBroker(brokerOrEnvironment)) {
      this.broker = brokerOrEnvironment;
    } else {
      this.environment = brokerOrEnvironment;
    }
  }

  public async schedule(grantId: string, expiresAt: number): Promise<void> {
    await this.state.storage.put("grantId", grantId);
    await this.state.storage.setAlarm(expiresAt);
  }

  public async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (
      request.method !== "POST" ||
      path !== INTERNAL_EXPIRY_SCHEDULE_PATH ||
      !this.environment ||
      !internalRequestIsAuthorized(request, this.environment)
    ) {
      return json({ error: "not_found" }, 404);
    }
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "invalid_request" }, 400);
    }
    if (!isScheduleInput(body)) {
      return json({ error: "invalid_request" }, 400);
    }
    await this.schedule(body.grantId, body.expiresAt);
    return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
  }

  public async alarm(): Promise<void> {
    const grantId = await this.state.storage.get<string>("grantId");
    if (!grantId) {
      return;
    }
    if (this.broker) {
      await this.broker.expire(grantId);
      return;
    }
    const environment = this.environment;
    if (!environment?.BROKER_INTERNAL_TOKEN) {
      throw new Error("BROKER_INTERNAL_TOKEN is required for expiry callbacks");
    }
    const coordinator = environment.BROKER_COORDINATOR.get(
      environment.BROKER_COORDINATOR.idFromName(BROKER_COORDINATOR_NAME),
    );
    const response = await coordinator.fetch(
      new Request(`https://${BROKER_COORDINATOR_NAME}.internal${INTERNAL_EXPIRY_PATH}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          [INTERNAL_TOKEN_HEADER]: environment.BROKER_INTERNAL_TOKEN,
        },
        body: JSON.stringify({ grantId }),
      }),
    );
    if (!response.ok) {
      throw new Error(`expiry callback failed with ${response.status}`);
    }
  }
}
