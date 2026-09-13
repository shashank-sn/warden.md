import { errorResponse, OAuthError } from "./errors.js";
import { createWorkerService, type WorkerEnvironment } from "./router.js";
import type { AgentAuthService } from "./service.js";
import type { DeliveryFetch, DurableObjectState } from "./types.js";

export const EVENT_DELIVERY_SCHEDULE_PATH = "/__warden/internal/event-delivery/schedule";

const issuerStorageKey = "event-delivery:issuer";

export type EventDeliveryServiceFactory = (
  environment: WorkerEnvironment,
  issuer: string,
) => Promise<AgentAuthService>;

function internalIssuer(request: Request): string {
  const issuer = request.headers.get("x-warden-issuer");
  if (!issuer) {
    throw new Error("event delivery requests require an issuer");
  }
  return issuer.replace(/\/+$/u, "");
}

/**
 * A singleton Durable Object owns the retry alarm. A failed delivery therefore
 * remains scheduled even when no later revocation request reaches the Worker.
 */
export class EventDeliveryDurableObject {
  private issuer: string | undefined;
  private service: Promise<AgentAuthService> | undefined;

  public constructor(
    private readonly state: DurableObjectState,
    private readonly environment: WorkerEnvironment,
    private readonly serviceFactory: EventDeliveryServiceFactory = createWorkerService,
    private readonly deliveryFetch: DeliveryFetch = fetch,
  ) {}

  public async fetch(request: Request): Promise<Response> {
    if (
      request.method !== "POST" ||
      new URL(request.url).pathname !== EVENT_DELIVERY_SCHEDULE_PATH
    ) {
      return errorResponse(new OAuthError("invalid_request"));
    }
    try {
      const issuer = internalIssuer(request);
      await this.state.storage.put(issuerStorageKey, issuer);
      await this.run(issuer);
      return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
    } catch {
      return errorResponse(new OAuthError("temporarily_unavailable"));
    }
  }

  public async alarm(): Promise<void> {
    const issuer = await this.state.storage.get<string>(issuerStorageKey);
    if (issuer) {
      await this.run(issuer);
    }
  }

  private async run(issuer: string): Promise<void> {
    const service = await this.serviceFor(issuer);
    await service.deliverDueEvents(this.deliveryFetch);
    const next = await service.nextEventDeliveryAt();
    if (next === undefined) {
      await this.state.storage.deleteAlarm();
      return;
    }
    await this.state.storage.setAlarm(next);
  }

  private serviceFor(issuer: string): Promise<AgentAuthService> {
    if (!this.service || this.issuer !== issuer) {
      this.issuer = issuer;
      this.service = this.serviceFactory(this.environment, issuer);
    }
    return this.service;
  }
}
