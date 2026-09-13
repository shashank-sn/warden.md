import { errorResponse, OAuthError } from "./errors.js";
import { D1ClaimRouteRepository, DurableObjectClaimState } from "./repository.js";
import { createRouter, createWorkerService, type WorkerEnvironment } from "./router.js";
import type { AgentAuthService } from "./service.js";
import type { DurableObjectState } from "./types.js";

function internalIssuer(request: Request): string {
  const issuer = request.headers.get("x-warden-issuer");
  if (!issuer) {
    throw new Error("claim ceremony requests require an issuer");
  }
  return issuer.replace(/\/+$/u, "");
}

/**
 * Cloudflare serializes calls to this object. Its storage is the authoritative
 * claim-state repository, while D1 retains identities, replay records, and tokens.
 */
export class ClaimCeremonyDurableObject {
  private readonly claims: DurableObjectClaimState;
  private issuer: string | undefined;
  private service: Promise<AgentAuthService> | undefined;
  private router: ReturnType<typeof createRouter> | undefined;

  public constructor(
    state: DurableObjectState,
    private readonly environment: WorkerEnvironment,
  ) {
    this.claims = new DurableObjectClaimState(state);
  }

  public async fetch(request: Request): Promise<Response> {
    try {
      const issuer = internalIssuer(request);
      if (!this.service || this.issuer !== issuer) {
        this.issuer = issuer;
        this.service = createWorkerService(this.environment, issuer, this.claims);
        this.router = undefined;
      }
      this.router ??= createRouter(await this.service);
      return this.router.fetch(request);
    } catch {
      return errorResponse(new OAuthError("temporarily_unavailable"));
    }
  }

  public async alarm(): Promise<void> {
    const now = Date.now();
    await this.claims.removeExpiredClaims(now);
    await new D1ClaimRouteRepository(this.environment.DB).removeExpiredRoutes(now);
  }
}
