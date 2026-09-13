import { sha256 } from "./encoding.js";
import { OAuthError } from "./errors.js";
import type {
  ClaimOptions,
  ClaimRecord,
  ClaimRepository,
  Clock,
  IdentifierGenerator,
  PollResult,
  RateLimiter,
  StartedClaim,
} from "./types.js";

const defaultClaimOptions: ClaimOptions = {
  expiresInSeconds: 600,
  initialIntervalSeconds: 5,
  maxVerificationAttempts: 5,
  verificationWindowSeconds: 600,
  maxStartsPerWindow: 5,
  startWindowSeconds: 3600,
};

function withVersion(claim: ClaimRecord, changes: Partial<ClaimRecord>): ClaimRecord {
  return { ...claim, ...changes, version: claim.version + 1 };
}

function codeFromIdentifier(identifier: string): string {
  const compact = identifier.replaceAll(/[^A-Za-z0-9]/gu, "").toUpperCase();
  const suffix = compact.slice(-12).padStart(12, "X");
  return `${compact.slice(0, 4).padEnd(4, "X")}-${suffix.slice(0, 4)}-${suffix.slice(4, 8)}-${suffix.slice(8)}`;
}

export class ClaimCeremony {
  private readonly options: ClaimOptions;

  public constructor(
    private readonly claims: ClaimRepository,
    private readonly clock: Clock,
    private readonly identifiers: IdentifierGenerator,
    private readonly rateLimiter: RateLimiter,
    options: Partial<ClaimOptions> = {},
  ) {
    this.options = { ...defaultClaimOptions, ...options };
  }

  public async start(
    identityId: string,
    scopes: readonly string[],
    resource: string | undefined,
    rateLimitKey: string,
  ): Promise<StartedClaim> {
    const now = this.clock.now();
    const allowed = await this.rateLimiter.take(
      `claim-start:${rateLimitKey}`,
      this.options.maxStartsPerWindow,
      this.options.startWindowSeconds,
      now,
    );
    if (!allowed) {
      throw new OAuthError("temporarily_unavailable");
    }

    const deviceCode = this.identifiers.next("device");
    const userCode = codeFromIdentifier(this.identifiers.next("user"));
    const claim: ClaimRecord = {
      id: this.identifiers.next("claim"),
      identityId,
      userCodeHash: await sha256(userCode),
      deviceCodeHash: await sha256(deviceCode),
      status: "pending",
      scopes: [...scopes],
      resource,
      createdAt: now,
      expiresAt: now + this.options.expiresInSeconds * 1000,
      intervalSeconds: this.options.initialIntervalSeconds,
      verificationAttempts: 0,
      version: 1,
    };
    await this.claims.createClaim(claim);
    return { claim, deviceCode, userCode };
  }

  public async verifyUserCode(userCode: string, rateLimitKey = "unknown"): Promise<ClaimRecord> {
    const allowed = await this.rateLimiter.take(
      `claim-verify:${rateLimitKey}`,
      this.options.maxVerificationAttempts,
      this.options.verificationWindowSeconds,
      this.clock.now(),
    );
    if (!allowed) {
      throw new OAuthError("access_denied");
    }
    const claim = await this.claims.findByUserCodeHash(await sha256(userCode));
    if (!claim) {
      throw new OAuthError("invalid_grant");
    }
    const current = await this.expireIfNeeded(claim);
    if (current.status !== "pending" || current.userCodeUsedAt !== undefined) {
      throw new OAuthError("invalid_grant");
    }
    if (current.verificationAttempts >= this.options.maxVerificationAttempts) {
      await this.transition(current, { status: "denied", userCodeUsedAt: this.clock.now() });
      throw new OAuthError("access_denied");
    }
    return this.transition(current, {
      status: "user_verified",
      userCodeUsedAt: this.clock.now(),
      verificationAttempts: current.verificationAttempts + 1,
    });
  }

  public async decide(claimId: string, decision: "approved" | "denied"): Promise<ClaimRecord> {
    const claim = await this.requireClaim(claimId);
    const current = await this.expireIfNeeded(claim);
    if (current.status !== "user_verified") {
      throw new OAuthError("invalid_grant");
    }
    return this.transition(current, { status: decision });
  }

  public async poll(deviceCode: string): Promise<PollResult> {
    const claim = await this.claims.findByDeviceCodeHash(await sha256(deviceCode));
    if (!claim) {
      throw new OAuthError("invalid_grant");
    }
    const current = await this.expireIfNeeded(claim);
    if (current.status === "expired") {
      throw new OAuthError("expired_token");
    }
    if (current.status === "denied") {
      throw new OAuthError("access_denied");
    }

    const now = this.clock.now();
    if (
      current.lastPollAt !== undefined &&
      now - current.lastPollAt < current.intervalSeconds * 1000
    ) {
      const slowed = await this.transition(current, {
        intervalSeconds: current.intervalSeconds + 5,
      });
      if (slowed.status === "expired") {
        throw new OAuthError("expired_token");
      }
      throw new OAuthError("slow_down");
    }
    const polled = await this.transition(current, { lastPollAt: now });
    if (polled.status === "approved") {
      return { status: "approved", claim: polled };
    }
    return { status: "pending" };
  }

  public async consumeApprovedClaim(claimId: string): Promise<ClaimRecord> {
    const claim = await this.requireClaim(claimId);
    const current = await this.expireIfNeeded(claim);
    if (current.status === "expired") {
      throw new OAuthError("expired_token");
    }
    if (current.status !== "approved" || current.grantUsedAt !== undefined) {
      throw new OAuthError("invalid_grant");
    }
    return this.transition(current, { grantUsedAt: this.clock.now() });
  }

  private async requireClaim(id: string): Promise<ClaimRecord> {
    const claim = await this.claims.findClaimById(id);
    if (!claim) {
      throw new OAuthError("invalid_grant");
    }
    return claim;
  }

  private async expireIfNeeded(claim: ClaimRecord): Promise<ClaimRecord> {
    if (claim.expiresAt > this.clock.now() || claim.status === "expired") {
      return claim;
    }
    if (claim.status === "approved" && claim.grantUsedAt !== undefined) {
      return claim;
    }
    return this.transition(claim, { status: "expired" });
  }

  private async transition(
    current: ClaimRecord,
    changes: Partial<ClaimRecord>,
  ): Promise<ClaimRecord> {
    const next = withVersion(current, changes);
    if (await this.claims.compareAndSet(current, next)) {
      return next;
    }
    const refreshed = await this.claims.findClaimById(current.id);
    if (!refreshed) {
      throw new OAuthError("invalid_grant");
    }
    throw new OAuthError("temporarily_unavailable");
  }
}
